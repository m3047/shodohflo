#!/usr/bin/python3
# Copyright (c) 2019 by Fred Morris Tacoma WA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Packet Capture Agent.

Capture IP addresses and ports of TCP and UDP packets and send them to Redis.

    pcap_agent.py <interface> <our-nets>

Takes two arguments:

    interface:  The interface to listen on in promiscuous mode.
    our-nets:   A network mask which indicates which end of the connection is
                "our" end.

POTENTIAL RACE CONDITION: Make sure that the address of the Redis server is in our-nets
or that you're not communicating with it on the interface you're watching. Otherwise, 
traffic coming from the Redis server will trigger the logic which communicates
with the redis server.

Keys written to Redis:

    <client-address>;<remote-address>;<remote-port>;flow -> count (TTL_GRACE)
        Remote addresses/ports and a relative count, not the true number of packets

Packets between two nodes on the "our" network are not captured. Only traffic arriving
at (destined for) "our" network is captured.

NOTE: Traffic leaving the host running this agent is not captured. Only traffic
arriving at the interface is captured.

The PRINT_ Constants
--------------------

The PRINT_... constants control various debugging output. They can be
set to a print function which accepts a string, for example:

    PRINT_THIS = logging.debug
    PRINT_THAT = print
"""

import sys
from os import path
import struct
import logging

import socket
import asyncio
from concurrent.futures import CancelledError

import ipaddress
import dpkt
import redis

sys.path.insert(0,path.dirname(path.dirname(path.abspath(__file__))))

from shodohflo.redis_handler import RedisBaseHandler
from shodohflo.utils import Once, Recent, StatisticsFactory

if __name__ == "__main__":
    from configuration import *
else:
    REDIS_SERVER = 'localhost'
    USE_DNSPYTHON = False
    LOG_LEVEL = None
    TTL_GRACE = None
    PCAP_STATS = None

if LOG_LEVEL is not None:
    logging.basicConfig(level=LOG_LEVEL)

if TTL_GRACE is None:
    TTL_GRACE = 900         # 15 minutes

if USE_DNSPYTHON:
    import dns.resolver as resolver

ETH_IP4 = 0x0800
ETH_IP6 = 0x86DD

# As set in if_packet.h
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
# As set in socket.h
SOL_PACKET = 263

TCP_OR_UDP = set((socket.IPPROTO_TCP, socket.IPPROTO_UDP))

# Start/end of coroutines.
PRINT_COROUTINE_ENTRY_EXIT = None
# Packet flows being written to Redis.
PRINT_PACKET_FLOW = None

# Similar to the foregoing, but always set to something valid.
STATISTICS_PRINTER = logging.info

def hexify(data):
    return ''.join(('{:02x} '.format(b) for b in data))

def get_socket(interface, network):
    """Return a Packet Socket on the specified interface."""

    network = ipaddress.ip_network(network)
    if isinstance(network, ipaddress.IPv4Network):
        ip_type = ETH_IP4
        ip_class = dpkt.ip.IP
    else:
        ip_type = ETH_IP6
        ip_class = dpkt.ip6.IP6
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM)
    sock.bind((interface, ip_type))

    # All of the rest of this is to set the socket into promiscuous mode.
    try:
        if_number = socket.if_nametoindex(interface)
    except OSError:
        if_number = 0
    if not if_number:
        logging.error("Interface number not available, unable to set promiscuous mode.")
    else:
        # See the manpage for packet(7)
        membership_request = struct.pack("IHH8s", if_number, PACKET_MR_PROMISC, 0, b"\x00"*8)
        sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, membership_request)
    
    return sock, ip_class, network

def to_address(s):
    if len(s) == 4:
        return ipaddress.IPv4Address(s)
    else:
        return ipaddress.IPv6Address(s)
    
class RedisHandler(RedisBaseHandler):
    
    def __init__(self, event_loop, ttl, statistics):
        RedisBaseHandler.__init__(self, event_loop, ttl)
        if PCAP_STATS:
            self.flow_to_redis_stats = statistics.Collector("flow_to_redis")
        return

    def redis_server(self):
        if USE_DNSPYTHON:
            server = resolver.query(REDIS_SERVER).response.answer[0][0].to_text()
        else:
            server = REDIS_SERVER
        return server
    
    def flow_to_redis(self, client_address, k):
        """Log a netflow to Redis.
        
        Scheduled with RedisHandler.submit().
        """
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("START flow_to_redis")
        if PCAP_STATS:
            timer = self.flow_to_redis_stats.start_timer()

        self.client_to_redis(client_address)

        self.redis.incr(k)
        self.redis.expire(k, TTL_GRACE)

        if PCAP_STATS:
            timer.stop()
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("END flow_to_redis")
        return
    
class Server(object):
    def __init__(self, interface, our_network, event_loop, statistics):
        sock, Packet, our_network = get_socket(interface, our_network)
        self.sock = sock
        self.Packet = Packet
        self.our_network = our_network
        self.recently = Recent()
        self.redis = RedisHandler(event_loop, TTL_GRACE, statistics)
        if PCAP_STATS:
            self.process_data_stats = statistics.Collector("process_data")
            self.socket_recv_stats = statistics.Collector("socket_recv")
            self.socket_recv_timer = self.socket_recv_stats.start_timer()
        return
    
    def process_data(self):
        """Called by the event loop when there is a packet to process."""
        if PCAP_STATS:
            self.socket_recv_timer.stop()
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("START process_data")
        if PCAP_STATS:
            timer = self.process_data_stats.start_timer()

        msg = self.sock.recv(60)
        pkt = self.Packet(msg)
        
        once = Once()
        while once():

            if   pkt.p not in TCP_OR_UDP:
                break
            
            src = to_address(pkt.src)
            dst = to_address(pkt.dst)

            if   src in self.our_network:
                if dst in self.our_network:
                    break
                client = str(src)
                remote = str(dst)
                remote_port = pkt.data.dport
            elif dst in self.our_network:
                if src in self.our_network:
                    break
                client = str(dst)
                remote = str(src)
                remote_port = pkt.data.sport
            else:
                break
            
            k = "{};{};{};flow".format(client, remote, remote_port)
            if self.recently.seen(k):
                break

            if PRINT_PACKET_FLOW:
                PRINT_PACKET_FLOW("{} <-> {}#{}".format(client, remote, remote_port))

            self.redis.submit(self.redis.flow_to_redis, client, k)

        if PCAP_STATS:
            timer.stop()
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("END process_data")

        if PCAP_STATS:
            self.socket_recv_timer = self.socket_recv_stats.start_timer()
        return

    def close(self):
        self.sock.close()
        return

async def statistics_report(statistics):
    while True:
        await asyncio.sleep(PCAP_STATS)
        for stat in sorted(statistics.stats(), key=lambda x:x['name']):
            STATISTICS_PRINTER(
                '{}: emin={:.4f} emax={:.4f} e1={:.4f} e10={:.4f} e60={:.4f} dmin={} dmax={} d1={:.4f} d10={:.4f} d60={:.4f} nmin={} nmax={} n1={:.4f} n10={:.4f} n60={:.4f}'.format(
                    stat['name'],
                    stat['elapsed']['minimum'], stat['elapsed']['maximum'], stat['elapsed']['one'], stat['elapsed']['ten'], stat['elapsed']['sixty'],
                    stat['depth']['minimum'], stat['depth']['maximum'], stat['depth']['one'], stat['depth']['ten'], stat['depth']['sixty'],
                    stat['n_per_sec']['minimum'], stat['n_per_sec']['maximum'], stat['n_per_sec']['one'], stat['n_per_sec']['ten'], stat['n_per_sec']['sixty'])
                )
    return
    
async def close_tasks(tasks):
    all_tasks = asyncio.gather(*tasks)
    all_tasks.cancel()
    try:
        await all_tasks
    except CancelledError:
        pass
    return
    

def main():
    interface, our_network = sys.argv[1:3]
    logging.info('Packet Capture Agent starting. Interface: {}  Our Network: {}  Redis: {}'.format(interface, our_network, REDIS_SERVER))
    event_loop = asyncio.get_event_loop()
    statistics = StatisticsFactory()
    server = Server(interface, our_network, event_loop, statistics)
    event_loop.add_reader(server.sock, server.process_data)
    if PCAP_STATS:
        asyncio.run_coroutine_threadsafe(statistics_report(statistics), event_loop)
        
    try:
        event_loop.run_forever()
    except KeyboardInterrupt:
        pass
    
    tasks = asyncio.Task.all_tasks(event_loop)
    if tasks:
        event_loop.run_until_complete(close_tasks(tasks))

    server.close()
    
    return

if __name__ == '__main__':
    main()
