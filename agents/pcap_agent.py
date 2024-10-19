#!/usr/bin/python3
# Copyright (c) 2019-2024 by Fred Morris Tacoma WA
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
                
our-nets is used as follows:

  * ICMP and RST have to have a destination in our-nets
  * To define the OUR_4NETS or OUR_6NETS special value used in defining a
    NetworkEnumeration.
  * In conjunction with SUPPRESS_OWN_NETWORK (which defaults to True) it suppresses
    any flows for which the source and destination are both in our-nets

If you define nets (NETWORK_ENUMERATION) and flows (FLOW_MAPPING) beyond the
trivial defaults you will probably want to set SUPPRESS_OWN_NETWORK to False.

POTENTIAL RACE CONDITION: Make sure that the address of the Redis server is in our-nets
or that you're not communicating with it on the interface you're watching. Otherwise, 
traffic coming from the Redis server will trigger the logic which communicates
with the redis server.

Keys written to Redis in all cases include remote addresses/ports as part of the key,
and the value is a relative count, not the true number of packets.

In the case of flow, by default a heuristic is utilized that the lower port belongs
to the service, and the server-address is the same (source or destination) as the
whether the source or destination has the lower port. See shodohflo.pcap_config for
sophisticated flow mapping.

    <client-address>;<server-address>;<service-port>;flow -> count (TTL_GRACE)
    
In the case of rst, the destination always has to be in "our network".

    * client-address is the destination
    * remote-address is the source
    * remote_port is the destination and source ports concatenated with a ':'

    <client-address>;<remote-address>;<remote-port>;rst -> count (TTL_GRACE)
    
In the case of peer, both records are written for each event.

    <client-address>;<remote-address>;peer -> count (TTL_GRACE)

    <remote-address>;<client-address>;peer -> count (TTL_GRACE)
    
In the case of icmp, the destination always has to be in "our network".

    * client-address is the destination
    * remote-address is the source
    * remote-port is the source and destination ports concatenated with a ':'

    <client-address>;<remote-address>;<remote-port>;<icmp-code>;icmp -> count (TTL_GRACE)
        ICMP code is one of the unreachable codes accompanying type 3

Packets between two nodes on the "our" network are not captured unless SUPPRESS_OWN_NETWORK
is set to False. Only traffic arriving at (destined for) "our" network is captured.

EXCEPTION: ICMP unreachable and TCP RST packets are captured regardless of origin and
client is the destination of the packet.

NOTE: Traffic leaving the host running this agent is not captured. Only traffic
arriving at the interface is captured.

The PRINT_ Constants
--------------------

The PRINT_... constants control various debugging output. They can be
set to a print function which accepts a string, for example:

    PRINT_THIS = logging.debug
    PRINT_THAT = print
    
REDIS_KEY_ Strings
------------------

All format strings for the keys written to Redis are defined as constants. The
declarations occur before importing the configuration, so you can alter them in
the configuration file if you wish to. Hopefully this will also make it easier
to locate the responsible code as well.

"""

import sysconfig

PYTHON_IS_311 = int( sysconfig.get_python_version().split('.')[1] ) >= 11

import sys
from os import path
import struct
import logging
import traceback

import socket
import asyncio
from concurrent.futures import CancelledError

import ipaddress
import dpkt
import redis
from redis.exceptions import ConnectionError

sys.path.insert(0,path.dirname(path.dirname(path.abspath(__file__))))

from shodohflo.pcap_config import NetworkEnumeration, LowerPort, FlowMapping, update_our_nets

from shodohflo.redis_handler import RedisBaseHandler
from shodohflo.utils import Once, Recent
from shodohflo.statistics import StatisticsFactory

if PYTHON_IS_311:
    from asyncio import CancelledError
else:
    from concurrent.futures import CancelledError

REDIS_SERVER = 'localhost'
USE_DNSPYTHON = False
LOG_LEVEL = None
TTL_GRACE = None
PCAP_STATS = None
SUPPRESS_OWN_NETWORK = True
IGNORE_FLOW = set()
NETWORK_ENUMERATION = NetworkEnumeration( ('all', '0.0.0.0/0') )
FLOW_MAPPING = FlowMapping( (None, None, LowerPort()) )

REDIS_KEY_ICMP = "{};{};{};{};icmp"
REDIS_KEY_RST = "{};{};{};rst"
REDIS_KEY_FLOW = "{};{};{};flow"
REDIS_KEY_PEER = '{};{};peer'
REDIS_KEY_CLIENT = 'client;{}'

if __name__ == "__main__":
    from configuration import *

if LOG_LEVEL is not None:
    logging.basicConfig(level=LOG_LEVEL)

if TTL_GRACE is None:
    TTL_GRACE = 900         # 15 minutes

if USE_DNSPYTHON:
    if PYTHON_IS_311:
        from dns.resolver import resolve as dns_query
    else:
        from dns.resolver import query as dns_query

# As set in if_ether.h
ETH_IP4 = 0x0800
ETH_IP6 = 0x86DD

# As set in if_packet.h
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
# As set in socket.h
SOL_PACKET = 263

ICMP_DST_UNREACHABLE = 3

TCP_OR_UDP = set((socket.IPPROTO_TCP, socket.IPPROTO_UDP))
PROTOCOLS = set((socket.IPPROTO_TCP, socket.IPPROTO_UDP, socket.IPPROTO_ICMP))
SYN_OR_FIN = dpkt.tcp.TH_SYN | dpkt.tcp.TH_FIN

# Start/end of coroutines.
PRINT_COROUTINE_ENTRY_EXIT = None
# Packet flows being written to Redis.
PRINT_PACKET_FLOW = None

# Similar to the foregoing, but always set to something valid.
STATISTICS_PRINTER = logging.info

UNSIGNED_BIG_ENDIAN = dict(byteorder='big', signed=False)

def hexify(data):
    return ''.join(('{:02x} '.format(b) for b in data))

def get_socket(interface, network, blocking=False):
    """Return a Packet Socket on the specified interface.
    
    blocking isn't ordinarily used. It is provided for situations where you
    want to import the module and use get_socket() interactively: in such
    cases it is often easier to just have it blocking.
    """

    network = ipaddress.ip_network(network)
    if isinstance(network, ipaddress.IPv4Network):
        ip_type = ETH_IP4
        ip_class = dpkt.ip.IP
    else:
        ip_type = ETH_IP6
        ip_class = dpkt.ip6.IP6
    if blocking:
        blocking = 0
    else:
        blocking = socket.SOCK_NONBLOCK
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM|blocking)
    #sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW|blocking)
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
            self.backlog = statistics.Collector("redis_backlog")
        return

    def redis_server(self):
        if USE_DNSPYTHON:
            server = dns_query(REDIS_SERVER).response.answer[0][0].to_text()
        else:
            server = REDIS_SERVER
        return server
    
    def flow_to_redis(self, backlog_timer, client_address, *keys):
        """Log a netflow to Redis.
        
        Scheduled with RedisHandler.submit().
        """
        if self.stop:
            return
        
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("START flow_to_redis")
        if PCAP_STATS:
            timer = self.flow_to_redis_stats.start_timer()

        try:
            self.client_to_redis(client_address)

            for k in keys:
                self.redis.incr(k)
                self.redis.expire(k, TTL_GRACE)
        except ConnectionError as e:
            if not self.stop:
                logging.error('redis.exceptions.ConnectionError: {}'.format(e))
                self.stop = True
        except Exception as e:
            if not self.stop:
                traceback.print_exc()
                self.stop = True

        if PCAP_STATS:
            timer.stop()
            backlog_timer.stop()
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("END flow_to_redis")
        return
    
    def submit(self, func, *args):
        if PCAP_STATS:
            backlog_timer = self.backlog.start_timer()
        else:
            backlog_timer = None
        args = (backlog_timer,) + args
        RedisBaseHandler.submit(self, func, *args)
        return

class Server(object):
    def __init__(self, interface, our_network, event_loop, statistics):
        sock, Packet, our_network = get_socket(interface, our_network)
        update_our_nets( our_network )
        FLOW_MAPPING.number_networks( NETWORK_ENUMERATION )
        self.sock = sock
        self.Packet = Packet
        self.our_network = our_network
        self.recently = Recent()
        self.redis = RedisHandler(event_loop, TTL_GRACE, statistics)
        self.redis.REDIS_KEY_CLIENT = REDIS_KEY_CLIENT
        if PCAP_STATS:
            self.process_data_stats = statistics.Collector("process_data")
            self.socket_recv_stats = statistics.Collector("socket_recv")
            self.socket_recv_timer = self.socket_recv_stats.start_timer()
        return
    
    def process_data(self):
        """Called by the event loop when there is a packet to process."""
        if PCAP_STATS:
            if self.socket_recv_timer is not None:
                self.socket_recv_timer.stop()
                self.socket_recv_timer = None
            else:
                logging.error('Server.socket_recv_timer unexpectedly None')
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("START process_data")

        while True:

            try:
                msg = self.sock.recv(60)
            except BlockingIOError:
                msg = b''
            if not msg or len(msg) == 0:
                break
                
            if PCAP_STATS:
                timer = self.process_data_stats.start_timer()

            pkt = self.Packet(msg)
            
            once = Once()
            while once():

                if   pkt.p not in PROTOCOLS:
                    break

                src = to_address(pkt.src)
                dst = to_address(pkt.dst)
                
                if pkt.p == socket.IPPROTO_ICMP:

                    # In the ICMP case we care about a machine in our network which is receiving
                    # ICMP unreachable notifications.
                    if dst not in self.our_network:
                        break
                    if not isinstance(pkt.data, dpkt.icmp.ICMP):
                        break
                    icmp = pkt.data
                    if icmp.type != ICMP_DST_UNREACHABLE:
                        break
                        
                    icmp_code = icmp.code
                    if not isinstance(icmp.data, dpkt.icmp.ICMP.Unreach):
                        logging.warn('Expected icmp.ICMP.Unreach, found {}'.format(type(icmp.data)))
                        break
                    if not isinstance(icmp.data.data, self.Packet):
                        logging.warn('Expected {}, found {}'.format(type(self.Packet), type(icmp.data.data)))
                        break
                    bounce = icmp.data.data
                    if bounce.p not in TCP_OR_UDP:
                        break

                    client = str(dst)
                    remote = str(to_address(bounce.dst))
                    # dpkt may or may not succeed in recognizing and decoding the header of the bounced packet.
                    try:
                        remote_port = ':'.join((str(port) for port in (bounce.data.sport, bounce.data.dport)))
                    except AttributeError:
                        remote_port = ':'.join((str(int.from_bytes(bounce.data[x:x+2], **UNSIGNED_BIG_ENDIAN))
                                                for x in (0,2)
                                                ))
                        
                    k = REDIS_KEY_ICMP.format(client, remote, remote_port, icmp_code)
                    
                elif pkt.p in TCP_OR_UDP:
                    # Reject packets which cannot be decoded.
                    if type(pkt.data) is bytes:
                        logging.warn('{} packet cannot be decoded {}->{}'.format(
                                            pkt.p == socket.IPPROTO_TCP and 'TCP' or 'UDP',
                                            str(src), str(dst)
                                )       )
                        break
                    # In the TCP and UDP cases we need to figure out if the traffic is between a
                    # machine in our network and a machine not in our network, as those are the
                    # only normal cases we care about (but we care about them both).
                    k = ''
                    if dst in self.our_network:
                        if pkt.p == socket.IPPROTO_TCP and pkt.data.flags & dpkt.tcp.TH_RST:
                            # This is a special case where there is a TCP RST seen, and we
                            # want to capture it even if the remote is on our network.
                            remote_port = ':'.join((str(port) for port in (pkt.data.dport, pkt.data.sport)))
                            client = dst
                            remote = src
                            k = REDIS_KEY_RST.format(client, remote, remote_port)
                        elif SUPPRESS_OWN_NETWORK and src in self.our_network:
                            break
                    
                    if not k:
                        if pkt.p == socket.IPPROTO_TCP and pkt.data.flags & SYN_OR_FIN:
                            # Only want TCP packets which don't have a SYN or FIN. That means
                            # that they're legitimate TCP connections.
                            break
                        # Picks the right client, server and server port if possible.
                        mapping = FLOW_MAPPING.match( src, pkt.data.sport, dst, pkt.data.dport )
                        if mapping is None:
                            break
                        k = REDIS_KEY_FLOW.format(*mapping)
                        client, remote, remote_port = mapping
                else:
                    break
                    
                if self.recently.seen(k):
                    break

                if PRINT_PACKET_FLOW:
                    PRINT_PACKET_FLOW("{} <-> {}#{}".format(client, remote, remote_port))

                if   k.endswith('icmp') or k.endswith('rst'):
                    redis_keys = [ k ]
                elif (pkt.src, pkt.data.sport) in IGNORE_FLOW or (pkt.dst, pkt.data.dport) in IGNORE_FLOW:
                    # This will still update the "client;..." key.
                    redis_keys = [ ]
                else:
                    redis_keys = [ k ] + [ REDIS_KEY_PEER.format(*peers) for peers in ((src,dst), (dst,src)) ]

                self.redis.submit(self.redis.flow_to_redis, client, *redis_keys )

            if PCAP_STATS:
                timer.stop()

        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("END process_data")

        if PCAP_STATS:
            if self.socket_recv_timer is None:
                self.socket_recv_timer = self.socket_recv_stats.start_timer()
            else:
                logging.error('Server.socket_recv_timer is unexpectedly NOT None.')
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
    except (CancelledError, ConnectionError):
        pass
    return
    

def main():
    interface, our_network = sys.argv[1:3]
    logging.info('Packet Capture Agent starting. Interface: {}  Our Network: {}  Redis: {}'.format(interface, our_network, REDIS_SERVER))
    event_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(event_loop)
    statistics = StatisticsFactory()
    server = Server(interface, our_network, event_loop, statistics)
    event_loop.add_reader(server.sock, server.process_data)
    if PCAP_STATS:
        stats_routine = event_loop.create_task(statistics_report(statistics))
        
    try:
        event_loop.run_forever()
    except KeyboardInterrupt:
        pass
    
    if PYTHON_IS_311:
        tasks = asyncio.all_tasks(event_loop)
    else:
        tasks = asyncio.Task.all_tasks(event_loop)

    if tasks:
        event_loop.run_until_complete(close_tasks(tasks))

    server.close()
    event_loop.close()
    
    return

if __name__ == '__main__':
    main()
