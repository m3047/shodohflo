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

Keys written to Redis:

    <client-address>;<remote-address>;<remote-port>;flow -> count (TTL_GRACE)
        Remote addresses/ports and a relative count, not the true number of packets

Packets between two nodes on the "our" network are not captured. Only traffic arriving
at (destined for) "our" network is captured.

NOTE: Traffic leaving the host running this agent is not captured. Only traffic
arriving at the interface is captured.
"""

import sys
from os import path
import time
import logging

import ctypes
import ctypes.util
import struct
import socket
import ipaddress
import dpkt
import redis

if __name__ == "__main__":
    from configuration import *
else:
    REDIS_SERVER = 'localhost'
    USE_DNSPYTHON = False
    LOG_LEVEL = None

if LOG_LEVEL is not None:
    logging.basicConfig(level=LOG_LEVEL)

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
    libc = ctypes.CDLL(ctypes.util.find_library('c'))
    if_number = libc.if_nametoindex(ctypes.c_char_p(interface.encode()))
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

class Recent(object):
    """Tracks recently seen things."""
    def __init__(self, cycle=30, buckets=3, frequency=10):
        self.buckets = [ set() for i in range(buckets) ]
        self.working_set = set()
        self.current = self.buckets[0]
        self.last_time = time.time()
        self.cycle = cycle
        self.frequency = frequency
        self.count = 0
        return
    
    def check_frequency(self):
        self.count += 1
        if self.count < self.frequency:
            return
        self.count = 0
        now = time.time()
        if (now - self.last_time) < self.cycle:
            return
        self.last_time = now
        discard = self.buckets.pop()
        working_set = set()
        for bucket in self.buckets:
            working_set |= bucket
        self.working_set = working_set
        self.current = set()
        self.buckets.insert(0, self.current)
        return
    
    def seen(self, thing):
        self.check_frequency()
        if thing in self.working_set:
            return True
        self.working_set.add(thing)
        self.current.add(thing)
        return False

def main():
    interface, our_network = sys.argv[1:3]
    logging.info('Packet Capture Agent starting. Interface: {}  Our Network: {}  Redis: {}'.format(interface, our_network, REDIS_SERVER))
    sock, ip_class, our_network = get_socket(interface, our_network)
    if USE_DNSPYTHON:
        redis_server = resolver.query(REDIS_SERVER).response.answer[0][0].to_text()
    else:
        redis_server = REDIS_SERVER
    redis_client = redis.client.Redis(redis_server, decode_responses=True)
    recently = Recent()
    while True:
        msg = sock.recv(60)
        pkt = ip_class(msg)

        if   pkt.p not in TCP_OR_UDP:
            continue
        
        src = to_address(pkt.src)
        dst = to_address(pkt.dst)

        if   src in our_network:
            if dst in our_network:
                continue
            client = str(src)
            remote = str(dst)
            remote_port = pkt.data.dport
        elif dst in our_network:
            if src in our_network:
                continue
            client = str(dst)
            remote = str(src)
            remote_port = pkt.data.sport
        else:
            continue
        
        k = "{};{};{};flow".format(client, remote, remote_port)
        if recently.seen(k):
            continue

        logging.debug("{} <-> {}#{}".format(client, remote, remote_port))
        redis_client.incr(k)
        redis_client.expire(k, TTL_GRACE)
        k = 'client;{}'.format(client)
        redis_client.incr(k)
        redis_client.expire(k, TTL_GRACE)
        
    sock.close()

if __name__ == '__main__':
    main()
