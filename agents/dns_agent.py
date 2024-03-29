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

"""DNS Agent.

Command Line:

    dns_agent.py <listening-address>:<listening-port> {<multicast-interface>}
    
The agent listens on listening-address:listening-port for (line oriented) JSON
formatted UDP datagrams containing the fields documented in dnstap_agent.py.

REQUIRES PYTHON 3.6 OR BETTER

Keys written to Redis:

    client;<client-address> -> counter (TTL_GRACE)
        Index of all client addresses.
    <client-address>;<address>;dns -> list of onames (ttl + TTL_GRACE)
        List of FQDNs which an address resolves from.
    <client-address>;<rname>;cname -> list of onames (TTL_GRACE)
        List of FQDNs which a CNAME resolves from.
    <client-address>;<oname>;nx -> counter (TTL_GRACE)
        FQDNs which return NXDOMAIN.

The PRINT_ Constants
--------------------

The PRINT_... constants control various debugging output. They can be
set to a print function which accepts a string, for example:

    PRINT_THIS = logging.debug
    PRINT_THAT = print
"""
import sysconfig

import sys
from os import path
import logging
import traceback

from time import time

import asyncio
import socket
from ipaddress import ip_address

import redis
from redis.exceptions import ConnectionError

from json import loads

sys.path.insert(0,path.dirname(path.dirname(path.abspath(__file__))))

from shodohflo.redis_handler import RedisBaseHandler
from shodohflo.statistics import StatisticsFactory

import struct
import shodohflo.mcast_structs as structs

PYTHON_IS_311 = int( sysconfig.get_python_version().split('.')[1] ) >= 11

if PYTHON_IS_311:
    from asyncio import CancelledError
else:
    from concurrent.futures import CancelledError

DNS_CHANNEL = None
REDIS_SERVER = 'localhost'
USE_DNSPYTHON = False
LOG_LEVEL = None
TTL_GRACE = None
DNS_STATS = None
IGNORE_DNS = None

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

if DNS_CHANNEL is None:
    DNS_CHANNEL = {}

# How old a telemetry source has to be to reap it (memory leak prevention).
STALE_PEER = 3600   # 1 hour

# Start/end of coroutines. You will probably also want to enable it in shodohflo.fstrm.
PRINT_COROUTINE_ENTRY_EXIT = None

# Similar to the foregoing, but always set to something valid.
STATISTICS_PRINTER = logging.info

# Used for packing addresses when setting socket options.
BIG_ENDIAN = ( 4, 'big' )

ALL_INTERFACES = ''

def lart(msg=''):
    if msg:
        msg += '\n\n'
    print('{}dns_agent <udp-address>:<udp-port> {{<multicast-interface>}}'.format(msg), file=sys.stderr)
    sys.exit(1)

class DictOfCounters(dict):
    REAP_FREQUENCY = 60 # Once a minute.
    
    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        self.next_reap = time() + self.REAP_FREQUENCY
        return
    
    def update_entry(self, entry, v=None):
        """Update / check for stale entries.
        
        Each entry is an array with two elements:
            0   The sequence number we're tracking for the peer.
            1   The timestamp when the sequence number last changed.
        """
        now = time()

        if v is None:
            entry[0] += 1
        else:
            entry[0] = v
        entry[1] = now

        if now < self.next_reap:
            return
        while self.next_reap < now:
            self.next_reap += self.REAP_FREQUENCY

        reap = now - STALE_PEER
        to_reap = set()
        for peer, peer_entry in self.items():
            if peer_entry[1] < reap:
                to_reap.add(peer)
        for peer in to_reap:
            logging.info('Reaped: {}'.format(peer))
            del self[peer]

        return
    
    def inc(self, k):
        """Return the postincrement value."""
        if k not in self:
            self[k] = [0, 0]
        self.update_entry( self[k] )
        return self[k][0]
    
    def put(self, k, v):
        if k not in self:
            self[k] = [0, 0]
        self.update_entry( self[k], v )
        return

    def expected(self, k, v):
        if k not in self:
            return False
        self.update_entry( self[k] )
        return self[k][0] == v

class RedisHandler(RedisBaseHandler):
    """Handles calls to Redis so that they can be run in a different thread."""

    ADDRESS_RECORDS = { 'A', 'AAAA' }
    
    def __init__(self, event_loop, ttl_grace, statistics):
        RedisBaseHandler.__init__(self, event_loop, ttl_grace)
        if statistics:
            self.answer_to_redis_stats = statistics.Collector("answer_to_redis")
            self.nx_to_redis_stats = statistics.Collector("nx_to_redis")
            self.backlog = statistics.Collector("redis_backlog")
        else:
            self.answer_to_redis_stats = self.nx_to_redis_stats = self.backlog = None
        return
    
    def redis_server(self):
        if USE_DNSPYTHON:
            server = dns_query(REDIS_SERVER).response.answer[0][0].to_text()
        else:
            server = REDIS_SERVER
        return server
    
    def a_to_redis(self, client_address, name, address ):
        """Called internally by rrset_to_redis()."""
        k = '{};{};dns'.format(client_address, address)
        name = ';{};'.format(name)
        names = self.redis.get(k) or ''
        if name not in names:
            self.redis.append(k, name)
        self.redis.expire(k, TTL_GRACE)
        return
    
    def cname_to_redis(self, client_address, oname, rname):
        """Called internally by rrset_to_redis()."""
        k = '{};{};cname'.format(client_address, rname)
        oname = ';{};'.format(oname)
        names = self.redis.get(k) or ''
        if oname not in names:
            self.redis.append(k, oname)
        self.redis.expire(k, TTL_GRACE)
        return

    def answer_to_redis_(self, client_address, answer):
        """Address and CNAME records to redis - core logic."""
        self.client_to_redis(client_address)
        address = answer.pop()
        for i in range(len(answer)):
            name = answer[i]
            if i == len(answer)-1:
                self.a_to_redis(client_address, name, address)
                continue
            else:
                self.cname_to_redis(client_address, name, answer[i+1])
                continue
        return

    def answer_to_redis(self, backlog_timer, client_address, answer):
        """Address and CNAME records to Redis.
        
        Scheduled with RedisHandler.submit().
        """
        if self.stop:
            return
        
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("START answer_to_redis")
        if DNS_STATS:
            timer = self.answer_to_redis_stats.start_timer()

        self.redis_executor(self.answer_to_redis_, client_address, answer)
        
        if DNS_STATS:
            timer.stop()
            backlog_timer.stop()
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("END answer_to_redis")
        return
    
    def nx_to_redis_(self, client_address, name):
        """NXDomain records to Redis - core logic."""
        self.client_to_redis(client_address)
        k = '{};{};nx'.format(client_address, name)
        self.redis.incr(k)
        self.redis.expire(k, TTL_GRACE)
        return
    
    def nx_to_redis(self, backlog_timer, client_address, name):
        """NXDOMAIN records to Redis.
        
        Scheduled with RedisHandler.submit().
        """
        if self.stop:
            return

        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("START nx_to_redis")
        if DNS_STATS:
            timer = self.answer_to_redis_stats.start_timer()

        self.redis_executor(self.nx_to_redis_, client_address, name.replace('\\;',';'))

        if DNS_STATS:
            timer.stop()
            backlog_timer.stop()
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("END nx_to_redis")
        return
    
    def submit(self, func, *args):
        if DNS_STATS:
            backlog_timer = self.backlog.start_timer()
        else:
            backlog_timer = None
        args = (backlog_timer,) + args
        RedisBaseHandler.submit(self, func, *args)
        return
    
class Consumer(asyncio.DatagramProtocol):
    
    ACCEPTED_STATUS = set(( 'NOERROR', 'NXDOMAIN' ))
    
    def initialize(self, event_loop, statistics, ignore=None):
        """Telemetry consumer.

        Parameters:

            ignore:       It's possible to pass a list of strings. Questions will be
                          scanned for the strings and if found the update will be ignored.
                          This is done downstream of process_message(), which means that
                          all messages are available there; you can choose to implement
                          this for your use case or not.
        """
        self.event_loop = event_loop
        self.redis = RedisHandler(event_loop, TTL_GRACE, statistics)
        self.ignore = ignore
        self.requests = set()
        self.last_id = DictOfCounters()
        if statistics:
            self.consume_stats = statistics.Collector("consume")
            self.datagram_stats = statistics.Collector('datagram')
        else:
            self.consume_stats = self.datagram_stats = None
            
        return

    def post_to_redis(self, message):
        """Analyze and post to the ShoDoHFlo redis database."""
        
        client_address = str(message['client'])
        question = message['chain'][0]

        if self.ignore is not None:
            for s in self.ignore:
                if s in question:
                    return

        redis = self.redis

        if message['status'] == 'NXDOMAIN':
            redis.submit(redis.nx_to_redis, client_address, question)
        else:
            redis.submit(redis.answer_to_redis, client_address, message['chain'])
        
        return
    
    def process_message(self, message, peer_address):
        """This can be subclassed to add/remove message processing.
        
        Arguments:
            message: DNS wire format message.
            
        Before calling post_to_redis() message is loaded into a Python dictionary from
        wire format. The following fields must be present and valid:
        
        * id
        * chain
        * address (if status is NOERROR)
        * client
        * status
        * qtype
        
        The id is checked to see if it is monotonically increasing for the peer address.
        
        Status which is not either NOERROR or NXDOMAIN (present in ACCEPTED_STATUS) is
        ignored.
        """
        try:
            message = loads(message)
            field = 'id'
            if not self.last_id.expected( peer_address, message[field]):
                if peer_address in self.last_id:
                    logging.info('sequence {}: {} -> {}'.format( peer_address, self.last_id[peer_address][0]-1, message[field] ))
                else:
                    logging.info('new peer {}'.format( peer_address ))
                self.last_id.put( peer_address, message[field] )
            field = 'chain'
            chain = message[field]
            for i in range(len(chain)):
                fqdn = chain[i]
                if fqdn[-1] != '.':
                    raise TypeError('FQDN "{}" missing trailing "."'.format(fqdn))
                chain[i] = fqdn.lower()
            chain.reverse()
            field = 'address'
            if 'address' in message:
                message[field] = ip_address(message[field])
                chain.append(str(message[field]))
            field = 'client'
            message[field] = str(ip_address(message[field]))
            field = 'status'
            if message[field] not in self.ACCEPTED_STATUS:
                logging.info('{} from {} not in ACCEPTED_STATUS'.format( message[field], peer_address ))
                return
            field = 'qtype'
            if message[field] not in self.redis.ADDRESS_RECORDS:
                logging.info('{} from {} not in ADDRESS_RECORDS'.format( message[field], peer_address ))
                return
        except Exception as e:
            logging.warning('{} from {} while processing {}: {}'.format(type(e).__name__, peer_address, field, e))
            return

        self.post_to_redis(message)
        return

    async def handle_datagram(self, datagram, peer_address, datagram_timer, promise):
        """Consume JSON data."""
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("START handle_datagram")
        if self.consume_stats is not None:
            timer = self.consume_stats.start_timer()

        self.process_message(datagram, peer_address)

        if self.consume_stats is not None:
            timer.stop()
            datagram_timer.stop()
        self.requests.remove(promise[0])
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("END handle_datagram")
        return
    
    def datagram_received(self, datagram, peer):
        promise = []
        task = self.event_loop.create_task(
                    self.handle_datagram( datagram, peer,
                                          self.datagram_stats is not None and self.datagram_stats.start_timer() or None,
                                          promise
            )                           )
        promise.append(task)
        self.requests.add(task)
        return

async def statistics_report(statistics):
    while True:
        await asyncio.sleep(DNS_STATS)
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

def main(address, port, interface=None):
    logging.info('DNS Agent starting. Listening: {}:{}  Redis: {}'.format(address, port, REDIS_SERVER))
    
    event_loop = asyncio.new_event_loop()
    asyncio.set_event_loop( event_loop )

    if DNS_STATS:
        statistics = StatisticsFactory()
        stats_routine = event_loop.create_task( statistics_report(statistics) )
    else:
        statistics = None
    
    try:
        if interface:
            sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM | socket.SOCK_NONBLOCK )
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(( ALL_INTERFACES, int(port) ))
            multicast_interfaces = struct.pack( structs.ip_mreq.item.format,
                                                int(ip_address(address)).to_bytes(*BIG_ENDIAN),
                                                int(ip_address(interface)).to_bytes(*BIG_ENDIAN)
                                              )
            sock.setsockopt( socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_interfaces )
            listener = event_loop.create_datagram_endpoint( Consumer, sock=sock )
        else:
            listener = event_loop.create_datagram_endpoint( Consumer, local_addr=(address, int(port) ))
        transport,consumer = event_loop.run_until_complete(listener)
        consumer.initialize( event_loop, statistics, IGNORE_DNS )
    except PermissionError:
        lart('Permission Denied! (are you root? is the port free?)')
        sys.exit(1)
    except OSError as e:
        lart('{} (did you supply an interface address?)'.format(e))
        sys.exit(1)
    except Exception as e:
        lart('{}'.format(e))
    
    try:
        event_loop.run_forever()
    except KeyboardInterrupt:
        pass

    transport.close()

    if PYTHON_IS_311:
        tasks = asyncio.all_tasks(event_loop)
    else:
        tasks = asyncio.Task.all_tasks(event_loop)

    if tasks:
        event_loop.run_until_complete(close_tasks(tasks))

    event_loop.close()

    return

if __name__ == '__main__':
    argv = sys.argv.copy()
    
    address = DNS_CHANNEL.get('recipient', None)
    port = DNS_CHANNEL.get('port', None)
    
    if   len(argv) < 2 and not (address and port):
        lart("address:port needed")
    elif len(argv) > 3:
        lart("unrecognized argument(s)")

    if not (address and port):
        address_and_port = argv[1].split(':',1)
        if len(address_and_port) != 2:
            lart("improper address:port")
        if not address:
            address = address_and_port[0]
        if not port:
            port = address_and_port[1]

    interface = DNS_CHANNEL.get('recv_interface', None)
    if not interface and len(argv) == 3:
        interface = argv[2]

    try:
        if ip_address(address).is_multicast:
            if not interface:
                lart('interface required for multicast')
        else:
            if interface:
                lart('interfaced not used for unicast')
    except Exception as e:
        lart("{}".format(e))
        
    if interface:
        try:
            ignore = ip_address(interface)
        except Exception:
            lart("Specify the interface using an address bound to it.")
            
    main(address,port,interface)
