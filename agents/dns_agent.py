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

"""DNS Agent.

This script takes no arguments.

REQUIRES PYTHON 3.6 OR BETTER

Uses Dnstap to capture A and AAAA responses to specific addresses and send
them to Redis. By default only Client Response type messages are processed
and you'll get better performance if you configure your DNS server to only
send such messages. The expected specification for BIND in named.conf is:

    dnstap { client response; };
    dnstap-output unix "/tmp/dnstap";

If you don't restrict the message type to client responses, a warning message
will be printed for every new connection established.
        
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

import sys
from os import path
import logging

import asyncio
from concurrent.futures import ThreadPoolExecutor
import redis

import dns.rdatatype as rdatatype
import dns.rcode as rcode

sys.path.insert(0,path.dirname(path.dirname(path.abspath(__file__))))

from shodohflo.fstrm import Consumer, Server, AsyncUnixSocket
import shodohflo.protobuf.dnstap as dnstap

if __name__ == "__main__":
    from configuration import *
else:
    SOCKET_ADDRESS = '/tmp/dnstap'
    REDIS_SERVER = 'localhost'
    USE_DNSPYTHON = False
    LOG_LEVEL = None
    TTL_GRACE = None

if LOG_LEVEL is not None:
    logging.basicConfig(level=LOG_LEVEL)

CONTENT_TYPE = 'protobuf:dnstap.Dnstap'

if TTL_GRACE is None:
    TTL_GRACE = 900         # 15 minutes

if USE_DNSPYTHON:
    import dns.resolver as resolver

# Start/end of coroutines.
PRINT_COROUTINE_ENTRY_EXIT = None

def hexify(data):
    return ''.join(('{:02x} '.format(b) for b in data))

class RedisHandler(object):
    """Handles calls to Redis so that they can be run in a different thread."""

    ADDRESS_RECORDS = { rdatatype.A, rdatatype.AAAA }
    
    def __init__(self, redis_server, event_loop):
        if USE_DNSPYTHON:
            redis_server = resolver.query(REDIS_SERVER).response.answer[0][0].to_text()
        else:
            redis_server = REDIS_SERVER
        self.redis = redis.client.Redis(redis_server, decode_responses=True)
        # NOTE: Tried to do this with a BlockingConnectionPool but it refused to connect
        #       to anything but localhost. I don't think it matters, the ThreadPoolExecutor
        #       should limit the number of connections to the number of threads, which is 1.
                        #connection_pool=redis.connection.BlockingConnectionPool(
                            #max_connections=2,timeout=5)
                                       #)
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.event_loop = event_loop
        return
    
    def submit(self, func, *args):
        """Submit a Redis update to run."""
        updater = self.event_loop.run_in_executor(self.executor, func, *args)
        return updater
    
    def client_to_redis(self, client_address):
        """Called internally by the other *_to_redis() methods to update the client."""
        k = 'client;{}'.format(client_address)
        self.redis.incr(k)
        self.redis.expire(k, TTL_GRACE)
        return
    
    def a_to_redis(self, client_address, name, ttl, address ):
        """Called internally by rrset_to_redis()."""
        k = '{};{};dns'.format(client_address, address)
        ttl += TTL_GRACE
        name = ';{};'.format(name)
        names = self.redis.get(k) or ''
        if name not in names:
            self.redis.append(k, name)
        old_ttl = self.redis.ttl(k)
        if old_ttl is None or old_ttl < ttl:
            self.redis.expire(k, ttl)
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

    def answer_to_redis(self, client_address, answer):
        """Address and CNAME records to Redis.
        
        Scheduled with RedisHandler.submit().
        """
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("START answer_to_redis")
        self.client_to_redis(client_address)
        for rrset in answer:
            name = rrset.name.to_text()
            if rrset.rdtype in self.ADDRESS_RECORDS:
                ttl = rrset.ttl
                for rr in rrset:
                    self.a_to_redis(client_address, name.lower(), ttl, rr.to_text().lower())
                continue
            if rrset.rdtype == rdatatype.CNAME:
                self.cname_to_redis(client_address, name.lower(), rrset[0].to_text().lower())
                continue
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("END answer_to_redis")
        return
        
    def nx_to_redis(self, client_address, name):
        """NXDOMAIN records to Redis.
        
        Scheduled with RedisHandler.submit().
        """
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("START nx_to_redis")
        self.client_to_redis(client_address)
        k = '{};{};nx'.format(client_address, name)
        self.redis.incr(k)
        self.redis.expire(k, TTL_GRACE)
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("END nx_to_redis")
        return

class DnsTap(Consumer):
    
    def __init__(self, event_loop, message_type=dnstap.Message.TYPE_CLIENT_RESPONSE):
        """Dnstap consumer.

        Parameters:
        
            message_type: This agent is intended to consume client response
                          messages. You can have it process all messages by
                          setting this to None, but then you'll get potentially
                          strange client addresses logged to Redis.
        """
        self.redis = RedisHandler(REDIS_SERVER, event_loop)
        self.message_type = message_type
        return

    def accepted(self, data_type):
        logging.info('Accepting: {}'.format(data_type))
        if data_type != CONTENT_TYPE:
            logging.warn('Unexpected content type "{}", continuing...'.format(data_type))
        # NOTE: This isn't technically correct in the async case, since DnsTap context is
        # the same for all connections. However, we're only ever expecting one connection
        # at a time and this is intended to provide a friendly hint to the user about their
        # nameserver configuration, so the impact of the race condition is minor.
        self.performance_hint = True
        return True

    def consume(self, frame):
        """Consume Dnstap data.
        
        By default the type is restricted to dnstap.Message.TYPE_CLIENT_RESPONSE.
        """
        message = dnstap.Dnstap(frame).field('message')[1]
        if self.message_type and message.field('type')[1] != self.message_type:
            if self.performance_hint:
                logging.warn('PERFORMANCE HINT: Change your Dnstap config to restrict it to client response only.')
                self.performance_hint = False
            return True
        # NOTE: Do these lookups AFTER verifying that we have the correct message type!
        response = message.field('response_message')[1]
        client_address = message.field('query_address')[1]

        redis = self.redis

        if response.rcode() == rcode.NXDOMAIN:
            redis.submit(redis.nx_to_redis, client_address, response.question[0].name.to_text().lower())
            return True
        if response.rcode() != rcode.NOERROR:
            return True
        redis.submit(redis.answer_to_redis, client_address, response.answer)
        return True
    
    def finished(self, partial_frame):
        logging.warn('Finished. Partial data: "{}"'.format(hexify(partial_frame)))
        return

def main():
    logging.info('DNS Agent starting. Socket: {}  Redis: {}'.format(SOCKET_ADDRESS, REDIS_SERVER))
    event_loop = asyncio.get_event_loop()
    Server(AsyncUnixSocket(SOCKET_ADDRESS), DnsTap(event_loop), event_loop).listen_asyncio()

if __name__ == '__main__':
    main()
    
