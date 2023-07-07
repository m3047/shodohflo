#!/usr/bin/python3
# Copyright (c) 2019-2023 by Fred Morris Tacoma WA
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
import traceback

import asyncio
import redis
from redis.exceptions import ConnectionError

import dns.rdatatype as rdatatype
import dns.rcode as rcode

sys.path.insert(0,path.dirname(path.dirname(path.abspath(__file__))))

from shodohflo.fstrm import Consumer, Server, AsyncUnixSocket, PYTHON_IS_311
import shodohflo.protobuf.dnstap as dnstap
from shodohflo.redis_handler import RedisBaseHandler
from shodohflo.statistics import StatisticsFactory

if PYTHON_IS_311:
    from asyncio import CancelledError
else:
    from concurrent.futures import CancelledError

SOCKET_ADDRESS = '/tmp/dnstap'
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

CONTENT_TYPE = 'protobuf:dnstap.Dnstap'

if TTL_GRACE is None:
    TTL_GRACE = 900         # 15 minutes

if USE_DNSPYTHON:
    if PYTHON_IS_311:
        from dns.resolver import resolve as dns_query
    else:
        from dns.resolver import query as dns_query

# Start/end of coroutines. You will probably also want to enable it in shodohflo.fstrm.
PRINT_COROUTINE_ENTRY_EXIT = None

# Similar to the foregoing, but always set to something valid.
STATISTICS_PRINTER = logging.info

def hexify(data):
    return ''.join(('{:02x} '.format(b) for b in data))

class RedisHandler(RedisBaseHandler):
    """Handles calls to Redis so that they can be run in a different thread."""

    ADDRESS_RECORDS = { rdatatype.A, rdatatype.AAAA }
    
    def __init__(self, event_loop, ttl_grace, statistics):
        RedisBaseHandler.__init__(self, event_loop, ttl_grace)
        if DNS_STATS:
            self.answer_to_redis_stats = statistics.Collector("answer_to_redis")
            self.nx_to_redis_stats = statistics.Collector("nx_to_redis")
            self.backlog = statistics.Collector("redis_backlog")
        return
    
    def redis_server(self):
        if USE_DNSPYTHON:
            server = dns_query(REDIS_SERVER).response.answer[0][0].to_text()
        else:
            server = REDIS_SERVER
        return server
    
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

    def answer_to_redis_(self, client_address, answer):
        """Address and CNAME records to redis - core logic."""
        self.client_to_redis(client_address)
        for rrset in answer:
            name = rrset.name.to_text().lower().replace('\\;',';')
            if rrset.rdtype in self.ADDRESS_RECORDS:
                ttl = rrset.ttl
                for rr in rrset:
                    self.a_to_redis(client_address, name, ttl, rr.to_text().lower())
                continue
            if rrset.rdtype == rdatatype.CNAME:
                self.cname_to_redis(client_address, name, rrset[0].to_text().lower())
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
    
class DnsTap(Consumer):
    
    def __init__(self, event_loop, statistics, ignore=None, message_type=dnstap.Message.TYPE_CLIENT_RESPONSE):
        """Dnstap consumer.

        Parameters:

            ignore:       It's possible to pass a list of strings. Questions will be
                          scanned for the strings and if found the update will be ignored.
                          This is done downstream of process_message(), which means that
                          all messages are available there; you can choose to implement
                          this for your use case or not.
            message_type: This agent is intended to consume client response
                          messages. You can have it process all messages by
                          setting this to None, but then you'll get potentially
                          strange client addresses logged to Redis.
        """
        self.redis = RedisHandler(event_loop, TTL_GRACE, statistics)
        self.message_type = message_type
        self.ignore = ignore
        if DNS_STATS:
            self.consume_stats = statistics.Collector("consume")
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
    
    def post_to_redis(self, message):
        """Analyze and post to the ShoDoHFlo redis database."""
        
        if self.message_type and message.field('type')[1] != self.message_type:
            if self.performance_hint:
                logging.warn('PERFORMANCE HINT: Change your Dnstap config to restrict it to client response only.')
                self.performance_hint = False
            return
        # NOTE: Do these lookups AFTER verifying that we have the correct message type!
        response = message.field('response_message')[1]
        client_address = message.field('query_address')[1]
        
        question = None

        if self.ignore is not None:
            question = response.question[0].name.to_text().lower()
            for s in self.ignore:
                if s in question:
                    return

        redis = self.redis

        if response.rcode() == rcode.NXDOMAIN:
            if question is None:
                question = response.question[0].name.to_text().lower()
            redis.submit(redis.nx_to_redis, client_address, question)
        elif response.rcode() == rcode.NOERROR:
            redis.submit(redis.answer_to_redis, client_address, response.answer)
        
        return
    
    def process_message(self, message):
        """This can be subclassed to add/remove message processing.
        
        Arguments:
            message: DNS wire format message.
        """
        self.post_to_redis(message)
        return

    def consume(self, frame):
        """Consume Dnstap data.
        
        By default the type is restricted to dnstap.Message.TYPE_CLIENT_RESPONSE.
        """
        # NOTE: This function is called in coroutine context, but is not the coroutine itself.
        # Enable PRINT_COROUTINE_ENTRY_EXIT in shodohflo.fstrm if needed.
        if DNS_STATS:
            timer = self.consume_stats.start_timer()

        message = dnstap.Dnstap(frame).field('message')[1]
        self.process_message(message)

        if DNS_STATS:
            timer.stop()
        return True
    
    def finished(self, partial_frame):
        logging.warn('Finished. Partial data: "{}"'.format(hexify(partial_frame)))
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

def main_36(socket_address, statistics, ignore, Consumer_class):
    event_loop = asyncio.get_event_loop()
    if statistics is not None:
        stats_routine = event_loop.create_task(statistics_report(statistics))

    try:
        event_loop.run_until_complete(
            Server( AsyncUnixSocket(socket_address),
                    Consumer_class(event_loop, statistics, ignore),
                    event_loop
                ).listen_asyncio()
            )
    except KeyboardInterrupt:
        pass

    event_loop.run_until_complete(
            close_tasks(asyncio.Task.all_tasks(event_loop))
        )
    event_loop.close()

    return

async def main_311(socket_address, statistics, ignore, Consumer_class):
    event_loop = asyncio.get_running_loop()
    if statistics is not None:
        stats_routine = event_loop.create_task( statistics_report(statistics) )
    
    try:
        await Server(
                AsyncUnixSocket(socket_address),
                Consumer_class(event_loop, statistics, ignore),
                event_loop
            ).listen_asyncio()
    except CancelledError:
        pass
    
    return

def main(Consumer=DnsTap):
    logging.info('DNS Agent starting. Socket: {}  Redis: {}'.format(SOCKET_ADDRESS, REDIS_SERVER))
    statistics = DNS_STATS and StatisticsFactory() or None

    main_args = (
            SOCKET_ADDRESS,
            statistics,
            IGNORE_DNS,
            Consumer
        )
    
    if PYTHON_IS_311:
        asyncio.run(main_311(*main_args))
    else:
        main_36(*main_args)
    
    return

if __name__ == '__main__':
    main()
    
