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

Uses Dnstap to capture A and AAAA responses to specific addresses and send
them to Redis. By default only Client Response type messages are processed
and you'll get better performance if you configure your DNS server to only
send such messages.
        
Keys written to Redis:

    client;<client-address> -> counter (TTL_GRACE)
        Index of all client addresses.
    <client-address>;<address>;dns -> list of onames (ttl + TTL_GRACE)
        List of FQDNs which an address resolves from.
    <client-address>;<rname>;cname -> list of onames (TTL_GRACE)
        List of FQDNs which a CNAME resolves from.
    <client-address>;<oname>;nx -> counter (TTL_GRACE)
        FQDNs which return NXDOMAIN.
"""

import sys
from os import path
import logging

import redis

import dns.rdatatype as rdatatype
import dns.rcode as rcode

sys.path.insert(0,path.dirname(path.dirname(path.abspath(__file__))))

from shodohflo.fstrm import Consumer, Server, UnixSocket
import shodohflo.protobuf.dnstap as dnstap

if __name__ == "__main__":
    from configuration import *
else:
    SOCKET_ADDRESS = '/tmp/dnstap'
    REDIS_SERVER = 'localhost'
    USE_DNSPYTHON = False
    LOG_LEVEL = None

if LOG_LEVEL is not None:
    logging.basicConfig(level=LOG_LEVEL)

CONTENT_TYPE = 'protobuf:dnstap.Dnstap'

TTL_GRACE = 900         # 15 minutes

if USE_DNSPYTHON:
    import dns.resolver as resolver

def hexify(data):
    return ''.join(('{:02x} '.format(b) for b in data))

class DnsTap(Consumer):
    
    ADDRESS_RECORDS = { rdatatype.A, rdatatype.AAAA }
    
    def __init__(self, message_type=dnstap.Message.TYPE_CLIENT_RESPONSE):
        """Dnstap consumer.

        Parameters:
        
            message_type: This agent is intended to consume client response
                          messages. You can have it process all messages by
                          setting this to None, but then you'll get potentially
                          strange client addresses logged to Redis.
        """
        if USE_DNSPYTHON:
            redis_server = resolver.query(REDIS_SERVER).response.answer[0][0].to_text()
        else:
            redis_server = REDIS_SERVER
        self.redis = redis.client.Redis(redis_server, decode_responses=True)
        self.message_type = message_type
        return

    def accepted(self, data_type):
        logging.info('Accepting: {}'.format(data_type))
        if data_type != CONTENT_TYPE:
            logging.warn('Unexpected content type "{}", continuing...'.format(data_type))
        return True

    def client_to_redis(self, client_address):
        k = 'client;{}'.format(client_address)
        self.redis.incr(k)
        self.redis.expire(k, TTL_GRACE)
        return
    
    def a_to_redis(self, client_address, name, ttl, address ):
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
        k = '{};{};cname'.format(client_address, rname)
        oname = ';{};'.format(oname)
        names = self.redis.get(k) or ''
        if oname not in names:
            self.redis.append(k, oname)
        self.redis.expire(k, TTL_GRACE)
        return
    
    def nx_to_redis(self, client_address, name):
        k = '{};{};nx'.format(client_address, name)
        self.redis.incr(k)
        self.redis.expire(k, TTL_GRACE)
        return
    
    def consume(self, frame):
        """Consume Dnstap data.
        
        By default the type is restricted to dnstap.Message.TYPE_CLIENT_RESPONSE.
        """
        performance_hint = True
        message = dnstap.Dnstap(frame).field('message')[1]
        response = message.field('response_message')[1]
        client_address = message.field('query_address')[1]
        if self.message_type and message.field('type')[1] != self.message_type:
            if performance_hint:
                logging.warn('PERFORMANCE HINT: Change your Dnstap config to restrict it to client response only.')
                performance_hint = False
            return True
        if response.rcode() == rcode.NXDOMAIN:
            self.client_to_redis(client_address)
            self.nx_to_redis(client_address, response.question[0].name.to_text().lower())
            return True
        if response.rcode() != rcode.NOERROR:
            return True
        for rrset in response.answer:
            name = rrset.name.to_text()
            if rrset.rdtype in self.ADDRESS_RECORDS:
                self.client_to_redis(client_address)
                ttl = rrset.ttl
                for rr in rrset:
                    self.a_to_redis(client_address, name.lower(), ttl, rr.to_text().lower())
                continue
            if rrset.rdtype == rdatatype.CNAME:
                self.client_to_redis(client_address)
                self.cname_to_redis(client_address, name.lower(), rrset[0].to_text().lower())
                continue
        return True
    
    def finished(self, partial_frame):
        logging.warn('Finished. Partial data: "{}"'.format(hexify(partial_frame)))
        return

def main():
    logging.info('DNS Agent starting. Socket: {}  Redis: {}'.format(SOCKET_ADDRESS, REDIS_SERVER))
    Server(UnixSocket(SOCKET_ADDRESS), DnsTap()).listen()

if __name__ == '__main__':
    main()
    
