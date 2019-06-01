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
them to Redis.
"""

import sys
from os import path
import logging

import redis

import dns.rdatatype as rdatatype

sys.path.insert(0,path.dirname(path.dirname(path.abspath(__file__))))

from shodohflo.fstrm import Consumer, Server, UnixSocket
import shodohflo.protobuf.dnstap as dnstap

SOCKET_ADDRESS = '/tmp/dnstap'
CONTENT_TYPE = 'protobuf:dnstap.Dnstap'

REDIS_SERVER = 'localhost'
TTL_GRACE = 60

def hexify(data):
    return ''.join(('{:02x} '.format(b) for b in data))

class DnsTap(Consumer):
    
    ADDRESS_RECORDS = { rdatatype.A, rdatatype.AAAA }
    
    def __init__(self):
        self.redis = redis.client.Redis(REDIS_SERVER, decode_responses=True)
        return

    def accepted(self, data_type):
        logging.info('Accepting: {}'.format(data_type))
        if data_type != CONTENT_TYPE:
            logging.warn('Unexpected content type "{}", continuing...'.format(data_type))
        return True
    
    def to_redis(self, client_address, name, ttl, address ):
        k = '{}:{}:dns'.format(client_address,address)
        ttl += TTL_GRACE
        name = ';{};'.format(name)
        names = self.redis.get(k) or ''
        if name not in names:
            self.redis.append(k, name)
        old_ttl = self.redis.ttl(k)
        if old_ttl is None or old_ttl < ttl:
            self.redis.expire(k, ttl)
        return
    
    def consume(self, frame):
        message = dnstap.Dnstap(frame).field('message')[1]
        response = message.field('response_message')[1]
        if response.rcode() != 0:
            return True
        client_address = message.field('query_address')[1]
        for rrset in response.answer:
            if rrset.rdtype not in self.ADDRESS_RECORDS:
                continue
            name = rrset.name.to_text()
            ttl = rrset.ttl
            for rr in rrset:
                self.to_redis(client_address, name, ttl, rr.to_text())
        return True
    
    def finished(self, partial_frame):
        logging.warn('Finished. Partial data: "{}"'.format(hexify(partial_frame)))
        return

def main():
    logging.info('DNS Agent starting. Socket: {}  Redis: {}'.format(SOCKET_ADDRESS, REDIS_SERVER))
    Server(UnixSocket(SOCKET_ADDRESS), DnsTap()).listen()

if __name__ == '__main__':
    main()
    