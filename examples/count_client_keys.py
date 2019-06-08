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

"""Count of client's keys.

Returns some statistics about keys associated with clients.
"""

import sys
from os import path
import logging

import redis

if __name__ == "__main__":
    from configuration import *
else:
    REDIS_SERVER = 'localhost'
    USE_DNSPYTHON = False

if USE_DNSPYTHON:
    import dns.resolver as resolver

def main():
    if USE_DNSPYTHON:
        redis_server = resolver.query(REDIS_SERVER).response.answer[0][0].to_text()
    else:
        redis_server = REDIS_SERVER
    r = redis.client.Redis(redis_server, decode_responses=True)
    
    for client in r.keys('client:*'):

        client_address = client.split(':',1)[1]

        seen_count = r.get('client:{}'.format(client_address)) or 0
        seen_count = seen_count and str(seen_count) or 'n/a'
        dns = len(r.keys('{}:*:dns'.format(client_address)))
        cname = len(r.keys('{}:*:cname'.format(client_address)))
        nx = len(r.keys('{}:*:nx'.format(client_address)))
        flow = len(r.keys('{}:*:flow'.format(client_address)))
                
        print('  {} ({}): dns: {}   cname: {}   nx: {}   flow: {}'.format(client, seen_count, dns, cname, nx, flow))
    
    return

if __name__ == '__main__':
    main()
