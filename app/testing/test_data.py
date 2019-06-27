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

"""Data for UI testing purposes.

Command Line:

    test_data.py [4|6]

This script adds test data to the Redis database. You can choose either IP4 or IP6
depending on the (mandatory) argument supplied.

* All FQDNs are under the ".example" TLD.
* All addresses are nonrouting / private.

The data attempts to achieve the following attributes:

* An FQDN that doesn't resolve (NXDOMAIN).
* An unterminated CNAME chain.
* A CNAME loop.
* One address, many names.
* One name, many addresses.
* Resolutions at different depths.
** One of which is NXDOMAIN.
* An address with no resolutions.
* Multiple "our" clients resolving different things.

"Our" clients 2 & 3 are randomly assigned resolving values, with different probabilities.

A number of constants are defined for attributes of the above. You can look at the
source for further information about constants.
"""

import sys
import redis
import ipaddress as ip
from random import random

if __name__ == "__main__":
    from configuration import *
else:
    REDIS_SERVER = 'localhost'
    USE_DNSPYTHON = False
    TTL_GRACE = 900

if USE_DNSPYTHON:
    import dns.resolver as resolver

ADDRESS = { 4:ip.IPv4Address, 6:ip.IPv6Address }
NETWORK = { 4:ip.IPv4Network, 6:ip.IPv6Network }

class FourAndSixThing(object):
    """Contains either/both IP4 and IP6 versions of addresses."""
    def __init__(self, container, four, six=None ):
        self.container = container
        if six is None:
            six = four
        self.four = self.build(4, four)
        self.six  = self.build(6, six )
        return
    
    def build(self, which, value):
        """This gets overridden by subclasses to do different things.
        
        self.container in this case is an appropriate address or network class.
        """
        return self.container[which](value)
    
    def get(self,which):
        """Return either the 4 or 6 thing."""
        if which == 4:
            return self.four
        else:
            return self.six

class Network(FourAndSixThing):
    """Build a network from another network."""
    def build(self, which, value):
        """self.container in this case is an enclosing network."""
        value = NETWORK[which](value)
        return NETWORK[which](
                ( int(self.container.get(which).network_address) | int(value.network_address), value.prefixlen)
            )

class Address(FourAndSixThing):
    """Builds an address inside of a network."""
    def build(self, which, value):
        """self.container in this caase is an enclosing network."""
        return ADDRESS[which](
                int(self.container.get(which).network_address) | value
            )

def client(our_client, which, redis_client):
    k = 'client;{}'.format(str(our_client.get(which)))
    redis_client.incr(k)
    redis_client.expire(k, TTL_GRACE)
    return

TLD = 'example.'

def address(our_client, lhs, rhs, which, redis_client):
    k = '{};{};dns'.format(str(our_client.get(which)), str(rhs.get(which)))
    name = ';{}.{};'.format(lhs, TLD)
    names = redis_client.get(k) or ''
    if name not in names:
        redis_client.append(k, name)
    redis_client.expire(k, TTL_GRACE)
    return

def cname(our_client, lhs, rhs, which, redis_client):
    k = '{};{}.{};cname'.format(str(our_client.get(which)), rhs, TLD)
    oname = ';{}.{};'.format(lhs, TLD)
    names = redis_client.get(k) or ''
    if oname not in names:
        redis_client.append(k, oname)
    redis_client.expire(k, TTL_GRACE)
    return

def flow(our_client, lhs, rhs, which, redis_client):
    k = "{};{};{};flow".format(str(our_client.get(which)), str(lhs.get(which)), 80)
    redis_client.incr(k)
    redis_client.expire(k, TTL_GRACE)
    return

def nxdomain(our_client, lhs, rhs, which, redis_client):
    k = '{};{}.{};nx'.format(str(our_client.get(which)), lhs, TLD)
    redis_client.incr(k)
    redis_client.expire(k, TTL_GRACE)
    return

PRIVATE_SPACE = FourAndSixThing( NETWORK, '10.0.0.0/8', '2001:db8::/32' )

OUR_NETWORK = Network( PRIVATE_SPACE, '0.1.0.0/16',   '0:0:1::/64' )
A_NETWORK   = Network( PRIVATE_SPACE, '0.128.0.0/16', '0:0:80::/64' )
B_NETWORK   = Network( PRIVATE_SPACE, '0.194.0.0/16', '0:0:a2::/64' )

OUR_1_CLIENT = Address( OUR_NETWORK,   2 )
OUR_2_CLIENT = Address( OUR_NETWORK,  52 )
OUR_3_CLIENT = Address( OUR_NETWORK, 221 )

OUTSIDE_A_1  = Address( A_NETWORK,   1 )
OUTSIDE_A_2  = Address( A_NETWORK,  11 )
OUTSIDE_A_3  = Address( A_NETWORK,  55 )
OUTSIDE_A_4  = Address( A_NETWORK, 133 )
OUTSIDE_A_5  = Address( A_NETWORK, 225 )

OUTSIDE_B_1  = Address( B_NETWORK,   3 )
OUTSIDE_B_2  = Address( B_NETWORK, 155 )

CLIENT_1_PROBABILITY = 1.0
CLIENT_2_PROBABILITY = 0.75
CLIENT_3_PROBABILITY = 0.25

MAPPINGS = [
        ('not-resolving',       nxdomain,       None),
        ('site-a',              address,        OUTSIDE_B_2 ),
        ('site-a',              cname,          'load-balancer.cloud' ),
        ('load-balancer.cloud', cname,          'c.pool.oops' ),
        ('c.pool.oops',         nxdomain,       None),
        ('load-balancer.cloud', cname,          'a.pool.balancer.cloud' ),
        ('load-balancer.cloud', cname,          'b.pool.balancer.cloud' ),
        ('load-balancer.cloud', cname,          'd.pool.balancer.cloud' ),
        # There is no 'a'. Eh? Yes I'm seriously not kidding!
        # ('eh.pool.balancer.cloud',address,      OUTSIDE_A_0 ),
        ('b.pool.balancer.cloud', address,      OUTSIDE_A_1 ),
        ('b.pool.balancer.cloud', address,      OUTSIDE_A_2 ),
        ('d.pool.balancer.cloud', address,      OUTSIDE_A_3 ),
        ('site-b',              cname,          'western.cloud' ),
        ('western.cloud',       cname,          'd.pool.balancer.cloud' ),
        ('western.cloud',       cname,          'e.pool.balancer.cloud' ),
        ('e.pool.balancer.cloud', address,      OUTSIDE_A_4 ),
        ('www.janus',           cname,          'janus' ),
        ('www.janus',           cname,          'left.janus' ),
        ('janus',               address,        OUTSIDE_A_5, ),
        ('left.janus',          cname,          'right.janus' ),
        ('right.janus',         cname,          'left.janus' ),
        (OUTSIDE_A_1,           flow,           None),
        (OUTSIDE_A_2,           flow,           None),
        (OUTSIDE_A_3,           flow,           None),
        (OUTSIDE_A_4,           flow,           None),
        (OUTSIDE_A_5,           flow,           None),
        (OUTSIDE_B_1,           flow,           None),
        (OUTSIDE_B_2,           flow,           None)
    ]

def main():
    try:
        which = int(sys.argv[1])
    except IndexError:
        print("Did you specify 4 or 6?")
        return
    print('Addresses/Networks:')
    print('\n'.join(
        ( '  {}: {}'.format( v, globals()[v].get(which) )
          for v in """PRIVATE_SPACE OUR_NETWORK A_NETWORK B_NETWORK OUR_1_CLIENT OUR_2_CLIENT
                      OUR_3_CLIENT OUTSIDE_A_1 OUTSIDE_A_2 OUTSIDE_A_3 OUTSIDE_A_4 OUTSIDE_A_5
                      OUTSIDE_B_1 OUTSIDE_B_2""".split() )
         )         )

    if USE_DNSPYTHON:
        redis_server = resolver.query(REDIS_SERVER).response.answer[0][0].to_text()
    else:
        redis_server = REDIS_SERVER
    redis_client = redis.client.Redis(redis_server, decode_responses=True)
    
    for our_client in (OUR_1_CLIENT, OUR_2_CLIENT, OUR_3_CLIENT):
        client(our_client, which, redis_client)
    
    for mapping in MAPPINGS:
        mapping[1](OUR_1_CLIENT, mapping[0], mapping[2], which, redis_client)
        if random() < CLIENT_2_PROBABILITY:
            mapping[1](OUR_2_CLIENT, mapping[0], mapping[2], which, redis_client)
        if random() < CLIENT_3_PROBABILITY:
            mapping[1](OUR_3_CLIENT, mapping[0], mapping[2], which, redis_client)
    return

if __name__ == '__main__':
    main()
