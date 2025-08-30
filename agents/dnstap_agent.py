#!/usr/bin/python3
# Copyright (c) 2019-2025 by Fred Morris Tacoma WA
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

REQUIRES PYTHON 3.6 OR BETTER

Command Line:
------------

    dnstap_agent.py <unix-socket> {<dest-host>:<port>} {interface-address}
    
(Line oriented) JSON is written with each line terminated with '\\n'.

Arguments:

    <unix-socket> is required, and is the unix domain socket location to
        which Dnstap data is being written.
    <dest-host> and <port> are optional (although if supplied both are required)
        and specify the receiving end of the stream of UDP packets. If not supplied,
        the JSON is written to stdout.
    <interface-address> is required if <dest-host> is a multicast address, and is
        the (system-) bound address for the interface to be used to send the datagram.

NOTE: The configuration.py file overrides parameters.
    
Uses Dnstap to capture A and AAAA responses to specific addresses and generate
telemetry. By default only Client Response type messages are processed
and you'll get better performance if you configure your DNS server to only
send such messages. The expected specification for BIND in named.conf is:

    dnstap { client response; };
    dnstap-output unix "/tmp/dnstap";

Leverages / subclasses ../examples/dnstap2json.py

JSON Data Format
----------------

The JSON contains a dictionary with the following fields:

    id:       A monotonically increasing serial number for the datagram, reset to zero
              on restart of the Dnstap agent.
    chain:    A list containing the reversed CNAME chain.
    qtype:    The query type, either "A" or "AAAA".
    client:   The address from which the query was sent.
    status:   A status code string, either "NOERROR" or "NXDOMAIN".
    
Additionally when the status is "NOERROR", an additional field is provided:

    address:  The address or "end" of the CNAME chain; both IPv4 and IPv6 are supported.

The only anticipated status values are "NOERROR" and "NXDOMAIN", but best practice is
to explicitly test for both and to ignore any unexpected values.

Unlike dnstap2json (on which this is based) the chain is reversed and internal elements
are not ellipsized when the length of the chain exceeds an internal conservative MTU
(dnstap2json.JSONMapper.MAX_BLOB). This can lead to fragmentation of the UDP packets; be
prepared to accept and reassemble UDP frags.
"""

import sys
from os import path
import logging
from time import time

from ipaddress import ip_address

import dns.rdatatype as rdatatype
import dns.rcode as rcode

import dnstap2json
from dnstap2json import main, JSONMapper, FieldMapping

SOCKET_ADDRESS = '/tmp/dnstap'
LOG_LEVEL = None
DNSTAP_STATS = None
PRINT_COROUTINE_ENTRY_EXIT = None

DNS_CHANNEL = None
DNS_MULTICAST_LOOPBACK = None
DNS_MULTICAST_TTL = None

EXTENDED_CHAIN_LOGGING = False
DNSTAP_EXIT_ON_PERSISTENT_FAILURE = True
DNSTAP_DEDUPLICATION_SECONDS = 1

if __name__ == "__main__":
    from configuration import *

if LOG_LEVEL is not None:
    logging.basicConfig(level=LOG_LEVEL)

dnstap2json.EXIT_ON_PERSISTENT_FAILURE = DNSTAP_EXIT_ON_PERSISTENT_FAILURE
dnstap2json.STATS = DNSTAP_STATS
dnstap2json.PRINT_COROUTINE_ENTRY_EXIT = PRINT_COROUTINE_ENTRY_EXIT
if DNS_MULTICAST_LOOPBACK:
    dnstap2json.MULTICAST_LOOPBACK = DNS_MULTICAST_LOOPBACK
if DNS_MULTICAST_TTL:
    dnstap2json.MULTICAST_TTL = DNS_MULTICAST_TTL

class MyMapper(JSONMapper):

    # This effectively disables ellipsization.
    MAX_BLOB = 65535
    
    FIELDS = (
            FieldMapping( 'chain',  lambda self,p: self.build_resolution_chain(p) ),
            FieldMapping( 'address',lambda self,p: None ),
            FieldMapping( 'client', lambda self,p: str(p.field('query_address')[1]) ),
            FieldMapping( 'qtype',  lambda self,p: rdatatype.to_text(p.field('response_message')[1].question[0].rdtype) ),
            FieldMapping( 'status', lambda self,p: rcode.to_text(p.field('response_message')[1].rcode()) ),
            FieldMapping( 'id',     lambda self,p: self.id )
        )

    def __init__(self):
        self.id_ = 0
        self.last_dedupe_rotation = time()
        self.deduplicate = set()
        return
    
    @property
    def id(self):
        self.id_ += 1
        return self.id_
    
    def filter(self, packet):
        if not JSONMapper.filter(self, packet):
            return False

        message = packet.field('response_message')[1]
        if message.rcode() == rcode.NXDOMAIN:
            return True
        if not len(message.answer):
            return False
        if message.question[0].rdtype not in tuple( rset.rdtype for rset in message.answer ):
            return False

        # Rudimentary deduplication such that a qname + rdtype is emitted no more than
        # once every DEDUPLICATION_SECONDS.
        now = time()
        if self.last_dedupe_rotation < (now - DNSTAP_DEDUPLICATION_SECONDS):
            self.last_dedupe_rotation = now
            self.deduplicate = set()
        query = ( message.question[0].name.to_text().lower(), message.question[0].rdtype )
        if query in self.deduplicate:
            return False
        self.deduplicate.add( query )
        
        return True
    
    def map_fields(self, packet):
        """Performs an explosion of the chain. (generator function)
        
        While multiple CNAMEs for an oname shouldn't occur, multiple addresses are
        an expected artifact.
        """
        data = {}
        for field in self.FIELDS:
            field(data, self, packet)
        # Omit any values which are None.
        for k,v in tuple(data.items()):
            if v is None:
                del data[k]

        chain = data['chain']
        if packet.field('response_message')[1].rcode() == rcode.NOERROR:
            addresses = chain.pop()
            # TODO: This is paranoid integrity checking which can possibly be removed (or
            #       improved) at some point in the future.
            try:
                for addr in addresses:
                    ignore = ip_address(addr)
            except:
                if EXTENDED_CHAIN_LOGGING:
                    logging.info('Invalid address "{}" ({}) {} {}\n  {}'.format(
                        addr, data['qtype'], chain, addresses,
                        { '{} ({})'.format(rrset.name.to_text().lower(), rdatatype.to_text(rrset.rdtype)):
                            [ rr.to_text().lower() for rr in rrset ]
                          for rrset in packet.field('response_message')[1].answer
                        }
                    ))
                else:
                    logging.info('Invalid address "{}" ({}) {} {}'.format(addr, data['qtype'], chain, addresses))
                self.id_ -= 1
                return
        else:
            addresses = None
        chain.reverse()
        for i in range(len(chain)):
            chain[i] = chain[i][0]
        
        # This is the outcome for e.g. NXDOMAIN.
        if addresses is None:
            yield data
            return
        
        # Otherwise, we generate one event per final address.
        additional = False
        for address in addresses:
            data['address'] = address
            if additional:
                data['id'] = self.id
            yield data
            additional = True
        
        return
    
if __name__ == '__main__':
    recipient = port = interface = None

    if DNS_CHANNEL:
        recipient = DNS_CHANNEL.get('recipient', None)
        port = DNS_CHANNEL.get('port', None)
        interface = DNS_CHANNEL.get('send_interface', None)
        
    main(MyMapper, SOCKET_ADDRESS, recipient, port, interface)
