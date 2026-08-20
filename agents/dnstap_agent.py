#!/usr/bin/python3
# Copyright (c) 2019-2026 by Fred Morris Tacoma WA
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

"""Dnstap Agent producing UDP Datagrams

The single-minded end goal of this program is to associate an actual queried-for
name (intent) with the resulting IP addresses. Rules are broken.

REQUIRES PYTHON 3.6 OR BETTER

Command Line:
------------

    dnstap2json.py [<unix-socket>|<file-name>] {<dest-host>:<port> {interface-address}}
    
(Line oriented) JSON is written with each line terminated with '\\n'.

Arguments:

    <unix-socket> is the unix domain socket location from which Dnstap data is being read.
    <file-name> is the name of a file from which Dnstap data can be replayed.

    Either <unix-socket> or <file-name> is required.
    
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

Leverages / subclasses: ../examples/dnstap2json.py

Backfill
--------

July 2026: This version attempts to deal with pathologies around (near) simultaneous
A / AAAA / HTTPS queries which we will not discuss here (contact me if you really want
it -- FWM) however several things have changed compared to previous versions:

* SVCB / HTTPS records are processed
* forward and reverse caches are kept with very short (seconds) lifetimes
* CNAMEs are followed (in cache) both backwards and forwards
* CNAMEs are followed across query types

Ultimately the tentative goal is something like treating SVCB targets similarly to
CNAME rdata, but more field experience is needed.

JSON Data Format
----------------

The JSON contains a dictionary with the following fields:

    id:       A monotonically increasing serial number for the datagram, reset to zero
              on restart of the Dnstap agent.
    chain:    A list containing the reversed CNAME chain.
    bkf:      Backfill. A count of the CNAMEs / SVCB records which were backchained
              from the query name. 0 means that the rightmost FQDN in the chain is the
              query name.
    qtype:    The query type: "A", "AAAA", "HTTPS"...
    client:   The address from which the query was sent.
    status:   A status code string, either "NOERROR" or "NXDOMAIN".
    
Additionally when the status is "NOERROR", an additional field is potentially provided:

    address:  The address or "end" of the CNAME chain; both IPv4 and IPv6 are supported.

The only anticipated status values are "NOERROR" and "NXDOMAIN", but best practice is
to explicitly test for both and to ignore any unexpected values.

Unlike dnstap2json (on which this is based) the chain is reversed and internal elements
are not ellipsized when the length of the chain exceeds an internal conservative MTU
(dnstap2json.JSONMapper.MAX_BLOB). This can lead to fragmentation of the UDP packets; be
prepared to accept and reassemble UDP frags if you don't use jumbos.
"""

import sys
from os import path
import logging
from time import time

from ipaddress import ip_address

import dns.rdatatype as rdatatype
import dns.rcode as rcode

import dnstap2json
from dnstap2json import copyright_2026_fred_morris_consulting_tacoma_wa_usa, JSONMapper, FieldMapping

SOCKET_ADDRESS = '/tmp/dnstap'
LOG_LEVEL = None
DNSTAP_STATS = None
PRINT_COROUTINE_ENTRY_EXIT = None

DNS_CHANNEL = None
DNS_MULTICAST_LOOPBACK = None
DNS_MULTICAST_TTL = None
DNSTAP_CHANNEL = None

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
if DNSTAP_CHANNEL:
    dnstap2json.DNSTAP_CHANNEL = DNSTAP_CHANNEL

class MyMapper(JSONMapper):

    # This effectively disables ellipsization.
    MAX_BLOB = 65535
    
    FIELDS = (
            FieldMapping( 'chain',  lambda self,p: self.build_resolution_chain(p), ['bkf'] ),
            FieldMapping( 'address',lambda self,p: None ),
            FieldMapping( 'client', lambda self,p: str(p.field('query_address')[1]) ),
            FieldMapping( 'qtype',  lambda self,p: rdatatype.to_text(p.field('response_message')[1][0].question[0].rdtype) ),
            FieldMapping( 'status', lambda self,p: rcode.to_text(p.field('response_message')[1][0].rcode()) ),
            FieldMapping( 'id',     lambda self,p: self.id )
        )
    
    ADDRESS_TYPES = { rdatatype.A, rdatatype.AAAA }

    def __init__(self):
        JSONMapper.__init__(self)
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

        message = packet.field('response_message')[1][0]
        if message.rcode() == rcode.NXDOMAIN:
            return True
        if not len(message.answer):
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
        addresses = None
        if (  packet.field('response_message')[1][0].rcode() == rcode.NOERROR
           ):
            try:
                # Integrity checking.
                for addr in chain[-1]:
                    ignore = ip_address(addr)
                # The point of the exercise.
                addresses = chain.pop()
            except:
                pass
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
        
    copyright_2026_fred_morris_consulting_tacoma_wa_usa(MyMapper, SOCKET_ADDRESS, recipient, port, interface)
