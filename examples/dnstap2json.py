#!/usr/bin/python3
# Copyright (c) 2019-2026 by Fred Morris / Fred Morris Consulting Tacoma WA USA
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

"""Dnstap data converted to a (line oriented) JSON stream.

REQUIRES PYTHON 3.6 OR BETTER and uses asyncio.

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

If you send the traffic via UDP

    ./dnstap2json.py /tmp/dnstap 127.0.0.1:3047

then listening for UDP data can be as simple as

    nc -luk 127.0.0.1 3047
    
Capturing and Playing Back Raw Dnstap Frames
--------------------------------------------

An option exists to write raw Dnstap frames to a UDP destination. There are no command
line options to enable this feature, and dnstap2json does not read a configuration file.
Therefore it must be done by modifying the setting of DNSTAP_CHANNEL in this file.
DNSTAP_CHANNEL is a dictionary which follows the same conventions as DNS_CHANNEL in
agents/configuration_sample.py.

Each frame is written as a one line binary string, e.g.:

    b'\\n\\x06athena\\x12\\x0eBIND 9.12.3-P1r\\x8b\\x04\\x08\\x06\\x10\\x01\\x18\\x01"\\x04\\n\\x00...'
    
NOTE: Datagrams. The pickled data is necessarily larger than the raw frame. A given DNS response
is limited to the maximum size of a datagram, which is 64K. A Dnstap frame contains other things.
Frags. Frags used to be ok, but they were never ok. Here we are again with frags. Your firewall
may drop frags. TLDR: on loopback your stack probably supports full 64K jumbos, elsewhere not so
much.
    
If instead of specifying a unix-socket you specify a file name, then the file will be
opened and read as though it was output as a result of configuring DNSTAP_CHANNEL.
SECURITY CAUTION: Each line of the file which starts with b['"] is evaled to yield the
corresponding byte string representing the actual payload. DO NOT try to read files
sent to you by random people on the internet.

Nobody is pretending to maintain an illusion that reading from a file needs to be
particularly faster than reading a file; given the intended purpose of the feature
no attempt is made to do other than read the file synchronously.

ReplayServer.MAX_REPLAY_PER_SEC controls the number of records replayed per second.
        
Customizing the Program
---------------------

The program is meant to be easily customizable in terms of filtering and actual
JSON output by subclassing JSONMapper. To do so, your program will do something
similar to:

    from dnstap2json import main, JSONMapper

    class MyMapper(JSONMapper):
        # Your goodness here.
    ...

    if __name__ == '__main__':
        main(MyMapper)
        
Look at ../agents/dnstap_agent.py as an example!

Review the class documentation for important performance and configuration
information.

The PRINT_ Constants
--------------------

The PRINT_... constants control various debugging output. They can be
set to a print function which accepts a string, for example:

    PRINT_THIS = logging.debug
    PRINT_THAT = print
    
Statistics
----------

Statistics are enabled by setting STATS to a positive integer value (seconds). To
disable statistics, set it to None. For further information see shodohflo.statistics.
"""

import sys, os
from os import path, set_blocking
import logging
import traceback

import asyncio
import socket
from ipaddress import ip_address, IPv4Address, IPv6Address

import json
from time import time
from collections import deque

import dns.rdatatype as rdatatype
import dns.rcode as rcode
import dns.rdata as rdata

sys.path.insert(0,path.dirname(path.dirname(path.abspath(__file__))))

from shodohflo.fstrm import Consumer, AsyncUnixSocket, PYTHON_IS_311
from shodohflo.fstrm import Server as FstrmServer
import shodohflo.protobuf.dnstap as dnstap
from shodohflo.statistics import StatisticsFactory

import struct
import shodohflo.mcast_structs as structs

if PYTHON_IS_311:
    from asyncio import CancelledError
else:
    from concurrent.futures import CancelledError

GLOBAL_EXIT_EXCEPTIONS = (CancelledError, KeyboardInterrupt)

# Number of seconds before we commit suicide after a failure to write with no bright
# future on the horizon.
WRITE_FAILURE_WINDOW = 10
# Should we commit suicide at all?
EXIT_ON_PERSISTENT_FAILURE = True

logging.basicConfig(level=logging.INFO)

CONTENT_TYPE = 'protobuf:dnstap.Dnstap'

# Start/end of coroutines. You will probably also want to enable it in shodohflo.fstrm.
#PRINT_COROUTINE_ENTRY_EXIT = lambda msg:print(msg,file=sys.stderr,flush=True)
PRINT_COROUTINE_ENTRY_EXIT = None

# Similar to the foregoing, but always set to something valid.
STATISTICS_PRINTER = logging.info
# Do we want stats at all? If so, set it to the number of seconds between reports.
#STATS = None
STATS = 60

# Both the UDP + JSON and the raw Dnstap output inherit the setting of these two parameters.
# They only apply if multicast is in use, which is likely to seldom occur for the raw case.
# These parameters are used by UniversalWriter.
MULTICAST_LOOPBACK = 1
MULTICAST_TTL = 1

# Raw, essentially picked, Dnstap output which can be replayed from a saved file.
# See DNS_CHANNEL in ../agents/configuration_sample.py
DNSTAP_CHANNEL = None
#DNSTAP_CHANNEL = dict(
      #recipient='127.0.0.1', port=3077
  #)

def hexify(data):
    return ''.join(('{:02x} '.format(b) for b in data))

def lart():
    print('{} <unix-socket> {{<udp-address>:<udp-port> {{<multicast-interface>}}}}'.format(path.basename(sys.argv[0]).split('.')[0]), file=sys.stderr)
    sys.exit(1)

class CountingDict(dict):
    """A dictionary of counters."""
    def inc(self, k, v=1):
        if k not in self:
            self[k] = 0
        self[k] += v
        return
    
class SVCBParamDeserializers(object):
    
    V4_WIRELEN = int( IPv4Address(1).max_prefixlen / 8 )
    V6_WIRELEN = int( IPv6Address(1).max_prefixlen / 8 )
    
    @staticmethod
    def smallint( raw_data ):
        if len(raw_data) != 2:
            raise TypeError("Expected two octet unsigned value.")
        return int.from_bytes( raw_data, byteorder='big', signed=False )
    
    @staticmethod
    def smallints( raw_data ):
        if len(raw_data)%2 != 0:
            raise TypeError("Expected array of two octet unsigned values.")
        return [
            SVCBParamDeserializers.smallint( raw_data[i*2:(i+1)*2] )
            for i in range( int( len(raw_data) / 2 ) )
        ]
        
    @staticmethod
    def labels( raw_data ):
        working_data = raw_data
        working_labels = []
        while working_data:
            label_end = working_data[0] + 1
            working_labels.append( working_data[ 1 : label_end ] )
            working_data = working_data[ label_end: ]
        return working_labels
        
    @staticmethod
    def empty( raw_data ):
        if len(raw_data):
            raise ValueError("Expected no value to be provided.")
        return True
        
    @staticmethod
    def ipv4addresses( raw_data ):
        wire_size = SVCBParamDeserializers.V4_WIRELEN
        if len(raw_data) % wire_size != 0:
            raise TypeError("Expected array of ipv4 addresses.")
        return [
            IPv4Address( int.from_bytes(raw_data[i*wire_size:(i+1)*wire_size], byteorder='big' ) )
            for i in range( int( len(raw_data) / wire_size ) )
        ]
        
    @staticmethod
    def ipv6addresses( raw_data ):
        wire_size = SVCBParamDeserializers.V6_WIRELEN
        if len(raw_data) % wire_size != 0:
            raise TypeError("Expected array of ipv6 addresses.")
        return [
            IPv6Address( int.from_bytes(raw_data[i*wire_size:(i+1)*wire_size], byteorder='big' ) )
            for i in range( int( len(raw_data) / wire_size ) )
        ]

class SVCBTypeRdata(object):
    """Encapsulated SVCB rdata.
    
    Q: Does this mean you're thinking about writing your own DNS packet
       processing utility?
    A: I pray not.
    """
    LOGGING = logging.warning
    
    SVC_PARAM_KEYS = (
        (   0,  'mandatory',    SVCBParamDeserializers.smallints ),
        (   1,  'alpn',         SVCBParamDeserializers.labels ),
        (   2,  'no-default-alpn', SVCBParamDeserializers.empty ),
        (   3,  'port',         SVCBParamDeserializers.smallint ),
        (   4,  'ipv4hint',     SVCBParamDeserializers.ipv4addresses ),
       #(   5,  'ech', reserved for future use ),
        (   6,  'ipv6hint',     SVCBParamDeserializers.ipv6addresses )
    )
    
    SVC_PARAM_BY_ID = { v[0]:v for v in SVC_PARAM_KEYS }
    
    def __init__(consulting_m3047_net, raw_dns, raw_rdata):
        consulting_m3047_net.raw_dns = raw_dns
        consulting_m3047_net.raw_rdata = bytes(raw_rdata)
        consulting_m3047_net.error = None
        consulting_m3047_net.elements = []
        consulting_m3047_net.priority_ = None
        consulting_m3047_net.target_ = None
        consulting_m3047_net.params_ = None
        consulting_m3047_net.parse()
        return
    
    @property
    def priority(self):
        pri = self.priority_
        if isinstance(pri, tuple):
            pri = self.priority_ = int.from_bytes( self.raw_rdata[ pri[1]:pri[2]], byteorder='big', signed=pri[3] )
        return pri
    
    @property
    def target(self):
        targ = self.target_
        if isinstance(targ, tuple):
            targ = self.target_ = '.'.join( self.elements[ i+targ[3]+1 ][0] for i in range(targ[4]) )
        return targ
    
    @property
    def params(self):
        prm = self.params_
        if isinstance(prm, tuple):
            name, start_pos, end_pos, parent_index, param_count = prm
            prm = self.params_ = {
                self.SVC_PARAM_BY_ID[elem[0]][1]:self.SVC_PARAM_BY_ID[elem[0]][2]( self.raw_rdata[ elem[1]:elem[2] ] )
                for elem in
                self.elements[ parent_index+1:parent_index+1+param_count ]
            }
        return prm
        
    def parse_int(self, name, signed=False, size=2):
        self.elements.append( (name, self.parse_offset, self.parse_offset+size, signed) )
        if name == 'priority':
            self.priority_ = self.elements[-1]
        self.parse_offset += size
        return
    
    def parse_label(self, raw_dns=False):
        if raw_dns:
            source = self.raw_dns
        else:
            source = self.raw_rdata
        
        label_length = int.from_bytes( source[ self.parse_offset:self.parse_offset+1], byteorder='big', signed=False)

        # Either:

        #  Null / root label
        if label_length == 0:
            self.elements.append( ('', self.parse_offset, self.parse_offset+1) )
            self.parse_offset += 1
            return

        #  Pointer
        if label_length & 0xC0:
            pointer = 0xC000 & int.from_bytes( source[ self.parse_offset:self.parse_offset+2], byteorder='big', signed=False)
            starting_element = len(self.elements)  # This is actually one more than the index of the last element.
            saved_offset = self.parse_offset
            self.parse_offset = pointer
            self.parse_domain( 'pointer', raw_dns=True )
            self.parse_offset = saved_offset + 2
            # Remove the recursive results from the element list before adding the correct entry.
            name = self.elements[ starting_element ][0]
            del self.elements[ starting_element: ]
            self.elements.append( (name, saved_offset, self.parse_offset) )
            return

        #  Octets
        self.parse_offset += 1
        self.elements.append( (source[ self.parse_offset:self.parse_offset+label_length],
                               self.parse_offset, self.parse_offset+label_length)
                            )
        self.parse_offset += label_length

        return
        
    def parse_domain(self, name, raw_dns=False):
        # Append a placeholder for later.
        starting_offset = self.parse_offset
        self.elements.append( None )
        our_element = len(self.elements)-1
        while True:
            self.parse_label( raw_dns )
            if not self.elements[-1][0]:
                break
        self.elements[ our_element ] = ( name,
                                         starting_offset, self.parse_offset,
                                         our_element, len(self.elements) - our_element - 1
                                       )
        if name == 'target':
            self.target_ = self.elements[ our_element ]
        return

    def parse_param(self):
        source = self.raw_rdata
        param_key = int.from_bytes( source[ self.parse_offset:self.parse_offset+2 ], byteorder='big', signed=False )
        self.parse_offset += 2
        
        value_len = int.from_bytes( source[ self.parse_offset:self.parse_offset+2], byteorder='big', signed=False )        
        value_start = self.parse_offset + 2
        self.parse_offset = value_start + value_len
        self.elements.append( (param_key, value_start, self.parse_offset) )
        return
        
    def parse_params(self):
        self.elements.append( None )
        our_element = len(self.elements)-1
        starting_offset = self.parse_offset
        while self.parse_offset < len(self.raw_rdata):
            self.parse_param()

        self.elements[ our_element ] = ( 'params',
                                         starting_offset, self.parse_offset,
                                         our_element, len(self.elements) - our_element - 1
                                       )
        self.params_ = self.elements[ our_element ]
        return
        
    def parse(self):
        """Parse the rdata when the object is created."""
        try:
            self.parse_offset = 0
            self.parse_int('priority', signed=False)
            self.parse_domain('target')
            self.parse_params()
        except Exception as e:
            if self.LOGGING:
                self.LOGGING('Bad SVCB rdata: {}: {}'.format(e.__class__.__name__, e))
            self.error = e
        return

class InvalidFQDN(Exception):
    pass

class InvalidAddress(Exception):
    pass

class CNAMEMapping(object):
    """A cache of recent CNAME / SVCB mappings.
    
    NOTE: We patch this into the JSONMapper when it is allocated in DnsTap.__init__().
    
    MAX_CACHE should be sized to maintain perhaps the last minute of context maximum, 
    if what you're really trying to do is fix short-circuit (6+4) lookups rather than
    general enhancement (I don't recommend this).
    """
    
    CACHE_TIME = 15    # seconds
    MAX_CACHE = 1000    # Oughta be enough for anybody...
    ADDRESS_TYPES = { rdatatype.A, rdatatype.AAAA }
    
    def __init__(self):
        self.forward = {}
        self.reverse = {}
        self.mappings = deque()
        return
    
    @staticmethod
    def valid_address( address, rdtype ):
        if   rdtype == rdatatype.A:
            return IPv4Address( address )
        elif rdtype == rdatatype.AAAA:
            return IPv6Address( address )
        raise InvalidAddress('Invalid {} address: {}'.format(rdatatype.to_text(rdtype), address))
    
    @staticmethod
    def valid_fqdn( fqdn, rdtype ):
        if (not fqdn.endswith('.')) or ' ' in fqdn:
            raise InvalidFQDN('Invalid {} FQDN {}'.format(rdatatype.to_text(rdtype), fqdn))
        return
        
    def add(self, map_from, map_to, rdtype):
        """Validates the values before adding to the mapping."""
        self.valid_fqdn( map_from, rdtype )
        for item in map_to:
            if rdtype in self.ADDRESS_TYPES:
                self.valid_address( item, rdtype )
            else:
                self.valid_fqdn( item, rdtype )
        
        now = time()
        self.forward[map_from] = ( map_to, rdtype )
        for fqdn in map_to:
            self.reverse[fqdn] = ( map_from, rdtype )
        self.mappings.appendleft( (map_from, map_to, now) ) # at the left end
        cutoff_time = now - self.CACHE_TIME
        while ( len(self.mappings)
            and ( self.mappings[-1][2] < cutoff_time or len(self.mappings) > self.MAX_CACHE )
              ):
            remove = self.mappings.pop()                             # at the right end
            if remove[0] in self.forward:
                del self.forward[ remove[0] ]
            for fqdn in remove[1]:
                if fqdn in self.reverse:
                    del self.reverse[ fqdn ]
        return
    
    def __str__(self):
        """Amateurish for anything except debugging."""
        return 'Mappings: {}\nForward:\n    {}\nReverse:\n    {}'.format(
                        len(self.mappings),
                        '\n    '.join( '{:<30s} {}'.format(k,v) for k,v in sorted(self.forward.items()) ),
                        '\n    '.join( '{:<30s} {}'.format(k,v) for k,v in sorted(self.reverse.items()) )
                    )
    
class FieldMapping(object):
    """Maps a JSON name to its value."""
    def __init__(self, name, extract, additional=None):
        """Enumerate a mapping.
        
        name:       The name to be given to the JSON element in the toplevel
                    dict.
        extract:    A function taking the packet as an argument and returning the
                    extracted value.
        additional: An ordered list of additional mapping keys to be set based on the
                    result of the mapping function. When this is passed an a nonempty
                    list then the return result is a list or tuple with the additional
                    values corresponding to the additional keys.
        """
        self.name = name
        self.extract = extract
        self.additional = additional and [ name ] + additional or []
        return
    
    def __call__(self, mapping, mapper, packet):
        """Maps the extracted value.
        
        Traps and warns on errors.
        """
        try:
            result = self.extract(mapper, packet)
            if not self.additional:
                mapping[self.name] = result
            else:
                for i,k in enumerate( self.additional ):
                    mapping[k] = result[i]
        except GLOBAL_EXIT_EXCEPTIONS as e:
            raise e
        except Exception as e:
            logging.warning("Field extraction error for {}: {}: {}\n{}".format(
                self.name, e.__class__.__name__, e, traceback.format_exc(limit=4))
            )
        return

class JSONMapper(object):
    """Map Dnstap data to JSON.

    This particular implementation filters only client responses to
    A and AAAA queries, including CNAME chains. Chains are "ellipsed"
    in the middle if the estimated size of the resulting JSON blob is
    over MAX_BLOB.

    Since only Client Response type messages are processed
    you'll get better performance if you configure your DNS server to only
    send such messages. The expected specification for BIND in named.conf is:

    dnstap { client response; };
    dnstap-output unix "/tmp/dnstap";

    If you don't restrict the message type to client responses, a warning message
    will be printed for every new connection established.

    Subclassing to change Filtering or Output
    -----------------------------------------
    
    filter() -- change packet selection
    
    Override filter() to change the packets which get processed further. Some changes
    can be accomplished by changing MESSAGE_TYPE or ACCEPTED_RECORDS instead.
    
    MESSAGE_TYPE -- dnstap.Message.TYPE_* Dnstap message type
    
    Changes to this should be coordinated with your nameserver configuration (discussed
    above).
    
    ACCEPTED_RECORDS -- query types
    
    This is the set of question (question rdata type or qtype) data types which are accepted.
    The default is A and AAAA. the constants are defined in dns.rdatatype'
    
    FIELDS -- change the output data
    
    This list is used to populate a map which is then JSONified. Each entry in the list is an
    instance of FieldMapping, which ties a JSON name to a function which can extract the
    appropriate data.
    
    SVCB Support
    ------------
    
    Older versions of dnspython do not support SVCB, and I wrote my own rdata deserializer
    SVCBTypeRdata.
    
    Consequently I warn once when a SVCB payload is encountered while using a version of
    dnspython with native but incompatible support. You can disable this warning by setting
    self.warned_svcb = True in your subclass.
    
    SMELL: Sounds kinda backwards that the newer versions aren't supported, but 1) installed
    base, 2) no patience for changes which aren't stable. LOTL matters. At the present time
    at least on the networks I have access to, for the intended purpose, lack of SVCB support
    doesn't cause a problematic failure of attribution.
    """
    
    # This should be safely below MTU, with the intent to avoid fragmentation.
    MAX_BLOB = 1024
    MESSAGE_TYPE = dnstap.Message.TYPE_CLIENT_RESPONSE
    ACCEPTED_RECORDS = { rdatatype.A, rdatatype.AAAA, 64, 65 }
    SVCB_COMPATIBLE_OR_CNAME = { rdatatype.CNAME, 64, 65 }
    SVCB_COMPATIBLE = { 64, 65 }
    NOT_SVCB_COMPATIBLE = { rdatatype.A, rdatatype.AAAA, rdatatype.CNAME }

    # NOTE: As of (01-Jul-2026) p.field('response_message')[1] is no longer just the deserialized
    #       protobuf, it's now a tuple of (protobuf, raw_dns_packet). See shodohflo.protobuf.dnstap
    FIELDS = (
            FieldMapping( 'client', lambda self,p:str(p.field('query_address')[1]) ),
            FieldMapping( 'qtype',  lambda self,p:rdatatype.to_text(p.field('response_message')[1][0].question[0].rdtype) ),
            FieldMapping( 'status', lambda self,p:rcode.to_text(p.field('response_message')[1][0].rcode()) ),
            FieldMapping( 'chain',  lambda self,p:self.build_resolution_chain(p), ['backfill'] )
        )
    
    def __init__(self):
        self.warned_svcb = False
        # This is used internally for debugging / logging. Unless you're doing threading
        # inside of field mapping there shouldn't be anything to be concerned about as
        # long as map_fields() is an atomic operation. (Hence, no thread locking.)
        # Even if it breaks all it affects is the logging of which field was being processed
        # at the time. Bear in mind it should have been logged inside of FieldMapping.__call__()
        # before it ever gets to the handler in this scope.
        self.field_name = None
        return
    
    def build_resolution_chain(self, packet):
        """Build the (CNAME) resolution chain with ellipsization.
        
        CNAMEs should only have one RR each, right? CNAME chains should be short, right?
        Yeah. Right. So, each element in the chain is actually a list, and the total
        length of all of the elements in the list of lists cannot exceed MAX_BLOB or we
        start taking chunks out of the middle to make it smaller.
        
        SVCB compatible types are treated much like CNAMEs except that they're queried for.
        (CNAMEs in the context of A / AAAA just appear in the answer data, nobody explicitly
        queries for CNAMEs.) As a consequence the target generates a separate A / AAAA query.
        I've noticed something similar happening on occasion with dual-stack (A + AAAA) queries
        the e.g. AAAA query will resolve a CNAME chain; then the A record simply queries for the
        same oname (at the end of the chain) which resolved in the AAAA query.
        """
        response, raw_dns = packet.field('response_message')[1]
        question = response.question[0].name.to_text().lower()
        qtype = response.question[0].rdtype
        
        # Deal with NXDOMAIN.
        if response.rcode() == rcode.NXDOMAIN:
            return [ [question] ], 0
        
        # Build a mapping of the rrsets.
        try:
            for rrset in response.answer:
                targets = []
                if   rrset.rdtype in self.SVCB_COMPATIBLE:
                    # TODO: Support for versions of dnspython natively supporting SVCB / HTTPS would go here.
                    for rr in rrset:
                        if isinstance(rr, rdata.GenericRdata):
                            svcb = SVCBTypeRdata( raw_dns, rr.data )
                            if svcb.error:
                                logging.error('SVCBTypeRdata failed to parse answer for {}: {} {}'.format(
                                                question, self.error.__class__.__name__, self.error)
                                )
                            else:
                                if svcb.target and svcb.target != '.':
                                    targets.append(svcb.target.lower())
                            continue
                        try:
                            svcb_handled = False
                            svcb_target = rr.target.to_text().lower()
                            if rr.priority and svcb_target and svcb_target != '.':
                                targets.append( svcb_target )
                                svcb_handled = True
                        except Exception:
                            pass
                        if scvb_handled:
                            continue
                        if not self.warned_svcb and not (hasattr( rr, 'priority' ) and hasattr( rr, 'target' )):
                            self.warned_svcb = True
                            logging.warning('dnspython implementation of SVCB not supported. rdata type: {}'.format(rrset[0].__class__.__name__))
                    if targets:
                        self.mapping.add( rrset.name.to_text().lower(), targets, rrset.rdtype )
                elif  rrset.rdtype in self.NOT_SVCB_COMPATIBLE:
                    self.mapping.add( rrset.name.to_text().lower(), [ rr.to_text().lower() for rr in rrset ], rrset.rdtype )
        except (InvalidFQDN, InvalidAddress) as e:
            raise type(e)('Query {} ({}): {}'.format( question, rdatatype.to_text(qtype), e ))
        
        # Follow the question (CNAMEs & SVCBs) to an answer.
        #
        # There are two aberrant scenarios to be handled:
        #
        # 1) CNAMEs all the way down.
        #
        # 2) The qname short-circuits a CNAME chain, which we recover from previously
        #    seen data.        
        names = [ question ]
        seen = set()
        chain = [ [question] ]
        
        #print(self.mapping)

        # Was this a short circuit query? Backfill.
        fqdn = question
        while fqdn in self.mapping.reverse:
            if fqdn in seen:
                break
            seen.add( fqdn )
            parent = self.mapping.reverse[ fqdn ][0]
            chain.insert( 0, [ parent ] )
            fqdn = parent
        
        backfilled = len(chain) - 1

        # Now search forward.
        while names:
            name = names.pop(0)
            if name in self.mapping.forward:
                rr_values = [ rr.lower() for rr in self.mapping.forward[name][0] ]
                rdtype = self.mapping.forward[name][1]
                if rdtype in self.SVCB_COMPATIBLE_OR_CNAME:
                    for rr in rr_values:
                        if rr in seen:
                            continue
                        names.append(rr)
                        seen.add(rr)
                chain.append( rr_values )
                
        # Ellipsize if it exceeds MAX_BLOB.
        lengths = [ sum((len(name) for name in e)) for e in chain ]
        if sum(lengths) > self.MAX_BLOB:
            logging.warning('Resolution chain for {} exceeds {}, ellipsizing.'.format(question, self.MAX_BLOB))
            shortened = None
            while sum(lengths) > self.MAX_BLOB:
                if len(lengths) < 3:
                    break
                shortened = int(len(lengths) / 2)
                del lengths[shortened]
                del chain[shortened]
            if shortened:
                chain.insert(shortened, ['(...)'])

        return chain, backfilled
    
    def filter_raw(self, packet):
        """Returns True if the dnstap frame should be written to the raw writer.
        
        We have the ability here to write raw dnstap frames as bytestreams.
        These can be replayed for testing and analysis purposes.
        
        This method is only called if a raw writer is defined. Or in other words, if
        DNSTAP_CHANNEL has been configured.
        
        The argument is the decoded message, the same as with filter().
        """
        # Dump the same frames which we are writing to the output stream.
        # return self.filter( packet )
        # Dump all the frames.
        return True

    def filter(self, packet):
        """Return True if the packet should be processed further."""
        if packet.field('type')[1] != self.MESSAGE_TYPE:
            if self.performance_hint:
                logging.warning('PERFORMANCE HINT: Change your Dnstap config to restrict it to client response only.')
                self.performance_hint = False
            return False
        if packet.field('response_message')[1][0].question[0].rdtype not in self.ACCEPTED_RECORDS:
            return False
        return True
    
    def map_fields(self, packet):
        """Maps all of the fields to their values. (generator function)
        
        The default implementation returns a single value, but being a genfunc
        allows this to be expanded to cases where multiple records are generated
        by a single input record.
        """
        data = {}
        for field in self.FIELDS:
            self.field_name = field.name
            field(data, self, packet)
        # Omit any values which are None.
        for k,v in tuple(data.items()):
            if v is None:
                del data[k]
        yield data
        return

class UniversalWriter(object):
    """Plastering over the differences between file descriptors and network sockets."""
    
    FAKE_STDOUT_TIMEOUT = 0
        
    def __init__(self, destination, interface, event_loop):
        """If destination is supplied then this is a UDP socket, otherwise STDOUT."""
        self.destination = destination
        if destination is not None:
            host, port = destination.split(':',1)

            sock = self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM|socket.SOCK_NONBLOCK)
            
            if ip_address(host).is_multicast:
                sock.setsockopt( socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, MULTICAST_LOOPBACK )
                local_interface_arg = struct.pack( structs.in_addr.item.format, int(ip_address(interface)).to_bytes(4, 'big') )
                sock.setsockopt( socket.IPPROTO_IP, socket.IP_MULTICAST_IF, local_interface_arg )
                sock.setsockopt( socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL )
            
            sock.connect((host,int(port)))
        else:
            self.fd = sys.stdout
            set_blocking(self.fd.fileno(), False)
        self.loop = event_loop
        self.tasks = asyncio.Queue()
        self.write_task = self.loop.create_task( self.writer() )
        return
    
    def close(self):
        if self.destination is None:
            set_blocking(self.fd.fileno(), True)
        else:
            self.sock.close()
        return
    
    def fileno(self):
        """Part of the socket interface required by loop.sock_sendall()."""
        if self.destination is None:
            return self.fd.fileno()
        return self.sock.fileno()
    
    def gettimeout(self):
        """Part of the socket interface required by loop.sock_sendall().
        
        For stdout we just use a fake value.
        """
        if self.destination is None:
            timeout = self.FAKE_STDOUT_TIMEOUT
        else:
            timeout = self.sock.gettimeout()
        return timeout
    
    def send(self, data):
        """Part of the socket interface required by loop.sock_sendall().
        
        Call appropriate write method on underlying stream object.
        """
        if self.destination is None:
            count = self.fd.write(data)
        else:
            count = self.sock.send(data)
        return count
    
    def encode_data(self, msg):
        """Convert str to bytes when sending to a UDP socket."""
        if self.destination is not None:
            return msg.encode()
        return msg
    
    def write(self, msg, backlog_timer):
        """To be called to queue something to be output.
        
        Handles task management and creates the task which performs the actual write.
        """
        self.tasks.put_nowait( (msg, backlog_timer) )
        return
    
    @staticmethod
    def failure_window_exceeded( timestamp ):
        """Is the timestamp within WRITE_FAILURE_WINDOW?"""
        return timestamp and (time() - timestamp) > WRITE_FAILURE_WINDOW
        
    async def writer(self):
        """Called to dequeue and send msg.
        
        Doing it as a persistent co-routine emptying a queue now.
        """
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("START writer")
        tasks = self.tasks
        write_failure = None
        cancelled = False
        while True:

            try:
                msg, backlog_timer = await tasks.get()
                tasks.task_done()
                # In the previous implementation, on (some) Linux systems our coroutine might be
                # garbage collected while awaiting loop.sock_sendall(), in spite of the fact that
                # we had a reference to it saved. Our mitigation was to save the Task object for
                # loop.sock_sendall(). Now it runs continuously, and we still assign the sendall
                # Task explicitly to a variable.
                sending = True
                sendall = self.loop.sock_sendall(self, self.encode_data(msg))
                await sendall
                sending = False
                
                if backlog_timer:
                    backlog_timer.stop()
                    backlog_timer = None

                if self.failure_window_exceeded( write_failure ):
                    write_failure = None
            except CancelledError:
                cancelled = True
                break
            except Exception as e:
                # A common pattern observed with e.g. ConnectionRefusedError is that some requests
                # give the appearance of success (and don't throw an exception) even though nothing
                # is actually written. Since we're duck-typing the socket interface for
                # loop.sock_sendall(), who knows?
                if sending and backlog_timer:
                    backlog_timer.stop()

                if not write_failure:
                    if isinstance(e, ConnectionError):
                        logging.critical('Unable to write data (lost): {}'.format(e))
                    else:
                        logging.critical('Unable to write data (lost):\n{}'.format(traceback.format_exc(limit=3)))
                    self.write_failure = time()
                if self.failure_window_exceeded( write_failure ) and EXIT_ON_PERSISTENT_FAILURE:
                    sys.exit(1)

        # This actually never exits.
        if not cancelled:
            raise RuntimeError('UniversalWriter.writer() should never exit!')
        
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("END writer")
        return
        
class DnsTap(Consumer):
    
    def __init__(self, event_loop, statistics, mapper, writer, raw_writer=None):
        """Dnstap consumer."""
        self.loop = event_loop
        #
        # Did it this way instead of adding the mapping to the JSONMapper constructor for
        # backwards compatility with what you fans have built out there.
        self.mapper = mapper
        mapper.mapping = CNAMEMapping()
        #
        self.writer = writer
        self.raw_writer = raw_writer
        if STATS:
            self.consume_stats = statistics.Collector("consume")
            self.backlog = statistics.Collector("output_backlog")
            if self.raw_writer:
                self.raw_backlog = statistics.Collector("raw_backlog")
        return

    def accepted(self, data_type):
        logging.info('Accepting: {}'.format(data_type))
        if data_type != CONTENT_TYPE:
            logging.warning('Unexpected content type "{}", continuing...'.format(data_type))
        # NOTE: This isn't technically correct in the async case, since DnsTap context is
        # the same for all connections. However, we're only ever expecting one connection
        # at a time and this is intended to provide a friendly hint to the user about their
        # nameserver configuration, so the impact of the race condition is minor.
        self.mapper.performance_hint = True
        return True

    def consume(self, frame):
        """Consume Dnstap data."""
        # NOTE: This function is called in coroutine context, but is not the coroutine itself.
        # Enable PRINT_COROUTINE_ENTRY_EXIT in shodohflo.fstrm if needed.
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('START consume')
        if STATS:
            timer = self.consume_stats.start_timer()

        message = dnstap.Dnstap(frame).field('message')[1]
        #print( message.field('response_message')[1][0].question )

        if self.raw_writer and self.mapper.filter_raw( message ):
            self.raw_writer.write( repr( frame ) + '\n', STATS and self.raw_backlog.start_timer() or None )
            
        if not self.mapper.filter(message):
            if STATS:
                timer.stop()
            if PRINT_COROUTINE_ENTRY_EXIT:
                PRINT_COROUTINE_ENTRY_EXIT('END consume')
            return True

        try:
            for data in self.mapper.map_fields(message):
                # Actually queues a separate coroutine.
                self.writer.write( json.dumps(data) + "\n",
                                STATS and self.backlog.start_timer() or None
                            )
        except GLOBAL_EXIT_EXCEPTIONS as e:
            raise e
        except Exception as e:
            logging.error('Internal error mapping field "{}": {} {}'.format(self.mapper.field_name, e.__class__.__name__, e))
            logging.warning(traceback.format_exc(limit=3))
        
        if STATS:
            timer.stop()
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('END consume')
        return True
    
    def finished(self, partial_frame):
        logging.warning('Finished. Partial data: "{}"'.format(hexify(partial_frame)))
        return
    
class Server(FstrmServer):
    """Overrides shodohflo.fstrm.Server."""
    
    def __init__(self,stream,consumer,loop=None,data_type=None):
        FstrmServer.__init__(self, stream, consumer, loop, data_type)
        return
    
class ReplayServer(object):
    """Replays previously captured Dnstap frames.
    
    ENOUGH_BUFFERING: The notion is to have enough buffered that when the consumer
    hits an empty queue after the file has been successfully read, that the
    file has finished being processed.
    """
    
    ENOUGH_BUFFERING = 10
    FRAME_START = { "b'", 'b"' }
    MAX_REPLAY_PER_SEC = 20
    
    @staticmethod
    def is_replay_file( filename ):
        """Is this a file or a socket?
        
        If it's a unix socket that's the normal "live data" mode. If it's the name of
        a valid, actual, file, then the file is presumably previously captured Dnstap
        frames to be replayed.
        """
        # Alternately: os.stat( filename ).st_mode & 0xf000 != 0xc000
        return os.path.isfile( filename )
    
    def __init__(self, filename, consumer, loop):
        self.filename = filename
        self.end_of_file = False
        self.consumer = consumer
        self.loop = loop
        self.frames = asyncio.Queue( self.ENOUGH_BUFFERING, loop=loop )
        return
    
    async def file_reader( self ):
        try:
            with open(self.filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if not line[:2] in self.FRAME_START:
                        continue
                    await self.frames.put( eval( line ) )
        except Exception as e:
            logging.critical('Error reading {}: {} {}'.format(self.filename, e.__class__.__name__, e))
        self.end_of_file = True
        return
    
    async def queue_processor( self ):
        while not (self.end_of_file and self.frames.empty()):
            self.consumer.consume( await self.frames.get() )
            await asyncio.sleep( 1 / self.MAX_REPLAY_PER_SEC, loop=self.loop )
        return
    
    async def consume_file( self ):
        """Runs file_reader() and queue_processor() in parallel to process the file."""
        results = await asyncio.wait( ( self.file_reader(), self.queue_processor() ), loop=self.loop )
        return
    
async def statistics_report(statistics):
    """Statistics aren't turned on unless STATS is set to a positive number of seconds."""
    while True:
        await asyncio.sleep(STATS)
        for stat in sorted(statistics.stats(), key=lambda x:x['name']):
            STATISTICS_PRINTER(
                '{}: emin={:.4f} emax={:.4f} e1={:.4f} e10={:.4f} e60={:.4f} dmin={} dmax={} d1={:.4f} d10={:.4f} d60={:.4f} nmin={} nmax={} n1={:.4f} n10={:.4f} n60={:.4f}'.format(
                    stat['name'],
                    stat['elapsed']['minimum'], stat['elapsed']['maximum'], stat['elapsed']['one'], stat['elapsed']['ten'], stat['elapsed']['sixty'],
                    stat['depth']['minimum'], stat['depth']['maximum'], stat['depth']['one'], stat['depth']['ten'], stat['depth']['sixty'],
                    stat['n_per_sec']['minimum'], stat['n_per_sec']['maximum'], stat['n_per_sec']['one'], stat['n_per_sec']['ten'], stat['n_per_sec']['sixty'])
                )

        coroutines = CountingDict()
        for task in (PYTHON_IS_311 and asyncio.all_tasks() or asyncio.Task.all_tasks()):
            coroutines.inc(task._coro.__name__)        
        STATISTICS_PRINTER( 'queues: writeq={} '.format(statistics.writer_tasks.qsize()) + ' '.join( '{}={}'.format(k,v) for k,v in sorted( coroutines.items() ) ) )
    return

async def close_tasks(tasks):
    all_tasks = asyncio.gather(*tasks)
    all_tasks.cancel()
    try:
        await all_tasks
    except GLOBAL_EXIT_EXCEPTIONS:
        pass
    return

def main_36(socket_address, destination, interface, Mapper_Class, raw_destination, raw_interface):
    event_loop = asyncio.get_event_loop()
    statistics = StatisticsFactory()
    writer = UniversalWriter(destination, interface, event_loop)
    if raw_destination:
        raw_writer = UniversalWriter( raw_destination, raw_interface, event_loop)
    else:
        raw_writer = None
    if STATS:
        stats_routine = asyncio.run_coroutine_threadsafe(statistics_report(statistics), event_loop)
        statistics.writer_tasks = writer.tasks

    try:
        if ReplayServer.is_replay_file( socket_address ):
            event_loop.run_until_complete(
                ReplayServer(
                        socket_address,
                        DnsTap(event_loop, statistics, Mapper_Class(), writer, raw_writer),
                        event_loop
                    ).consume_file()
                )
        else:
            event_loop.run_until_complete(
                Server( AsyncUnixSocket(socket_address),
                        DnsTap(event_loop, statistics, Mapper_Class(), writer, raw_writer),
                        event_loop
                    ).listen_asyncio()
                )
    except KeyboardInterrupt:
        pass

    writer.close()
    if raw_writer:
        raw_writer.close()
    event_loop.run_until_complete(
            close_tasks(asyncio.Task.all_tasks(event_loop))
        )
    event_loop.close()
    return

async def main_311(socket_address, destination, interface, Mapper_Class, raw_destination, raw_interface):
    event_loop = asyncio.get_running_loop()
    statistics = StatisticsFactory()
    writer = UniversalWriter(destination, interface, event_loop)
    if raw_destination:
        raw_writer = UniversalWriter( raw_destination, raw_interface, event_loop)
    else:
        raw_writer = None
    if STATS:
        stats_routine = event_loop.create_task( statistics_report(statistics) )
        statistics.writer_tasks = writer.tasks
    
    try:
        if ReplayServer.is_replay_file( socket_address ):
            await ReplayServer(
                        socket_address,
                        DnsTap(event_loop, statistics, Mapper_Class(), writer, raw_writer),
                        event_loop
                    ).consume_file()
        else:
            await Server(
                    AsyncUnixSocket(socket_address),
                    DnsTap(event_loop, statistics, Mapper_Class(), writer, raw_writer),
                    event_loop
                ).listen_asyncio()
    except CancelledError:
        pass
    
    writer.close()
    if raw_writer:
        raw_writer.close()
    return

def copyright_2026_fred_morris_consulting_tacoma_wa_usa(JSONMapper_class=JSONMapper, socket_address=None, recipient=None, port=None, interface=None):
    """Hi, thanks for reading this!
    
    You can subclass JSONMapper to alter the records which get selected as well as
    the JSON which is output.
    
    Parameters
    ----------
    
    With the exception of JSONMapper_class, the parameters override anything specified on
    the command line.
    
    socket_address: The unix socket to receive Dnstap telemetry on.
    recipient:      The receiving address or multicast group.
    port:           The receiving port.
    interface:      If recipient is a multicast group then this is the address bound to the
                    interface to send the datagram on.
    """
    if not socket_address:
        if len(sys.argv) < 2:
            lart()
        socket_address = sys.argv[1]

    if len(sys.argv) > 2:
        destination = sys.argv[2]
    else:
        destination = None
    if recipient and port:
        destination = '{}:{}'.format(recipient, port)

    if not interface and len(sys.argv) == 4:
        interface = sys.argv[3]
        
    try:
        if destination:
            recip_addr = ip_address(destination.split(':',1)[0])
            if recip_addr.is_multicast:
                if not interface:
                    print('interface required for multicast', file=sys.stderr)
                    lart()
            else:
                if interface:
                    print('interface invalid for unicast', file=sys.stderr)
                    lart()
    except Exception as e:
        print('{}\n'.format(e), file=sys.stderr)
        lart()
        
    if interface:
        try:
            ignore = ip_address(interface)
        except Exception:
            print('specify interface using a bound address', file=sys.stderr)
            lart()
            
    if DNSTAP_CHANNEL:
        try:
            param = 'recipient'
            recip_addr = ip_address( DNSTAP_CHANNEL.get( 'recipient' ) )
            if recip_addr.is_multicast:
                if not interface:
                    print('interface required for multicast', file=sys.stderr)
                    lart()
            else:
                if interface:
                    print('interface invalid for unicast', file=sys.stderr)
                    lart()
            param = 'port'
            port = DNSTAP_CHANNEL.get( 'port' )
            if port < 1 or port > 65535:
                print('DNSTAP_CHANNEL: invalid port number')
                lart()
            raw_destination = '{}:{}'.format(recip_addr, port)
            param = 'send_interface'
            raw_interface = DNSTAP_CHANNEL.get( 'send_interface' )
            if raw_interface:
                ignore = ip_address(raw_interface)
        except Exception as e:
            if param == 'send_interface':
                print('DNSTAP_CHANNEL: specify interface using a bound address', file=sys.stderr)
            else:
                print('DNSTAP_CHANNEL {}: {}\n'.format(param, e), file=sys.stderr)
            lart()
    else:
        raw_destination = raw_interface = None
    
    if len(sys.argv) > 4:
        lart()
    
    logging.info('{} starting. Socket: {}  Destination: {}'.format(
            path.basename(sys.argv[0]).split('.')[0], 
            socket_address, 
            destination or 'STDOUT'
        )       )
    if DNSTAP_CHANNEL:
        logging.info('    DNSTAP_CHANNEL: {}  {} {}'.format(raw_destination, raw_interface and 'Interface:' or '', raw_interface or ''))

    main_args = (socket_address, destination, interface, JSONMapper_class, raw_destination, raw_interface)
    if PYTHON_IS_311:
        asyncio.run(main_311(*main_args))
    else:
        main_36(*main_args)
    
    return

main = copyright_2026_fred_morris_consulting_tacoma_wa_usa
if __name__ == '__main__':
    copyright_2026_fred_morris_consulting_tacoma_wa_usa()

