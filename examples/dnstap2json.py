#!/usr/bin/python3
# Copyright (c) 2019-2020 by Fred Morris Tacoma WA
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

This program is adapted from agents/dns_agent.py.

Command Line:
------------

    dnstap2json.py <unix-socket> {<dest-host>:port}
    
(Line oriented) JSON is written with each line terminated with '\\n'.

Arguments:

    <unix-socket> is required, and is the unix domain socket location to
        which Dnstap data is being written.
    <dest-host> and <port> are optional (although if supplied both are required)
        and specify the receiving end of the stream of UDP packets. If not supplied,
        the JSON is written to stdout.
        
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

import sys
from os import path, set_blocking
import logging
import traceback

import asyncio
import socket

import json

import dns.rdatatype as rdatatype
import dns.rcode as rcode

sys.path.insert(0,path.dirname(path.dirname(path.abspath(__file__))))

from shodohflo.fstrm import Consumer, AsyncUnixSocket
from shodohflo.fstrm import Server as FstrmServer
import shodohflo.protobuf.dnstap as dnstap
from shodohflo.statistics import StatisticsFactory

logging.basicConfig(level=logging.INFO)

CONTENT_TYPE = 'protobuf:dnstap.Dnstap'

# Start/end of coroutines. You will probably also want to enable it in shodohflo.fstrm.
#PRINT_COROUTINE_ENTRY_EXIT = lambda msg:print(msg,file=sys.stderr,flush=True)
PRINT_COROUTINE_ENTRY_EXIT = None

# Similar to the foregoing, but always set to something valid.
STATISTICS_PRINTER = logging.info
# Do we want stats at all? If so, set it to the number of seconds between reports.
STATS = 60

def hexify(data):
    return ''.join(('{:02x} '.format(b) for b in data))

class FieldMapping(object):
    """Maps a JSON name to its value."""
    def __init__(self, name, extract):
        """Enumerate a mapping.
        
        name:       The name to be given to the JSON element in the toplevel
                    dict.
        extract:    A function taking the packet as an argument and returning the
                    extracted value.
        """
        self.name = name
        self.extract = extract
        return
    
    def __call__(self, mapping, mapper, packet):
        """Maps the extracted value.
        
        Traps and warns on KeyError.
        """
        try:
            mapping[self.name] = self.extract(mapper, packet)
        except KeyError as e:
            logging.warn("Field extraction error for {}: {}".format(self.name, e))
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
    """
    # This should be safely below MTU, with the intent to avoid fragmentation.
    MAX_BLOB = 1024
    MESSAGE_TYPE = dnstap.Message.TYPE_CLIENT_RESPONSE
    ACCEPTED_RECORDS = { rdatatype.A, rdatatype.AAAA }
    FIELDS = (
            FieldMapping( 'client', lambda self,p:str(p.field('query_address')[1]) ),
            FieldMapping( 'qtype',  lambda self,p:rdatatype.to_text(p.field('response_message')[1].question[0].rdtype) ),
            FieldMapping( 'status', lambda self,p:rcode.to_text(p.field('response_message')[1].rcode()) ),
            FieldMapping( 'chain',  lambda self,p:self.build_resolution_chain(p) )
        )
    
    def build_resolution_chain(self, packet):
        """Build the (CNAME) resolution chain with ellipsization.
        
        CNAMEs should only have one RR each, right? CNAME chains should be short, right?
        Yeah. Right. So, each element in the chain is actually a list, and the total
        length of all of the elements in the list of lists cannot exceed MAX_BLOB or we
        start taking chunks out of the middle to make it smaller.
        """
        response = packet.field('response_message')[1]
        question = response.question[0].name.to_text().lower()
        
        # Deal with NXDOMAIN.
        if response.rcode() == rcode.NXDOMAIN:
            return [ [question] ]

        # Build a mapping of the rrsets.
        mapping = { rrset.name.to_text().lower():rrset for rrset in response.answer }
        
        # Follow the question (CNAMEs) to an answer.
        names = [ question ]
        seen = set(names)
        chain = [ [question] ]
        while names:
            name = names.pop(0)
            if name in mapping:
                rr_values = [ rr.to_text().lower() for rr in mapping[name] ]
                if mapping[name].rdtype == rdatatype.CNAME:
                    for rr in rr_values:
                        if rr in seen:
                            continue
                        names.append(rr)
                        seen.add(rr)
                chain.append( rr_values )
        
        # Ellipsize if it exceeds MAX_BLOB.
        lengths = [ sum((len(name) for name in e)) for e in chain ]
        if sum(lengths) > self.MAX_BLOB:
            logging.warn('Resolution chain for {} exceeds {}, ellipsizing.'.format(question, self.MAX_BLOB))
            shortened = None
            while sum(lengths) > self.MAX_BLOB:
                if len(lengths) < 3:
                    break
                shortened = int(len(lengths) / 2)
                del lengths[shortened]
                del chain[shortened]
            if shortened:
                chain.insert(shortened, ['(...)'])
            
        return chain

    def filter(self, packet):
        """Return True if the packet should be processed further."""
        if packet.field('type')[1] != self.MESSAGE_TYPE:
            if self.performance_hint:
                logging.warn('PERFORMANCE HINT: Change your Dnstap config to restrict it to client response only.')
                self.performance_hint = False
            return False
        if packet.field('response_message')[1].question[0].rdtype not in self.ACCEPTED_RECORDS:
            return False
        return True
    
    def map_fields(self, packet):
        """Maps all of the fields to their values."""
        data = {}
        for field in self.FIELDS:
            field(data, self, packet)
        return data

class UniversalWriter(object):
    """Plastering over the differences between file descriptors and network sockets."""
    
    FAKE_STDOUT_TIMEOUT = 0
    
    def __init__(self, destination, event_loop):
        """If destination is supplied then this is a UDP socket, otherwise STDOUT."""
        self.destination = destination
        if destination is not None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM|socket.SOCK_NONBLOCK)
            host, port = destination.split(':',1)
            self.sock.connect((host,int(port)))
        else:
            self.fd = sys.stdout
            set_blocking(self.fd.fileno(), False)
        self.loop = event_loop
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
        
    async def write(self, msg, backlog_timer):
        """Called to queue something to be output."""
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("START write")
        await self.loop.sock_sendall(self, self.encode_data(msg))
        if backlog_timer:
            backlog_timer.stop()
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("END write")
        return
        
class DnsTap(Consumer):
    
    def __init__(self, event_loop, statistics, mapper, writer):
        """Dnstap consumer."""
        self.loop = event_loop
        self.mapper = mapper
        self.writer = writer
        if STATS:
            self.consume_stats = statistics.Collector("consume")
            self.backlog = statistics.Collector("output_backlog")
        return

    def accepted(self, data_type):
        logging.info('Accepting: {}'.format(data_type))
        if data_type != CONTENT_TYPE:
            logging.warn('Unexpected content type "{}", continuing...'.format(data_type))
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
        if STATS:
            timer = self.consume_stats.start_timer()

        message = dnstap.Dnstap(frame).field('message')[1]
        if not self.mapper.filter(message):
            if STATS:
                timer.stop()
            return True

        data = self.mapper.map_fields(message)
        self.loop.create_task(self.writer.write(json.dumps(data) + "\n",
                                                STATS and self.backlog.start_timer() or None
                             )                 )
        if STATS:
            timer.stop()
        return True
    
    def finished(self, partial_frame):
        logging.warn('Finished. Partial data: "{}"'.format(hexify(partial_frame)))
        return
    
class Server(FstrmServer):
    """Overrides shodohflo.fstrm.Server."""
    
    def __init__(self,stream,consumer,loop=None,data_type=None, writer=None, recv_size=None):
        FstrmServer.__init__(self, stream, consumer, loop, data_type)
        self.writer = writer
        return
    
    def run_forever(self):
        """Close the writer after exiting the loop."""
        FstrmServer.run_forever(self)
        self.writer.close()
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
    return

def main(JSONMapper_class=JSONMapper):
    """Hi, thanks for reading this!
    
    You can subclass JSONMapper to alter the records which get selected as well as
    the JSON which is output.
    """
    socket_address = sys.argv[1]
    destination = len(sys.argv) > 2 and sys.argv[2] or None
    logging.info('dnstap2json starting. Socket: {}  Destination: {}'.format(socket_address, destination or 'STDOUT'))
    event_loop = asyncio.get_event_loop()
    statistics = StatisticsFactory()
    if STATS:
        asyncio.run_coroutine_threadsafe(statistics_report(statistics), event_loop)
    writer = UniversalWriter(destination, event_loop)
    Server(AsyncUnixSocket(socket_address),
           DnsTap(event_loop, statistics, JSONMapper_class(), writer),
           event_loop, writer=writer
          ).listen_asyncio()

if __name__ == '__main__':
    main()
    
