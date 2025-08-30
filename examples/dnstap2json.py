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

"""Dnstap data converted to a (line oriented) JSON stream.

REQUIRES PYTHON 3.6 OR BETTER and uses asyncio.

This program is adapted from agents/dns_agent.py.

Command Line:
------------

    dnstap2json.py <unix-socket> {<dest-host>:port {interface-address}}
    
(Line oriented) JSON is written with each line terminated with '\\n'.

Arguments:

    <unix-socket> is required, and is the unix domain socket location from
        which Dnstap data is being read.
    <dest-host> and <port> are optional (although if supplied both are required)
        and specify the receiving end of the stream of UDP packets. If not supplied,
        the JSON is written to stdout.
    <interface-address> is required if <dest-host> is a multicast address, and is
        the (system-) bound address for the interface to be used to send the datagram.

If you send the traffic via UDP

    ./dnstap2json.py /tmp/dnstap 127.0.0.1:3047

then listening for UDP data can be as simple as

    nc -luk 127.0.0.1 3047
        
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

import sys
from os import path, set_blocking
import logging
import traceback

import asyncio
import socket
from ipaddress import ip_address

import json
from time import time
from collections import deque

import dns.rdatatype as rdatatype
import dns.rcode as rcode

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
STATS = 60

MULTICAST_LOOPBACK = 1
MULTICAST_TTL = 1

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
        qtype = response.question[0].rdtype
        
        # Deal with NXDOMAIN.
        if response.rcode() == rcode.NXDOMAIN:
            return [ [question] ]

        # Build a mapping of the rrsets.
        mapping = { rrset.name.to_text().lower():rrset
                    for rrset in response.answer
                    if rrset.rdtype == rdatatype.CNAME or rrset.rdtype == qtype
                  }
        
        # Follow the question (CNAMEs) to an answer.
        names = [ question ]
        seen = set(names)
        chain = [ [question] ]
        while names:
            name = names.pop(0)
            if name in mapping:
                rr_values = [ rr.to_text().lower() for rr in mapping[name] ]
                rdtype = mapping[name].rdtype
                if rdtype == rdatatype.CNAME:
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
        """Maps all of the fields to their values. (generator function)
        
        The default implementation returns a single value, but being a genfunc
        allows this to be expanded to cases where multiple records are generated
        by a single input record.
        """
        data = {}
        for field in self.FIELDS:
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
        if not self.mapper.filter(message):
            if STATS:
                timer.stop()
            if PRINT_COROUTINE_ENTRY_EXIT:
                PRINT_COROUTINE_ENTRY_EXIT('END consume')
            return True

        for data in self.mapper.map_fields(message):
            # Actually queues a separate coroutine.
            self.writer.write( json.dumps(data) + "\n",
                            STATS and self.backlog.start_timer() or None
                        )
        if STATS:
            timer.stop()
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('END consume')
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
        raise RuntimeError('This should never be raised, as it should never be called.')
        #FstrmServer.run_forever(self)
        #self.writer.close()
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
    except CancelledError:
        pass
    return

def main_36(socket_address, destination, interface, Mapper_Class):
    event_loop = asyncio.get_event_loop()
    statistics = StatisticsFactory()
    writer = UniversalWriter(destination, interface, event_loop)
    if STATS:
        stats_routine = asyncio.run_coroutine_threadsafe(statistics_report(statistics), event_loop)
        statistics.writer_tasks = writer.tasks

    try:
        event_loop.run_until_complete(
            Server( AsyncUnixSocket(socket_address),
                    DnsTap(event_loop, statistics, Mapper_Class(), writer),
                    event_loop, writer=writer
                ).listen_asyncio()
            )
    except KeyboardInterrupt:
        pass

    writer.close()
    event_loop.run_until_complete(
            close_tasks(asyncio.Task.all_tasks(event_loop))
        )
    event_loop.close()
    return

async def main_311(socket_address, destination, interface, Mapper_Class):
    event_loop = asyncio.get_running_loop()
    statistics = StatisticsFactory()
    writer = UniversalWriter(destination, interface, event_loop)
    if STATS:
        stats_routine = event_loop.create_task( statistics_report(statistics) )
        statistics.writer_tasks = writer.tasks
    
    try:
        await Server(
                AsyncUnixSocket(socket_address),
                DnsTap(event_loop, statistics, Mapper_Class(), writer),
                event_loop, writer=writer
            ).listen_asyncio()
    except CancelledError:
        pass
    
    writer.close()
    return

def main(JSONMapper_class=JSONMapper, socket_address=None, recipient=None, port=None, interface=None):
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
    
    if len(sys.argv) > 4:
        lart()
    
    logging.info('{} starting. Socket: {}  Destination: {}'.format(
            path.basename(sys.argv[0]).split('.')[0], 
            socket_address, 
            destination or 'STDOUT'
        )       )

    main_args = (socket_address, destination, interface, JSONMapper_class)
    if PYTHON_IS_311:
        asyncio.run(main_311(*main_args))
    else:
        main_36(*main_args)
    
    return

if __name__ == '__main__':
    main()
    
