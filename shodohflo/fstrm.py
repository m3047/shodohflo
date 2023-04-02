#!/usr/bin/python3
# Copyright (c) 2019-2022 by Fred Morris Tacoma WA
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

"""Pure Python Frame Streams implementation.

Frame Streams are a lightweight data transport protocol developed by Farsight
Security. See the documentation here:

    https://farsightsec.github.io/fstrm/index.html


BACKWARDS INCOMPATIBLE CHANGES TO Server FOR Python 3.11
-------------------------------------------------

Key takeaways:

* PYTHON_IS_311 is a boolean which indicates whether or not the module is
  operating in 3.11 mode
  
* Server.listen_asyncio() is now a coroutine.

For continued use with earlier versions of Python:

* Server.run_forever() has been replaced by Server.run_36()

* Server.run_forever() now incorporates some logic which was previously
  in Server.listen_asyncio()
  
* You should call loop.close() yourself in the context which Server()
  was created in.
  
See shodohflo/examples/dnstap2json.py as a reference example.


Structure of a Frame
--------------------

A frame starts with a 4 byte payload length field. If this field has a nonzero
value then what follows is a data record.

If the payload length is zero, then the frame is deemed a _control frame_. In
a control frame the (zero) payload length field is followed by:

* control frame length field (also 4 bytes)
* control frame type specifier (4 bytes)
* field type specifier (4 bytes)
* field length (4 bytes)
* data

There is only one field type defined, which is a content type represented as an
arbitrary string.


The Handshake
-------------

When a server accepts a connection, the client initiates the stream.

<- server  -> client

* <- `READY` a control frame specifying the content type which will be sent.
* -> `ACCEPT` a control frame specifying what the server accepts (should be
the same).
* <- `START` a control frame again specifying the content type, and declaring
that the client will begin sending data.

Data frames are then sent for an indeterminate period of time.

* <- STOP when a client is done it sends this control frame


The PRINT_ Constants
--------------------

The PRINT_... constants control various debugging output. They can be
set to a print function which accepts a string, for example:

    PRINT_THIS = logging.debug
    PRINT_THAT = print
"""

import sysconfig

PYTHON_IS_311 = int( sysconfig.get_python_version().split('.')[1] ) >= 11

import os
import socket
import asyncio

if PYTHON_IS_311:
    from asyncio import CancelledError
else:
    from concurrent.futures import CancelledError

FSTRM_CONTROL_ACCEPT = 1
FSTRM_CONTROL_START = 2
FSTRM_CONTROL_STOP = 3
FSTRM_CONTROL_READY = 4
FSTRM_CONTROL_FINISH = 5
FSTRM_DATA_FRAME = 99

FSTRM_CONTROL_FIELD_CONTENT_TYPE = 1

# Start/end of coroutines.
PRINT_COROUTINE_ENTRY_EXIT = None

class FieldTypeMismatchError(TypeError):
    pass

class ContentTypeMismatchError(TypeError):
    pass

class BadControlTypeError(TypeError):
    pass

class FieldSizeError(IndexError):
    pass

class StreamingSocket(object):
    """A stream provider."""
    
    def get_socket(self):
        """Return a bound socket.
        
        Each time this is called it should return a new socket.
        """
        pass
    
class UnixSocket(StreamingSocket):
    """A Unix Domain socket.
    
    For use with Server.listen().
    """
    
    def __init__(self, path):
        """Initialize
        
        path: the filesystem path to where the socket should be created.
        """
        self.path = path
        return
    
    def clean_path(self):
        try:
            os.unlink(self.path)
        except OSError:
            if os.path.exists(self.path):
                raise
    
    def get_socket(self):
        self.clean_path()

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(self.path)
        
        return sock

class AsyncUnixSocket(UnixSocket):
    """An asyncio Unix Domain server.
    
    For use with Server.listen_asyncio().
    """
    
    def get_socket(self, callback, loop):
        self.clean_path()

        return loop.create_task(
                   asyncio.start_unix_server(callback, self.path)
            )

class Consumer(object):
    """A data consumer."""
    
    def accepted(self,data_type):
        """Called when a connection is accepted.
        
        data_type: the data type string from content negotiation.
        
        Should return True.
        
        Technically speaking this is called when the START control frame is seen.
        """
        return True
    
    def consume(self,frame):
        """Called with a frame of data.
        
        This should be subclassed by your consumer and should return True
        """
        pass
    
    def finished(self,partial_frame):
        """Called when a connection is terminated.
        
        partial_frame: If there was data remaining in the buffer then it is
                pass to the method.
        """
        return

UNSIGNED_BIG_ENDIAN = dict(byteorder='big', signed=False)

class DataProcessor(object):
    """A stream data processor.
    
    Each connection gets its own instance, as it manages buffering and frame
    reassembly for the stream.
    """
    def __init__(self, data_type):
        self.buffer = bytes()
        self.receiving_data = True
        self.running = True
        self.data_type = data_type
        self.data_length = None
        self.control_length = None
        self.tasks = set()
        return
    
    def append(self, data):
        self.buffer += data
        return

    def connection_done(self, consumer):
        """Called to perform internal cleanup when a connection closes."""
        if self.receiving_data:
            consumer.finished(self.buffer)
        self.receiving_data = False
        self.buffer = bytes()
        return
    
    def read_size(self):
        """Returns how many bytes we need to read.
        
        This is predicated on reading enough of the packet that we know how much
        more we need to read to get the whole thing.
        """
        if self.data_length is None:
            return 8 - len(self.buffer)
        if self.data_length:
            return self.data_length - len(self.buffer)        # control length is really part of the data.
        if self.control_length is None:
            return 4 - len(self.buffer)
        return self.control_length - len(self.buffer)
    
    def frame_ready(self):
        """Is a complete frame ready in the buffer?"""
        
        if not self.running:
            return True

        buffered = self.buffer
        
        if self.data_length is None:

            # At least four bytes for the payload length?
            if len(buffered) < 4:
                return False
            
            self.data_length = int.from_bytes(buffered[:4], **UNSIGNED_BIG_ENDIAN)
            buffered = buffered[4:]
            
        # Length is zero, this is a control frame.
        if self.data_length == 0:

            if self.control_length is None:
                # Has to have at least 4 bytes for the length.
                if len(buffered) < 4:
                    self.buffer = buffered
                    return False

                self.control_length = int.from_bytes(buffered[:4], **UNSIGNED_BIG_ENDIAN)
                buffered = buffered[4:]

            # Have we got at least that much in the buffer?
            if len(buffered) < self.control_length:
                self.buffer = buffered
                return False
            
            self.is_control_frame = True
            self.frame = buffered[:self.control_length]
            self.buffer = buffered[self.control_length:]
            self.data_length = None
            self.control_length = None
            return True
        
        # Otherwise it is data.
        if len(buffered) < self.data_length:
            self.buffer = buffered
            return False
        
        self.is_control_frame = False
        self.frame = buffered[:self.data_length]
        self.buffer = buffered[self.data_length:]
        self.data_length = None
        self.control_length = None
        return True
    
    def content_type_payload(self, frame):
        
        field_type = int.from_bytes(frame[:4], **UNSIGNED_BIG_ENDIAN)
        frame = frame[4:]
        
        if field_type != FSTRM_CONTROL_FIELD_CONTENT_TYPE:
            raise FieldTypeMismatchError(
                'Expected Content Type field (id {})'.format(FSTRM_CONTROL_FIELD_CONTENT_TYPE))

        field_length = int.from_bytes(frame[:4], **UNSIGNED_BIG_ENDIAN)
        frame = frame[4:]
        
        if field_length > len(frame):
            raise FieldSizeError(
                'Content Type field was expected to be {} bytes'.format(field_length))
        
        content_type = frame[:field_length].decode()
        
        if   self.data_type is None:
            self.data_type = content_type
        elif content_type != self.data_type:
            raise ContentTypeMismatchError(
                'Expected: {}   Received: {}'.format(self.data_type, content_type))
            
        return
    
    async def schedule_consumer(self, consumer, frame, promise):
        """Wrapper for Consumer.consume()."""
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("START schedule_consumer")

        if not consumer.consume(frame):
            self.running = False
            self.tasks.remove(promise[0])
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("END schedule_consumer")
        return
    
    def process_frame(self, conn, consumer, loop=None):
        """Process a frame of data."""
        if not self.running:
            return False
        
        if not self.is_control_frame:
            if loop:
                promise = []
                task = loop.create_task(self.schedule_consumer(consumer, self.frame, promise))
                promise.append(task)
                self.tasks.add(task)
                return FSTRM_DATA_FRAME
            else:
                return consumer.consume(self.frame) and FSTRM_DATA_FRAME or False
        
        control_type = int.from_bytes(self.frame[:4], **UNSIGNED_BIG_ENDIAN)
        frame = self.frame[4:]

        # If READY then send ACCEPT...
        if control_type == FSTRM_CONTROL_READY:
            
            self.content_type_payload(frame)
            
            field_bytes = self.data_type.encode()
            field_length = len(field_bytes)
            
            payload = b''.join((
                    (0).to_bytes(4, **UNSIGNED_BIG_ENDIAN),
                    (field_length + 12).to_bytes(4, **UNSIGNED_BIG_ENDIAN),
                    FSTRM_CONTROL_ACCEPT.to_bytes(4, **UNSIGNED_BIG_ENDIAN),
                    FSTRM_CONTROL_FIELD_CONTENT_TYPE.to_bytes(4, **UNSIGNED_BIG_ENDIAN),
                    field_length.to_bytes(4, **UNSIGNED_BIG_ENDIAN),
                    field_bytes
                ))

            if loop:
                conn.write(payload)
                # To get around restrictions in the python implementation of asyncio
                # which require any method calling await to have been declared async.
                # Part 1 of 2...
                #await conn.drain()
            else:
                conn.sendall(payload)
        
            return control_type
        
        # If START then let the consumer know...
        if control_type == FSTRM_CONTROL_START:
            
            self.content_type_payload(frame)
            
            return consumer.accepted(self.data_type) and control_type or False
        
        # if STOP then stop...
        if control_type == FSTRM_CONTROL_STOP:
            
            return False
        
        raise BadControlTypeError('Control type: {}'.format(control_type))

class Server(object):
    """A Frame Stream server.
    
    Supports regular, synchronous socket connections as well as asyncio.
    
        Synchronous:  Use UnixSocket + Server.listen()
        Asyncrhonous: Use AsyncUnixSocket + Server.listen_asyncio()
    """
    
    def __init__(self,stream,consumer,loop=None,data_type=None):
        """Initialize the server.
        
        stream: a StreamingSocket
        consumer: Consumer which will be called with the contents of each data frame.
        loop: if loop is supplied, then an asyncio server is created.
        data_type: type of payload. If not supplied, then whatever the client
                advertises is sent back as acceptable.
        """
        if loop:
            # NOTE: Bad data hiding here, the server is finalized when listen_asyncio()
            #       is called. This allows __init__() not to be awaited.
            self.server = stream.get_socket(self.process_data, loop)
            self.processors = set()
        else:
            self.sock = stream.get_socket()
        self.loop = loop
        self.consumer = consumer
        self.data_type = data_type
        return
        
    def listen(self):
        """Starts listening on the socket."""
        self.sock.listen(1)
        try:
            while True:
                conn, client = self.sock.accept()
                processor = DataProcessor(self.data_type)
                active = True
                while active:
                    while not processor.frame_ready():
                        data = conn.recv(processor.read_size())        # type(data) == bytes
                        if not data:
                            processor.connection_done(self.consumer)
                            active = False
                            break
                        processor.append(data)
                    if active and not processor.process_frame(conn, self.consumer):
                        processor.connection_done(self.consumer)
                        active = False
                        break
                conn.close()
        except KeyboardInterrupt:
            pass
        return
            
    async def process_data(self, reader, writer):
        """Logically speaking part of listen_asyncio().
        
        This is the callback when a connection is established.
        """
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("START process_data")
        processor = DataProcessor(self.data_type)
        self.processors.add(processor)
        active = True
        while active:
            try:
                while not processor.frame_ready():
                    data = await reader.read(processor.read_size())
                    if not data:
                        processor.connection_done(self.consumer)
                        active = False
                        break
                    processor.append(data)
                if not active:
                    break
                status = processor.process_frame(writer, self.consumer, loop=self.loop)
                if not status:
                    processor.connection_done(self.consumer)
                    active = False
                    break
                elif status == FSTRM_CONTROL_READY:
                    # To get around restrictions in the python implementation of asyncio
                    # which require any method calling await to have been declared async.
                    # Part 2 of 2...
                    await writer.drain()
            except (KeyboardInterrupt, CancelledError):
                # This is usually a CancelledError caused by the KeyboardInterrupt,
                # not the actual KeyboardInterrupt.
                active = False

        writer.close()
        self.processors.remove(processor)
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT("END process_data")        
        return
    
    def run_forever(self):
        """This is deprecated. See the pydoc header for further information."""
        raise RuntimeError('Server.run_forever() has been removed. See pydoc3 shodohflo.fstrm')
        
    async def run_36(self):
        """Called internally by listen_asyncio() to process the stream.
        
        Does what run_forever() previously did, as well as some of what
        listen_asyncio() did. You now need to call loop.close() yourself
        in the context in which Server() was created.
        """

        #self.loop.run_forever()

        # Without callbacks or context where Future.set_result() is invoked this future
        # waits for cancellation and (re)raises CancelledError.
        await self.loop.create_future()

        return
    
    async def run_311(self):
        """Called internally by listen_asyncio() to process the stream.
        
        Waits on the Server.server instance. All other cleanup is performed
        by the (presumed) enclosing call to asyncio.run().
        """
        async with self.server as server:
            await server.serve_forever()
             
        return
    
    async def listen_asyncio(self):
        """Listens using asyncio.
        
        BREAKING CHANGE FOR Python 3.11 compatibility
        ---------------------------------------------
        
        This routine is now a coroutine. See the pydoc header for the file for further info.
        """
        # NOTE: First thing, realize the server from the Future created during __init__().
        self.server = await self.server
        
        if PYTHON_IS_311:
            await self.run_311()
        else:
            await self.run_36()

        return
        