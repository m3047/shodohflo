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

"""Pure Python Frame Streams implementation.

Frame Streams are a lightweight data transport protocol developed by Farsight
Security. See the documentation here:

    https://farsightsec.github.io/fstrm/index.html

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
"""

import os
import socket

FSTRM_CONTROL_ACCEPT = 1
FSTRM_CONTROL_START = 2
FSTRM_CONTROL_STOP = 3
FSTRM_CONTROL_READY = 4
FSTRM_CONTROL_FINISH = 5

FSTRM_CONTROL_FIELD_CONTENT_TYPE = 1

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
    """A Unix Domain socket."""
    
    def __init__(self, path):
        """Initialize
        
        path: the filesystem path to where the socket should be created.
        """
        self.path = path
        return
    
    def get_socket(self):
        try:
            os.unlink(self.path)
        except OSError:
            if os.path.exists(self.path):
                raise

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(self.path)
        
        return sock

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

class Server(object):
    """A Frame Stream server."""
    
    def __init__(self,stream,consumer,data_type=None,recv_size=1024):
        """Initialize the server.
        
        stream: a StreamingSocket
        consumer: a function which will be called with the contents of each data frame.
        data_type: type of payload. If not supplied, then whatever the client
                advertises is sent back as acceptable.
        recv_size: maximum number of bytes to accept in a single chunk.
        """
        self.sock = stream.get_socket()
        self.consumer = consumer
        self.data_type = data_type
        self.recv_size = recv_size
        self.receiving_data = False
        self.buffer = bytes()
        return
    
    def connection_done(self):
        """Called to perform internal cleanup when a connection closes."""
        if self.receiving_data:
            self.consumer.finished(self.buffer)
        self.receiving_data = False
        self.buffer = bytes()
        return
    
    def frame_ready(self):
        """Is a complete frame ready in the buffer?"""
        buffered = self.buffer

        # At least four bytes for the payload length?
        if len(buffered) < 4:
            return False
        
        payload_length = int.from_bytes(buffered[:4], **UNSIGNED_BIG_ENDIAN)
        buffered = buffered[4:]
        
        # Length is zero, this is a control frame.
        if payload_length == 0:
            
            # Has to have at least 8 bytes for the length and type.
            if len(buffered) < 8:
                return False

            payload_length = int.from_bytes(buffered[:4], **UNSIGNED_BIG_ENDIAN)
            buffered = buffered[4:]

            # Have we got at least that much in the buffer?
            if len(buffered) < payload_length:
                return False
            
            self.is_control_frame = True
            self.frame = buffered[:payload_length]
            self.buffer = buffered[payload_length:]
        
            return True
        
        # Otherwise it is data.
        if len(buffered) < payload_length:
            return False
        
        self.is_control_frame = False
        self.frame = buffered[:payload_length]
        self.buffer = buffered[payload_length:]
    
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
    
    def process_frame(self, conn):
        """Process a frame of data."""
        
        if not self.is_control_frame:
            return self.consumer.consume(self.frame)
        
        control_type = int.from_bytes(self.frame[:4], **UNSIGNED_BIG_ENDIAN)
        frame = self.frame[4:]

        # If READY then send ACCEPT...
        if control_type == FSTRM_CONTROL_READY:
            
            self.content_type_payload(frame)
            
            field_bytes = self.data_type.encode()
            field_length = len(field_bytes)
            
            conn.sendall(
                    (0).to_bytes(4, **UNSIGNED_BIG_ENDIAN) +
                    (field_length + 12).to_bytes(4, **UNSIGNED_BIG_ENDIAN) +
                    FSTRM_CONTROL_ACCEPT.to_bytes(4, **UNSIGNED_BIG_ENDIAN) +
                    FSTRM_CONTROL_FIELD_CONTENT_TYPE.to_bytes(4, **UNSIGNED_BIG_ENDIAN) +
                    field_length.to_bytes(4, **UNSIGNED_BIG_ENDIAN) +
                    field_bytes
                )
        
            return True
        
        # If START then let the consumer know...
        if control_type == FSTRM_CONTROL_START:
            
            self.content_type_payload(frame)
            
            return self.consumer.accepted(self.data_type)
        
        # if STOP then stop...
        if control_type == FSTRM_CONTROL_STOP:
            
            return False
        
        raise BadControlTypeError('Control type: {}'.format(control_type))
    
    def listen(self):
        """Starts listening on the socket."""
        self.sock.listen(1)
        while True:
            conn, client = self.sock.accept()
            active = True
            while active:
                data = conn.recv(self.recv_size)        # type(data) == bytes
                if not data:
                    self.connection_done()
                    break
                self.buffer += data
                while self.frame_ready():
                    if not self.process_frame(conn):
                        self.connection_done()
                        active = False
                        break
            conn.close()


