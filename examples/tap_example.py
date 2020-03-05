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

"""A sample program for the adventurously inclined.

This program is intended to read the Unix Domain socket written to by BIND.
You should ensure that SOCKET_ADDRESS points to the place where BIND is
configured to find it.

You can simply run it, or you can use it by:

    cd <this directory>
    python3
    >>> from tap_example import Server, UnixSocket, SOCKET_ADDRESS, DnsTap
    >>> tap = DnsTap()
    >>> server = Server(UnixSocket(SOCKET_ADDRESS), tap)
    >>> server.listen()
    ...
    ^C
    KeyboardInterrupt
    >>> server.sock.close()
    >>> tap.protobuf.field('message')[1].field('query_address')
    (Protobuf field: <class 'shodohflo.protobuf.dnstap.IpAddressField'>, IPv4Address('127.0.0.1'))

"""

import sys
from os import path

sys.path.insert(0,path.dirname(path.dirname(path.abspath(__file__))))

from shodohflo.fstrm import Consumer, Server, UnixSocket
import shodohflo.protobuf.dnstap as dnstap

if __name__ == "__main__":
    from configuration import SOCKET_ADDRESS
else:
    SOCKET_ADDRESS = '/tmp/dnstap'
    
CONTENT_TYPE = 'protobuf:dnstap.Dnstap'

def hexify(data):
    return ''.join(('{:02x} '.format(b) for b in data))

class DnsTap(Consumer):
    def accepted(self, data_type):
        print('Accepting: {}'.format(data_type))
        return True
    
    def consume(self, frame):
        """Where it all happens.
        
        One debugging trick is to set the return value to False, which will exit
        The loop. Don't forget to call server.socket.close() and allocate a new
        Server() before calling server.listen() again.
        """
        print('Data:\n{}'.format(hexify(frame)))
        proto_pkt = dnstap.Dnstap(frame,log_wire_type=True)
        print(proto_pkt)
        self.frame = frame
        self.protobuf = proto_pkt
        return True
    
    def finished(self, partial_frame):
        print('Finished. Partial data: "{}"'.format(hexify(partial_frame)))
        return

def main():
    Server(UnixSocket(SOCKET_ADDRESS), DnsTap()).listen()

if __name__ == '__main__':
    main()
    