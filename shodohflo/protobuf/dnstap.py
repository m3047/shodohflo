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

import ipaddress

import dns.message
import dns.rcode

from .protobuf import PbAnyField, PbBytesField, PbFixed32Field, PbInt32Field, PbUInt32Field, \
                      PbInt64Field, PbUInt64Field, Protobuf

class StringField(PbBytesField):
    def i2h(self,pkt,x):
        return repr(x)[1:]

class EnumField(PbUInt32Field):
    """Enums are one-based."""
    def __init__(self,name,default=None,id=None,multi=False,enum=[]):
        PbUInt32Field.__init__(self,name,default,id,multi)
        self.pb_ord2name = enum
        self.pb_name2ord = { enum[i]:i+1 for i in range(len(enum)) }
        return
    
    def i2h(self,pkt,x):
        return self.pb_ord2name[x-1]

class IpAddressField(PbBytesField):
    # TODO: Is intended to work with both IP4 and IP6, but not tested with IP6.
    def m2i(self,pkt,s):
        if len(s) == 4:
            return ipaddress.IPv4Address(s)
        else:
            return ipaddress.IPv6Address(s)
    
    def i2h(self,pkt,x):
        return str(x)

class DnsMessageField(PbBytesField):
    def m2i(self,pkt,s):
        return dns.message.from_wire(s)
    
    @staticmethod
    def answer(msg):
        """Return the answer to the question."""
        name = msg.question[0].name
        for rrset in msg.answer:
            if rrset.name == name:
                return rrset
        return ''
    
    def i2h(self,pkt,x):
        return '< status={} question=<{}> answer=<{}> |>'.format(
                    dns.rcode.to_text(x.rcode()), x.question[0], self.answer(x) )

class Message(Protobuf):

    SOCKET_FAMILY_INET = 1
    SOCKET_FAMILY_INET6 = 2
    
    SOCKET_PROTOCOL_UDP = 1
    SOCKET_PROTOCOL_TCP = 2
    
    TYPE_AUTH_QUERY = 1
    TYPE_AUTH_RESPONSE = 2
    TYPE_RESOLVER_QUERY = 3
    TYPE_RESOLVER_RESPONSE = 4
    TYPE_CLIENT_QUERY = 5
    TYPE_CLIENT_RESPONSE = 6
    TYPE_FORWARDER_QUERY = 7
    TYPE_FORWARDER_RESPONSE = 8
    TYPE_STUB_QUERY = 9
    TYPE_STUB_RESPONSE = 10
    TYPE_TOOL_QUERY = 11
    TYPE_TOOL_RESPONSE = 12
    
    fields_desc = [
            EnumField("type", id=1,
                      enum=[    'TYPE_AUTH_QUERY',
                                'TYPE_AUTH_RESPONSE',
                                'TYPE_RESOLVER_QUERY',
                                'TYPE_RESOLVER_RESPONSE',
                                'TYPE_CLIENT_QUERY',
                                'TYPE_CLIENT_RESPONSE',
                                'TYPE_FORWARDER_QUERY',
                                'TYPE_FORWARDER_RESPONSE',
                                'TYPE_STUB_QUERY',
                                'TYPE_STUB_RESPONSE',
                                'TYPE_TOOL_QUERY',
                                'TYPE_TOOL_RESPONSE'
                           ]
                     ),
            EnumField("socket_family", id=2, enum=['SOCKET_FAMILY_INET','SOCKET_FAMILY_INET6']),
            EnumField("socket_protocol", id=3, enum=['SOCKET_PROTOCOL_UDP','SOCKET_PROTOCOL_TCP']),
            IpAddressField("query_address", id=4),
            IpAddressField("response_address", id=5),
            PbUInt32Field("query_port", id=6),
            PbUInt32Field("response_port", id=7),
            PbUInt64Field("query_time_sec", id=8),
            PbFixed32Field("query_time_nsec", id=9),
            DnsMessageField("query_message", id=10),
            PbAnyField("query_zone", id=11),
            PbUInt64Field("response_time_sec", id=12),
            PbFixed32Field("response_time_nsec", id=13),
            DnsMessageField("response_message", id=14)
        ]

class Dnstap(Protobuf):
    
    TYPE_MESSAGE = 1
    
    fields_desc = [
            StringField("identity", id=1),
            StringField("version", id=2),
            PbAnyField("extra", id=3),
            EnumField("type", id=15, enum=['TYPE_MESSAGE']),
            Message.Field("message", id=14)
        ]
    