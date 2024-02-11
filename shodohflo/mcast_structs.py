#!/usr/bin/python3
# (c) 2024 Fred Morris Consulting, Tacoma WA 98445
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

"""Linux compatible structure definitions pertinent to Multicast."""

from .c_struct import Element, String, Array, Struct, Instance

# These work like typedefs.
u8  = Element('u8')
u16 = Element('u16')
s32 = Element('s32')
u32 = Element('u32')

# bits/sockaddr.h
SOCKADDR_COMMON = Struct(
        Element('u16    family')
    )

sockaddr = Struct(
        Instance(SOCKADDR_COMMON,   'common'),
        String( 14,                 'sa_data')
    )

# netinet/in.h
in_addr = Struct(
        String(  4,     's_addr')
    )
in6_addr = Struct(
        String( 16,     'addr8')
    )

in_port_t = u16

sockaddr_in = Struct(
        Instance(SOCKADDR_COMMON,   'common'),
        Instance(in_port_t,         'sin_port'),
        Instance(in_addr,           'sin_addr'),
        # Total of 16 bytes
        String(  8,                 'padding')
    )

sockaddr_in6 = Struct(
        Instance(SOCKADDR_COMMON,   'common'),
        Instance(in_port_t,         'sin6_port'),
        Element('u32                 sin6_flowcontrol'),
        Instance(in6_addr,          'sin6_addr'),
        Element('u32                 sin6_scope_id')
    )

ip_mreq = Struct(
        Instance(in_addr,           'imr_multiaddr'),
        Instance(in_addr,           'imr_interface')
    )

ipv6_mreq = Struct(
        Instance(in6_addr,          'ipv6mr_multiaddr'),
        Element('s32                 ipv6mr_interface')
    )

