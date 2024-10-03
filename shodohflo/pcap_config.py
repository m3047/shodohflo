#!/usr/bin/python3
# Copyright (c) 2024 by Fred Morris Tacoma WA
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

"""Packet Capture Agent Configuration.

This comprises the Domain Specific Language (DSL) for configuring agents/pcap_agent.py.

This is in two parts:

  * The network enumeration, which defines the networks of interest (or disinterest).

  * The mapping enumeration, which maps source and destination addresses and ports (flows)
    based on the source and destination networks.
    
We are concerned here with what gets written to Redis keys with this format:

  <client-address>;<service-address>;<port-of-interest>;flow
  
In particular the client-address, service-address, and port-of-interest.

There are defaults for NETWORK_ENUMERATION and FLOW_MAPPING. They attempt to
map all flows using LowerPort. In combination with our-nets (specified on the command
line) this represents a modest improvement in accuracy over the legacy behavior.

SOURCE (SRC) and DESTINATION (DST)
----------------------------------

SRC and DST represent the UDP or TCP packet source and destination address and / or port.

When you are declaring a MappingAction you will need to potentially specify a client-address
and / or a port-of-interest. The service-address is implicitly determined to be what the
client-address is not. If the client-address is SRC then the service-address is DST and
vice-versa.

The port identifies a service. There is a port associated with both the source and destination
address in the packet. Only the one port identified with the service is included in the
Redis key.
"""

from ipaddress import ip_network, IPv4Network, IPv6Network

SOURCE = SRC = 'src'
DESTINATION = DST = 'dst'

SOURCE_AND_DESTINATION = { SOURCE, DESTINATION }

class ChangeableMixin(object):
    """Magic smoke which makes it possible to mutate IPv*Network objects.
    
    This is all kinds of dangerous, but we endeavor to make the change
    before the value is ever retrieved.
    """
    def change(self, new_value):
        """Change the value of an IPv*Network object in-place.
        
        new_value is a network of the same base class that you want to copy
        the value from.
        """
        self.network_address = new_value.network_address
        self.netmask = new_value.netmask
        self._prefixlen = new_value._prefixlen
        return
    
class ChangeableIPv4Network( IPv4Network, ChangeableMixin ):
    """You can change the value of this IPv4Network in-place!"""
    pass

class ChangeableIPv6Network( IPv6Network, ChangeableMixin ):
    """You can change the value of this IPv6Network in-place!"""
    pass

OUR_4NETS = ChangeableIPv4Network( '127.0.0.0/24' )
OUR_6NETS = ChangeableIPv6Network( 'fc00::/7' )

def update_our_nets(our_nets):
    if isinstance(our_nets, IPv4Network):
        our_nets_instance = 'OUR_4NETS'
    else: # IPv6Network
        our_nets_instance = 'OUR_6NETS'
    globals()[our_nets_instance].change(our_nets)
    return    

class NetworkEnumeration(object):
    """A network enumeration.
    
    You will need one of these in your configuration. Your network enumeration is
    specified as an ordered list to the constructor. Testing stops with the first match,
    so an address can only match a single network. Here is an example:
    
    NETWORK_ENUMERATION = NetworkEnumeration(
            ( 'remote_site',    '10.222.0.0/16', '10.223.221.0/24' ),
            ( 'hangar_42',      '10.0.33.0/24' ),
            ( 'site_net',       '10.0.0.0/16' ),
            ( 'external',       '0.0.0.0/0' )
        )
        
    In this example:
    
      * remote_site is 10.222.0.0/16 and 10.223.221.0/24
      * hanger_42 is 10.0.33.0/24
      * site_net is everything in 10.0.0.0/16 EXCEPT for 10.0.33.0/24
      * external is everything EXCEPT for 10.222.0.0/16, 10.223.221.0/24, and 10.0.0.0/16
      
    You will use the source and destination networks to match MappingActions for
    the FlowMapping.
    
    our-nets: OUR_4NETS and OUR_6NETS
    ---------------------------------
    
    When pcap_agent.py is invoked on the command line it is supplied with the interface
    to listen on and "our-nets". our-nets is utilized to scope ICMP and RST events and in
    conjunction with SUPPRESS_OWN_NETWORK to trivially suppress flows between two addresses
    within our-nets.
    
    OUR_4NETS and OUR_6NETS (one or the other, not both) can be utilized in place of
    a CIDR in the network enumeration as a symbolic reference to the our-nets command line
    argument.    
    
    What happens if my last element isn't a CIDR of 0.0.0.0/0?
    -----------------------------------------------------
    
    That potentially leads to source and destination addresses which cannot be matched.
    Any such packets are dropped.
    """
    def __init__(self, *enumeration):
        """Your enumeration is specified here."""

        # We don't see None (as a network name) here but it occurs during runtime.
        n = 0
        self.network_id = { None: n }
        for net in enumeration:
            if net[0] not in self.network_id:
                n += 1
                self.network_id[net[0]] = n
        
        self.enumeration = [
                ( self.network_id[net[0]],
                  [ isinstance( cidr, (IPv4Network, IPv6Network) )
                    and cidr or ip_network(cidr)
                    for cidr in net[1:]
                  ]
                )
                for net in enumeration
            ]
        return
    
    def network(self, address):
        """Return the network name for the address.
        
        """
        for net in self.enumeration:
            for cidr in net[1]:
                if cidr is None or address in cidr:
                    return net[0]
        return None
    
class MappingAction(object):
    """A potential flow mapping.
    
    When a match occurs no further mappings are tested.
    """
    def match(self, src_addr, src_port, dst_addr, dst_port):
        """This never matches and should be overridden by subclasses.
        
        The parameters are (hopefully) self-explanatory.
        
        src_addr:   an ipaddress.IPv*Address representing the source of the packet
        src_port:   an int representing the source port for the packet
        dst_addr:   an ipaddress.IPv*Address representing the destination of the packet
        dst_port:   an int representing the destination port for the packet
        
        If a match occurs, returns a tuple of (client-address, service-address, port-of-interest).
        
        Some actions offer a "drop" option, in which case a tuple of (None, None, None) is returned
        when a match occurs.
        """
        return None

class PortMatch(MappingAction):
    """A mapping where addresses are determined from ports.
    
    This mapping is bi-directional: either the source port or the destination port
    may match.
    
    If e.g. the source port matches one of the specified ports then the
    service-address is inferred to be the source address associated with that port
    (and the client-address is the other one, the destination).
    """
    def __init__(self, set_of_ports, precedence=SOURCE, drop=False):
        """Parameters:
        
        set_of_ports:   The set of ports to match (required).
        precedence:     If the source and destination ports are the same, this
                        specifies which address should be inferred as the service-
                        address. The client-address is then the other address.
        drop:           Drop the flow without further processing.
        """
        if precedence not in SOURCE_AND_DESTINATION:
            raise ValueError( 'PortMatch: precedence not in "src", "dst".')
        if precedence == SOURCE:
            self.precedence = (0, 2)
        else:
            self.precedence = (2, 0)
        for port in set_of_ports:
            if port < 1 or port > 65535:
                raise ValueError( 'PortMatch: port not in 1..65535.')
        self.set_of_ports = set_of_ports
        self.drop = drop
        return

    def match(self, *args):
        """"""
        for i in range(2):
            if args[self.precedence[i] + 1] in self.set_of_ports:
                if self.drop: return (None, None, None)
                return ( args[ (self.precedence[i] + 2) % 4 ], args[ self.precedence[i] ], args[ self.precedence[i] + 1 ] )
        return None

class Assign(MappingAction):
    """A mapping which explicitly assigns flow source and destination.
    
    This mapping is unidirectional: port_from specifies whether the source port
    or destination port is to be matched. client_from specifies whether the source
    or destination address should be used as the client; the service-address is
    then the other one.
    
    In this mapping if SOURCE is specified as port_from then the source 
    port must match the set of ports (if supplied) and becomes the port-of-interest.
    The client-address and service-address are set as specified above.
    
    """
    def __init__(self, client_from, port_from, set_of_ports=None, drop=False):
        """Parameters:
        
        client_from:    Specifies whether the client-address is SRC or DST.
        port_from:      Specifies whether the port to match is SRC or DST, and
                        becomes the port-of-interest.
        set_of_ports    The set of possible port numbers to be matched (against the
                        port-of-interest). If not specified all ports match.
        drop:           Drop the flow without further processing.
        """
        if client_from not in SOURCE_AND_DESTINATION:
            raise ValueError( 'Assign: client_from not in "src", "dst".')
        if port_from not in SOURCE_AND_DESTINATION:
            raise ValueError( 'Assign: port_from not in "src", "dst".')
        if client_from == SOURCE:
            client_address = 0
            service_address = 2
        else:
            client_address = 2
            service_address = 0
        if port_from == SOURCE:
            port_of_interest = 1
        else:
            port_of_interest = 3
        self.mapping = ( client_address, service_address, port_of_interest )
        if set_of_ports is not None:
            for port in set_of_ports:
                if port < 1 or port > 65535:
                    raise ValueError( 'Assign: port not in 1..65535.')
        self.set_of_ports = set_of_ports
        self.drop = drop
        return
        
    def match(self, *args):
        """"""
        if self.set_of_ports is None or args[ self.mapping[2] ] in self.set_of_ports:
            if self.drop: return (None, None, None)
            return tuple( args[i] for i in self.mapping )
        return None
    
class LowerPort(MappingAction):
    """A mapping action which assigns a flow based on comparing port numbers.

    The source and destination ports are compared. The lower port number, whether
    source or destination determines the client and service addresses as well as
    the port of interest.
    """
    def __init__(self, precedence=SOURCE):
        """Parameters:
        
        precedence: If both ports match, this determines whether the source or
                    destination address should be inferred as the service-address.
                    The client-address is then the other address
        """
        if precedence not in SOURCE_AND_DESTINATION:
            raise ValueError( 'LowerPort: precedence not in "src", "dst".')
        self.precedence = precedence
        return

    def match(self, src_addr, src_port, dst_addr, dst_port):
        """"""
        if   src_port < dst_port:
            return (dst_addr, src_addr, src_port)
        elif dst_port < src_port:
            return (src_addr, dst_addr, dst_port)
        elif self.precedence == SOURCE:
            return (dst_addr, src_addr, src_port)
        else:
            return (src_addr, dst_addr, dst_port)
        
class FlowMapping(object):
    """A mapping enumeration.
    
    You will need one of these in your configuration. Your flow mapping is specified
    as an ordered list to the constructor. Testing stops with the first match, so at most
    one flow key is generated.
    
    Here is an example (using the networks enumerated as the example in NetworkEnumeration):
    
    FLOW_MAPPING = FlowMapping(
            ( 'remote_site', 'site_net',    Assign( SRC, DST ) ),
            ( 'site_net',    'remote_site', Assign( DST, SRC ) ),            
            ( 'remote_site', 'hangar_42',   LowerPort() ),
            ( 'hangar_42',   'remote_site', LowerPort() ),
            ( 'external',     None,         PortMatch({ 25, 53, 80, 443 }) ),
            ( 'external',     None,         Assign( DST, SRC ) ),
            (  None,          None,         LowerPort() )
        )
        
    In this example:
    
      * For traffic between remote_site and site_net the service-address and port-of-interest
        are presumed to always reside in site_net and the client-address is always in remote_site.
      * When remote_site talks to hanger_42 the lower port number determines the client and service
        addresses.
      * For traffic coming from external addresses if the port is one of (25,53,80,443) the
        service-address is the side containing the port-of-interest, and the client-address is the
        other.
      * Otherwise traffic from external is always presumed to represent the service-address speaking
        to the client-address.
      * There is a final catchall where the low port determines the presumptive client and service
        addresses.
        
    In the author's experience (even) this is an overly complicated example. A typical deployment has
    three rules (bearing in mind that only incoming / passively observed traffic is logged):
    
      * A rule for the machine where the agent is running.
      * A rule or two for the network the machine can see.
      * A catchall for everything else.
    """
    def __init__(self, *enumeration):
        self.mapping_enumeration = enumeration
        return
    
    def number_networks(self, network_enumeration):
        """A delayed precompilation step. (fluent)"""
        self.network_enumeration = network_enumeration
        self.mapping_enumeration = [
                [ network_enumeration.network_id[ rule[0] ], network_enumeration.network_id[ rule[1] ], rule[2] ]
                for rule in self.mapping_enumeration
            ]
        return self
    
    def match(self, src_addr, src_port, dst_addr, dst_port):
        src_id, dst_id = ( self.network_enumeration.network( addr ) for addr in (src_addr, dst_addr) )
        if src_id is None or dst_id is None:
            return None
        for rule in self.mapping_enumeration:
            if rule[0] and rule[0] != src_id:
                continue
            if rule[1] and rule[1] != dst_id:
                continue
            result = rule[2].match( src_addr, src_port, dst_addr, dst_port )
            if result is None:
                continue
            if result[0] is None: return None
            return result
        return None
    

