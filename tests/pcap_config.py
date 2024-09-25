#!/usr/bin/python3
# Copyright (c) 2024 Fred Morris Tacoma WA USA
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

"""Tests for ../shodohflo/pcap_config.py

These are tests for the components of the Domain Specific Language for defining
networks and flow detection heuristics.

IPv4 vs IPv6 test coverage
--------------------------

In general the philosophy is to do relatively complete testing with IPv4 and only
test with IPv6 what might be a variant from the processing observed with IPv4.
"""

import sys

if '..' not in sys.path:
    sys.path.insert(0,'..')

import unittest
from ipaddress import ip_address, ip_network

import shodohflo.pcap_config as pcfg

class TestIPv4NetworkEnumeration(unittest.TestCase):
    """IPv4 Tests"""
    
    @staticmethod
    def EndsWithNone():
        """A network enumeration which ends with None."""
        return pcfg.NetworkEnumeration(
                    ( 'remote_site',    '10.222.0.0/16', '10.223.221.0/24' ),
                    ( 'hangar_42',      '10.0.33.0/24' ),
                    ( 'site_net',       '10.0.0.0/16' ),
                    ( 'external',       None )
                )
        
    @staticmethod
    def EndsWithAllNets():
        """A network enumeration which ends with 0.0.0.0/0."""
        return pcfg.NetworkEnumeration(
                    ( 'remote_site',    '10.222.0.0/16', '10.223.221.0/24' ),
                    ( 'hangar_42',      '10.0.33.0/24' ),
                    ( 'site_net',       '10.0.0.0/16' ),
                    ( 'external',       '0.0.0.0/0' )
                )

    @staticmethod
    def EndsWithNoNets():
        """A network enumeration which doesn't end with 0.0.0.0/0.
        
        The difference with EndsWithAllNets is that this just falls off the end
        and there is no match instead of matching external.
        """
        return pcfg.NetworkEnumeration(
                    ( 'remote_site',    '10.222.0.0/16', '10.223.221.0/24' ),
                    ( 'hangar_42',      '10.0.33.0/24' ),
                    ( 'site_net',       '10.0.0.0/16' )
                )
        
    @staticmethod
    def assertion_args( address, net_name, enumeration, arg2_none=False):
        """Args for assertions in test_all_nets."""
        args = [ enumeration.network( ip_address(address) ) ]
        if not arg2_none: args.append( enumeration.network_id[ net_name ] )
        args.append( "{} -> {}".format( address, net_name ) )
        return args
        
    #
    # TESTS START HERE
    #
    
    def test_none_disallowed(self):
        """A CIDR of None is disallowed."""
        with self.assertRaises(ValueError) as cm:
            network_enumeration = self.EndsWithNone()
        return
    
    def test_all_nets(self):
        """Various addresses tested against EndsWithAllNets."""
        network_enumeration = self.EndsWithAllNets()
        self.assertEqual( *self.assertion_args( '1.1.1.1', 'external', network_enumeration ) )
        self.assertEqual( *self.assertion_args( '10.0.0.42', 'site_net', network_enumeration ) )
        self.assertEqual( *self.assertion_args( '10.0.31.42', 'site_net', network_enumeration ) )
        self.assertEqual( *self.assertion_args( '10.0.33.42', 'hangar_42', network_enumeration ) )
        self.assertEqual( *self.assertion_args( '10.0.34.42', 'site_net', network_enumeration ) )
        self.assertEqual( *self.assertion_args( '10.221.33.55', 'external', network_enumeration ) )
        self.assertEqual( *self.assertion_args( '10.222.33.55', 'remote_site', network_enumeration ) )
        self.assertEqual( *self.assertion_args( '10.223.33.55', 'external', network_enumeration ) )
        self.assertEqual( *self.assertion_args( '10.223.221.55', 'remote_site', network_enumeration ) )
        self.assertEqual( *self.assertion_args( '10.223.222.55', 'external', network_enumeration ) )
        self.assertEqual( *self.assertion_args( '222.223.33.55', 'external', network_enumeration ) )        
        return
    
    def test_no_nets(self):
        """Various addresses tested against EndsWithNoNets."""
        network_enumeration = self.EndsWithNoNets()
        self.assertIsNone( *self.assertion_args( '1.1.1.1', 'None', network_enumeration, True ) )
        self.assertIsNone( *self.assertion_args( '10.221.33.55', 'None', network_enumeration, True ) )
        self.assertIsNone( *self.assertion_args( '222.223.33.55', 'None', network_enumeration, True ) )   
        return

class TestIPv6NetworkEnumeration(unittest.TestCase):
    """IPv6 Tests."""
    
    @staticmethod
    def EndsWithAllNets():
        """A network enumeration which ends with ::/0."""
        return pcfg.NetworkEnumeration(
                    ( 'remote_site',    '2001:db8:13:1::/64', '2001:db8:13:3::/64' ),
                    ( 'hangar_42',      '2001:db8:12:a000::/64' ),
                    ( 'site_net',       '2001:db8:12::/48' ),
                    ( 'external',       '::/0' )
                )
        
    @staticmethod
    def assertion_args( address, net_name, enumeration, arg2_none=False):
        """Args for assertions in test_all_nets."""
        args = [ enumeration.network( ip_address(address) ) ]
        if not arg2_none: args.append( enumeration.network_id[ net_name ] )
        args.append( "{} -> {}".format( address, net_name ) )
        return args

    #
    # TESTS START HERE
    #

    def test_all_nets(self):
        """Various addresses tested against EndsWithAllNets."""
        network_enumeration = self.EndsWithAllNets()
        self.assertEqual( *self.assertion_args( '2001:db8:1::22:f3d1', 'external', network_enumeration ) )
        self.assertEqual( *self.assertion_args( '2001:db8:12::3:12', 'site_net', network_enumeration ) )
        self.assertEqual( *self.assertion_args( '2001:db8:12:9fff::fe33:3555', 'site_net', network_enumeration ) )
        self.assertEqual( *self.assertion_args( '2001:db8:12:a000::fe33:3555', 'hangar_42', network_enumeration ) )
        self.assertEqual( *self.assertion_args( '2001:db8:12:a001::fe33:3555', 'site_net', network_enumeration ) )
        self.assertEqual( *self.assertion_args( '2001:db8:13::fe33:3555', 'external', network_enumeration ) )
        self.assertEqual( *self.assertion_args( '2001:db8:13:1::fe33:3555', 'remote_site', network_enumeration ) )
        self.assertEqual( *self.assertion_args( '2001:db8:13:2::fe33:3555', 'external', network_enumeration ) )
        self.assertEqual( *self.assertion_args( '2001:db8:13:3::fe33:3555', 'remote_site', network_enumeration ) )
        self.assertEqual( *self.assertion_args( '2001:db8:14:4::fe33:3555', 'external', network_enumeration ) )
        self.assertEqual( *self.assertion_args( '2001:db8:ffff:1::fe33:3555', 'external', network_enumeration ) )        
        return

class TestOurNets(unittest.TestCase):
    """Tests both the IPv4 and IPv6 versions of OUR_NETS."""
    
    @staticmethod
    def IPv4Nets():
        return pcfg.NetworkEnumeration(
                    ( 'remote_site',    '10.222.0.0/16', '10.223.221.0/24' ),
                    ( 'hangar_42',      '10.0.33.0/24' ),
                    ( 'site_net',        pcfg.OUR_4NETS )
                )

    @staticmethod
    def IPv6Nets():
        return pcfg.NetworkEnumeration(
                    ( 'remote_site',    '2001:db8:13:1::/64', '2001:db8:13:3::/64' ),
                    ( 'hangar_42',      '2001:db8:12:a000::/64' ),
                    ( 'site_net',        pcfg.OUR_6NETS )
                )
                    
    #
    # TESTS START HERE
    #

    def test_our_4nets(self):
        """Test mutability of OUR_4NETS."""
        network_enumeration = self.IPv4Nets()
        self.assertIsNone( network_enumeration.network( ip_address('10.0.31.42') ) )
        pcfg.update_our_nets( ip_network( '10.0.0.0/16' ) )
        self.assertEqual( network_enumeration.network( ip_address('10.0.31.42') ),
                          network_enumeration.network_id[ 'site_net' ]
                        )
        return
    
    def test_our_6nets(self):
        """Test mutability of OUR_6NETS."""
        network_enumeration = self.IPv6Nets()
        self.assertIsNone( network_enumeration.network( ip_address('2001:db8:12:a001::fe33:3555') ) )
        pcfg.update_our_nets( ip_network( '2001:db8:12::/48' ) )
        self.assertEqual( network_enumeration.network( ip_address('2001:db8:12:a001::fe33:3555') ),
                          network_enumeration.network_id[ 'site_net' ]
                        )
        return
    
class TestMappingActions(unittest.TestCase):
    """Test the various mapping actions.
    
    The mapping actions are:
    
      * PortMatch
      * Assign
      * LowerPort
      
    """
    
    #
    # PortMatch
    #
    
    def test_port_match_empty(self):
        """PortMatch: empty set of ports."""
        # This is a no-op.
        action = pcfg.PortMatch( set() )
        self.assertIsNone( action.match( ip_address('10.0.0.1'), 1, ip_address('10.0.0.2'), 2 ) )
        return
    
    def test_port_match_false(self):
        """PortMatch: no match."""
        action = pcfg.PortMatch( set((80, 443)) )
        self.assertIsNone( action.match( ip_address('10.0.0.1'), 1, ip_address('10.0.0.2'), 2 ) )
        return
    
    def test_port_match_source(self):
        """PortMatch: source port match."""
        action = pcfg.PortMatch( set((80, 443)) )

        result = action.match( ip_address('10.0.0.1'), 80, ip_address('10.0.0.2'), 2 )
        self.assertEqual( result[0], ip_address('10.0.0.2'),
                          "client-address"
                        )
        self.assertEqual( result[1], ip_address('10.0.0.1'),
                          "service-address"
                        )
        self.assertEqual( result[2], 80,
                          "port"
                        )
        return
        
    def test_port_match_dest(self):
        """PortMatch: destination port match."""
        action = pcfg.PortMatch( set((80, 443)) )

        result = action.match( ip_address('10.0.0.1'), 1, ip_address('10.0.0.2'), 443 )
        self.assertEqual( result[0], ip_address('10.0.0.1'),
                          "client-address"
                        )
        self.assertEqual( result[1], ip_address('10.0.0.2'),
                          "service-address"
                        )
        self.assertEqual( result[2], 443,
                          "port"
                        )
        return

        
    def test_port_match_precedence_source(self):
        """PortMatch: source port has precedence."""
        action = pcfg.PortMatch( set((80, 443)) )

        result = action.match( ip_address('10.0.0.1'), 80, ip_address('10.0.0.2'), 443 )
        self.assertEqual( result[0], ip_address('10.0.0.2'),
                          "client-address"
                        )
        self.assertEqual( result[1], ip_address('10.0.0.1'),
                          "service-address"
                        )
        self.assertEqual( result[2], 80,
                          "port"
                        )
        return
        
    def test_port_match_precedence_dest(self):
        """PortMatch: destination port has precedence."""
        action = pcfg.PortMatch( set((80, 443)), precedence=pcfg.DST )

        result = action.match( ip_address('10.0.0.1'), 80, ip_address('10.0.0.2'), 443 )
        self.assertEqual( result[0], ip_address('10.0.0.1'),
                          "client-address"
                        )
        self.assertEqual( result[1], ip_address('10.0.0.2'),
                          "service-address"
                        )
        self.assertEqual( result[2], 443,
                          "port"
                        )
        return
        
    def test_port_match_drop(self):
        """PortMatch: drop instead of return match data."""
        action = pcfg.PortMatch( set((80, 443)), drop=True )

        result = action.match( ip_address('10.0.0.1'), 80, ip_address('10.0.0.2'), 2 )
        self.assertEqual( len(result), 3, "length of result" )
        self.assertIsNone( result[0], "value is None" )

        return
    
    #
    # Assign
    #
    
    def test_assign_no_ports(self):
        """Assign: no ports, match any."""
        action = pcfg.Assign( pcfg.SRC, pcfg.DST )
 
        result = action.match( ip_address('10.0.0.1'), 1, ip_address('10.0.0.2'), 2 )
        self.assertEqual( result[0], ip_address('10.0.0.1'),
                          "client-address"
                        )
        self.assertEqual( result[1], ip_address('10.0.0.2'),
                          "service-address"
                        )
        self.assertEqual( result[2], 2,
                          "port"
                        )
        return
 
    def test_assign_drop(self):
        """Assign: drop instead of return match data."""
        action = pcfg.Assign( pcfg.SRC, pcfg.DST, drop=True )

        result = action.match( ip_address('10.0.0.1'), 1, ip_address('10.0.0.2'), 2 )
        self.assertEqual( len(result), 3, "length of result" )
        self.assertIsNone( result[0], "value is None" )

        return
    
    def test_assign_client_from(self):
        """Assign: correct operation of client_from."""
        action = pcfg.Assign( pcfg.SRC, pcfg.DST )
        result = action.match( ip_address('10.0.0.1'), 1, ip_address('10.0.0.2'), 2 )
        self.assertEqual( result[0], ip_address('10.0.0.1'),
                          "src is client-address"
                        )
        self.assertEqual( result[1], ip_address('10.0.0.2'),
                          "dst is service-address"
                        )

        action = pcfg.Assign( pcfg.DST, pcfg.DST )
        result = action.match( ip_address('10.0.0.1'), 1, ip_address('10.0.0.2'), 2 )
        self.assertEqual( result[0], ip_address('10.0.0.2'),
                          "dst is client-address"
                        )
        self.assertEqual( result[1], ip_address('10.0.0.1'),
                          "src is service-address"
                        )
        return
        
    def test_assign_port_from(self):
        """Assign: correct operation of port_from."""
        action = pcfg.Assign( pcfg.SRC, pcfg.DST, set(( 80, 443 )) )
        result = action.match( ip_address('10.0.0.1'), 443, ip_address('10.0.0.2'), 2 )
        self.assertIsNone( result )
        result = action.match( ip_address('10.0.0.1'), 1, ip_address('10.0.0.2'), 443 )        
        self.assertEqual( result[2], 443,
                          "dst is port"
                        )
        
        action = pcfg.Assign( pcfg.SRC, pcfg.SRC, set(( 80, 443 )) )
        result = action.match( ip_address('10.0.0.1'), 1, ip_address('10.0.0.2'), 80 )
        self.assertIsNone( result )
        result = action.match( ip_address('10.0.0.1'), 80, ip_address('10.0.0.2'), 2 )        
        self.assertEqual( result[2], 80,
                          "src is port"
                        )
        return
    
    #
    # LowerPort
    #
    
    def test_lower_port(self):
        """LowerPort: typical behavior / use."""
        action = pcfg.LowerPort()
        result = action.match( ip_address('10.0.0.1'), 13786, ip_address('10.0.0.2'), 2 )
        self.assertEqual( result[0], ip_address('10.0.0.1'),
                          "src is client-address"
                        )
        self.assertEqual( result[1], ip_address('10.0.0.2'),
                          "dst is service-address"
                        )
        self.assertEqual( result[2], 2,
                          "dst is port"
                        )
        
        result = action.match( ip_address('10.0.0.1'), 1, ip_address('10.0.0.2'), 44685 )
        self.assertEqual( result[0], ip_address('10.0.0.2'),
                          "dst is client-address"
                        )
        self.assertEqual( result[1], ip_address('10.0.0.1'),
                          "src is service-address"
                        )
        self.assertEqual( result[2], 1,
                          "src is port"
                        )
        return

    def test_lower_port_precedence(self):
        """LowerPort: test of precedence."""
        action = pcfg.LowerPort()
        result = action.match( ip_address('10.0.0.1'), 2, ip_address('10.0.0.2'), 2 )
        self.assertEqual( result[0], ip_address('10.0.0.2'),
                          "dst is client-address"
                        )
        self.assertEqual( result[1], ip_address('10.0.0.1'),
                          "src is service-address"
                        )
        self.assertEqual( result[2], 2 )
        
        action = pcfg.LowerPort( precedence=pcfg.DST)
        result = action.match( ip_address('10.0.0.1'), 2, ip_address('10.0.0.2'), 2 )
        self.assertEqual( result[0], ip_address('10.0.0.1'),
                          "src is client-address"
                        )
        self.assertEqual( result[1], ip_address('10.0.0.2'),
                          "dst is service-address"
                        )
        return

class TestFlowMapping(unittest.TestCase):
    """Tests the flow mapping logic."""
    
    def setUp(self):
        networks = pcfg.NetworkEnumeration(
                ( 'net_1',  '10.0.1.0/24' ),
                ( 'net_2',  '10.0.2.0/24' ),
                ( 'any',    '0.0.0.0/0')
            )
        self.mapping = pcfg.FlowMapping(
                ( 'net_1', 'net_2', pcfg.Assign( pcfg.SRC, pcfg.DST, set(( 1, )) ) ),
                ( 'net_2', 'net_1', pcfg.Assign( pcfg.SRC, pcfg.DST ) ),
                ( 'net_2',  None,   pcfg.Assign( pcfg.SRC, pcfg.DST, set(( 2, )) ) ),
                (  None,   'net_1', pcfg.Assign( pcfg.SRC, pcfg.DST, set(( 3, )) ) ),
                (  None,    None,   pcfg.Assign( pcfg.SRC, pcfg.DST, set(( 53, )), drop=True ) ),
                (  None,    None,   pcfg.Assign( pcfg.SRC, pcfg.DST, set(( 80, )) ) ),
            ).number_networks( networks )
        return
    
    def test_net_net(self):
        """network to network"""
        # Match / don't match flow 1
        self.assertIsNone( self.mapping.match( ip_address('10.0.1.1'), 3047, ip_address('10.0.2.1'), 3047 ) )
        self.assertIsNone( self.mapping.match( ip_address('10.0.1.1'), 1, ip_address('10.0.2.1'), 3047 ) )
        self.assertIsNotNone( self.mapping.match( ip_address('10.0.1.1'), 3047, ip_address('10.0.2.1'), 1 ) )
        # Match / don't match flow 2
        self.assertIsNone( self.mapping.match( ip_address('10.0.3.3'), 3047, ip_address('10.0.3.3'), 3047 ) )
        self.assertIsNotNone( self.mapping.match( ip_address('10.0.2.3'), 3047, ip_address('10.0.1.3'), 3047 ) )
        return
        
    def test_net_any(self):
        """network to any"""
        self.assertIsNotNone( self.mapping.match( ip_address('10.0.2.1'), 3047, ip_address('10.0.2.1'), 2 ) )
        return
        
    def test_any_net(self):
        """any to network"""
        self.assertIsNotNone( self.mapping.match( ip_address('10.0.1.1'), 3047, ip_address('10.0.1.1'), 3 ) )
        return
    
    def test_any_any(self):
        """any to any"""
        # Test the drop rule.
        self.assertIsNone( self.mapping.match( ip_address('10.0.1.1'), 3047, ip_address('10.0.1.1'), 53 ) )
        # Test the final rule.
        self.assertIsNotNone( self.mapping.match( ip_address('10.0.1.1'), 3047, ip_address('10.0.1.1'), 80 ) )
        return
        
if __name__ == '__main__':
    unittest.main(verbosity=2)
