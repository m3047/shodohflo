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

"""Things useful for dealing with Redis."""

import ipaddress

def get_all_clients(r_client):
    """Return all "our" addresses.
    
    Returns a list of ipaddress *Address objects.
    """
    return [ ipaddress.ip_address(v.split(';',1)[1]) for v in r_client.keys('client;*') ]

class ClientArtifact(object):
    """Base class for artifacts."""
    def __init__(self, k, v):
        self.extract_key_data(k.split(';')
        self.extract_value_data(v)
        return
    
    def extract_key_data(self,k):
        """Extract information from the key.
        
        Information potentially includes:
        
        * client address
        * remote address
        * remote port
        * rname (right hand side name)
        * oname (left hand side name)
        
        This method needs to be implemented by the subclass.
        """
        pass
    
    def extract_value_data(self,v):
        """Extract information from the value associated with the key.
        
        Information potentially includes:
        
        * list of onames
        * count
        
        This method needs to be implemented by the subclass.
        """
        pass
    
    def append_to_mapping(self, k, mapping):
        if k not in mapping:
            mapping[k] = []
        mapping[k].append(self)
        return
    
def CounterArtifact(ClientArtifact):
    """The associated value is a count."""
    def extract_value_data(self,v):
        self.count = int(v)
        return

def ListArtifact(ClientArtifact):
    """The associated value is a list.
    
    It's always a list of onames (left hand side values). Or in other words
    it is the reverse of normal DNS lookup.
    """
    def extract_value_data(self,v):
        self.onames = [ oname for oname in v.split(';') if oname ]

    def update_origins(self, origin_type, origin_list):
        """Update origin_list.
        
        origin_list is a list of keys into mappings. mappings is updated by
        update_mappings().
        """
        if origin_type not in self.ORIGIN_FOR:
            return
        for name in self.onames:
            self.append_to_mapping(name, origin_list)
        return
    
    def update_fqdn_mappings(self,mappings):
        for name in self.onames:
            self.append_to_mapping(name, mappings)
        return
    
    def update_mappings(self, origin_type, mappings):
        if origin_type not in self.MAPPING_FOR:
            return
        if origin_type == 'address':
            self.update_address_mappings(mappings)
        else:           # 'fqdn'
            self.update_fqdn_mappings(mappings)
        return

class DNSArtifact(ListArtifact):
    """A DNS artifact."""

    CLIENT_ADDR = 0
    REMOTE_ADDR = 1
    
    ORIGIN_FOR = {'fqdn'}
    MAPPING_FOR = {'address','fqdn'}
    
    def extract_key_data(self,k):
        self.client_address = ipaddress.ip_address(k[self.CLIENT_ADDR])
        self.remote_address = ipaddress.ip_address(k[self.REMOTE_ADDR])
        return

    # update_origins() declared in ListArtifact.
    
    # update_mappings() and update_fqdn_mappings() declared in ListArtifact.
    
    def update_address_mappings(self,mappings):
        self.append_to_mapping(str(self.remote_address), mappings)
        return
    
    def children(self, origin_type):
        if origin_type == 'address':
            return self.onames
        else:           # fqdn
            return [self.remote_address]

class CNAMEArtifact(ListArtifact):
    """A CNAME artifact."""

    CLIENT_ADDR = 0
    RNAME = 1
    
    ORIGIN_FOR = {'fqdn'}
    MAPPING_FOR = {'address','fqdn'}
    
    def extract_key_data(self,k):
        self.client_address = ipaddress.ip_address(k[self.CLIENT_ADDR])
        self.rname = k[self.RNAME]
        return
    
    @property
    def name(self):
        return self.rname

    # update_origins() declared in ListArtifact.

    # update_mappings() and update_fqdn_mappings() declared in ListArtifact.

    def update_address_mappings(self,mappings):
        self.append_to_mapping(self.rname, mappings)
        return

    def children(self, origin_type):
        if origin_type == 'address':
            return self.onames
        else:           # fqdn
            return [self.rname]

class NXDOMAINArtifact(CounterArtifact):
    """An FQDN for which DNS resolution failed."""

    CLIENT_ADDR = 0
    ONAME = 1
    
    ORIGIN_FOR = {'fqdn'}
    MAPPING_FOR = {'fqdn'}
    
    def extract_key_data(self,k):
        self.client_address = ipaddress.ip_address(k[self.CLIENT_ADDR])
        self.oname = k[self.ONAME]
        return
    
    @property
    def name(self):
        return self.oname

    def update_origins(self, origin_type, origin_list):
        """Update origin_list.
        
        origin_list is a list of keys into mappings. mappings is updated by
        update_mappings().
        """
        if origin_type not in self.ORIGIN_FOR:
            return
        self.append_to_mapping(self.oname, origin_list)
        return
    
    def update_mappings(self, origin_type, mappings):
        if origin_type not in self.MAPPING_FOR:
            return
        self.append_to_mapping(self.oname, mappings)
        return

    def children(self, origin_type):
        if origin_type == 'fqdn':
            return [self.oname]
        else:           # fqdn
            return []

class NetflowArtifact(CounterArtifact):
    """A Packet Capture artifact."""

    CLIENT_ADDR = 0
    REMOTE_ADDR = 1
    REMOTE_PORT = 2
    
    ORIGIN_FOR = {'address'}
    MAPPING_FOR = set()
    
    def extract_key_data(self,k):
        self.client_address = ipaddress.ip_address(k[self.CLIENT_ADDR])
        self.remote_address = ipaddress.ip_address(k[self.REMOTE_ADDR])
        self.remote_port = k[self.REMOTE_PORT]
        return

    def update_origins(self, origin_type, origin_list):
        """Update origin_list.
        
        origin_list is a list of keys into mappings. mappings is updated by
        update_mappings().
        """
        if origin_type not in self.ORIGIN_FOR:
            return
        self.append_to_mapping(str(self.remote_address), origin_list)
        return
    
    def update_mappings(self, origin_type, mappings):
        """NetflowArtifact is not a mapping type for any origin."""
        #if origin_type not in self.MAPPING_FOR:
            #return
        return
    
    def children(self, origin_type):
        return []

ARTIFACT_MAPPER = dict(
        dns     = DNSArtifact,
        cname   = CNAMEArtifact,
        nx      = NXDOMAINArtifact,
        flow    = NetflowArtifact
    )

def Artifact(r_client, k):
    """Factory function which returns instances of ClientArtifact for the passed key."""

    artifact_type = k.split(';')[-1]
    if artifact_type not in ARTIFACT_MAPPER:
        return None
    
    v = r_client.get(k)
    if not v:
        return None
    
    return ARTIFACT_MAPPER[artifact_type](k, v)

def get_client_data(r_client, all_clients, network):
    """Get all data for all (active) clients in the network.
    
    Returns a list of instances of subclasses of ClientArtifact.
    
    For performance reasons (premature optimization?) we read a single client
    address at a time. DNS data is stored for as long as the TTL, so it may
    exist in the network even if the client which made the requests hasn't been
    seen. Such records are invisible until the client which made the request(s)
    is seen again.
    """
    all_artifacts = []
    for client in all_clients:
        if client not in network:
            continue
        for k in r_client.keys('{};*'.format(str(client))):
            artifact = Artifact(r_client, k)
            if artifact is None:
                continue
            all_artifacts.append(artifact)
    return all_artifacts
