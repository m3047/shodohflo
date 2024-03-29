#!/usr/bin/python3
# Copyright (c) 2019,2023 by Fred Morris Tacoma WA
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

"""RKVDNS Data Connector.

This is a readonly RKVDNS connector. Pass an instance of RKVDNSConnection
whenever you see r_client as a parameter.
"""

from time import time
import concurrent.futures

from database import *

# These are references to modules in the rkvdns_examples/ project. The script
# rkvdns_links.sh in this (the app/) directory will create the two required
# symlinks if rkvdns_examples is cloned in the same parent directory as shodohflo.
from rkvdns import ResolverPool, rdtype
from fanout import BaseName

ESCAPED = { c for c in '.;' }

ARTIFACT_BUCKET_SIZE = 20       # Number of artifacts to lookup in a thread.

# These control how much data about peers and ports we're willing to munge.
FLOW_LIMIT =  10
PEER_LIMIT = 200

COUNTER_ARTIFACTS = { 'nx', 'peer', 'flow', 'icmp', 'rst' }
LIST_ARTIFACTS = { 'dns', 'cname' }

def escape(qname, escaped=ESCAPED):
    """Escape . and ;"""
    for c in escaped:
        qname = qname.replace(c, '\\{}'.format(c))
    return qname

class RKVDNSConnection(object):
    """Represents an RKVDNS Connection.
    
    Pass an instance of this in wherever you see r_client as a parameter.
    
    rkvdns is (ideally) an FQDN which resolves to PTR records referencing
    (multiple RKVDNS) instances, although it can also be a direct reference
    to a single RKVDNS instance. An RKVDNS instance in this case is an FQDN
    which represents the "zone" which RKVDNS "serves" (in other words it has
    an NS record and we want the zone name (left side) not what it resolves to
    (right side)).
    
    See rkvdns_examples/fanout/ for further information.
    """
    def __init__(self, rkvdns, warn_if_noanswer=False):
        self.fanout = BaseName(rkvdns, warn_if_noanswer=warn_if_noanswer)
        if not self.fanout.fanout:
            self.fanout.fanout_ = [ rkvdns ]
        self.pool = ResolverPool()
        return

def read_rkvdns(server, pool, k, is_list=False):
    """Read from server using pool.
    
    k is the RKVDNS key, is_list indicates whether the returned data is list or scalar.
    Lists are converted to sets, scalars are returned as scalars with the value None indicating
    that nothing was found.
    """
    with pool:
        result = [ rd.to_text().lower().strip('"')
                   for rd in
                   pool.query('{}.{}'.format(k, server), rdtype.TXT).success and pool.result or []
                 ]
    if is_list:
        result = set(result)
    elif result:
        result = result[0]
    else:
        result = None
    return result

def read_keys( server, pool, client, origin, is_target ):
    """Read the keys for the client.
    
    If number of peers exceeds PEER_LIMIT it will be truncated and returned as "(many)"; no
    flows will be returned.
    
    If number of flows (ports) exceeds FLOW_LIMIT they will be truncated and returned as "(many)".
    """
    
    # Ping clients first to make sure there's a reason to look for anything else.
    with pool:
        if not pool.query('{}.get.{}'.format( escape('client;{}'.format(client)), server ), rdtype.TXT).success:
            return []
    
    keys = []
    
    for k in ('cname', 'dns'):
        keys += read_rkvdns( server, pool, escape('{};*;{}'.format(client,k)) + '.keys', is_list=True)
    
    if origin == 'fqdn':
        keys += read_rkvdns( server, pool, escape('{};*;nx'.format(client)) + '.keys', is_list=True)
        return keys
    
    # origin == 'address'
    
    for k in ('rst', 'icmp'):
        keys += read_rkvdns( server, pool, escape('{};*;{}'.format(client,k)) + '.keys', is_list=True)
    
    # We are going to read peers and flows, but only if the number is small.
    with pool:
        if pool.query('{}.klen.{}'.format(escape('{};*;peer'.format(client)), server), rdtype.TXT).success:
            n_peers = int(pool.result[0].strings[0])
        else:
            return keys
    
    if n_peers > PEER_LIMIT:
        return keys + [ '{};(many);peer'.format(client) ]
    
    # Accumulate ports, up to the limit. If there are too many ports, fall back to
    # returning peers.
    flows = []
    peers = read_rkvdns( server, pool, escape('{};*;peer'.format(client)) + '.keys', is_list=True)
    for peer in peers:
        flows += read_rkvdns( server, pool,
                              escape( '{};{};*;flow'.format(client, peer.split(';')[1]) ) + '.keys',
                              is_list=True)
        if len(flows) > FLOW_LIMIT:
            break
    if len(flows) > FLOW_LIMIT:
        keys += [ 
            '{};{};(many);flow'.format( client, peer.split(';')[1] )
            for peer in peers
        ]
    else:
        keys += flows
        
    return keys

def read_artifacts(pool, server, artifacts):
    """Reads info about the artifacts from the server."""
    results = [ ]
    with pool:
        for artifact in artifacts:
            artifact_type = artifact.split(';')[-1]
            if artifact_type not in ARTIFACT_MAPPER:
                continue
            if not pool.query('{}.get.{}'.format(escape(artifact), server), rdtype.TXT).success:
                continue
            
            is_list = issubclass(ARTIFACT_MAPPER[artifact_type], ListArtifact)
            
            if is_list:
                results.append(
                        ( artifact, is_list,
                          { v
                            for rd in pool.result 
                            for v in rd.to_text().lower().strip('"').split(';')
                            if v
                          }
                        )
                    )
            else:
                results.append(
                        ( artifact, is_list, int(pool.result[0].to_text().strip('"')) )
                    )
    return results

def get_all_clients(r_client):
    """Return all "our" addresses.
    
    Returns a list of ipaddress *Address objects.
    """
    results = set()
    for result in r_client.fanout.map( read_rkvdns, r_client.pool, '{}.keys'.format(escape('client;*')), is_list=True ).values():
        results |= result
    return [ ipaddress.ip_address(v.split(';',1)[1]) for v in results ]

class ArtifactDict(dict):
    def add(self, k, is_list, v):
        """Add / deduplicate an artifact.
        
        (k, is_list, v) is the tuple returned from read_artifacts().
        """
        if is_list:
            if k not in self:
                self[k] = set()
            self[k] |= v
        else:
            if k not in self:
                self[k] = 0
            self[k] += v
        return

def get_client_data(r_client, all_clients, targets, prefix, origin):
    """Get all data for all (active) clients in the network.
    
    Returns a list of instances of subclasses of ClientArtifact.
    
    Unlike the direct Redis implementation, in this implementation 
    counts are aggregated across potentially multiple RKVDNS instances
    before being baked.
    
    The naive (direct-to-redis) approach is to simply read all artifact types for
    all clients in the network. We do want to be a little more efficient here because
    of architectural limits and prebaked efficiencies in DNS.
    
    We always read:
    
    * dns
    * cname
    
    We only read the following for origin "fqdn":
    
    * nx
    
    We only read the following for origin "address" and the specific targets:
    
    * rst
    * icmp
    * peer
    * flow
    
    Furthermore, we only read "flow" if the number of flows is <= 10.
    """
    artifact_jobs = []
    artifact_data = ArtifactDict()
    #t = time()
    for client in all_clients:
        if client not in prefix:
            continue
        for server,results in r_client.fanout.map( read_keys, r_client.pool, str(client), origin, is_target=(client in targets)
                            ).items():

            artifacts = set()
            while results:
                # Things which are CounterArtifacts just need to be dummied up, we don't need the
                # actual counts.
                result = results.pop()
                artifact_type = result.split(';')[-1]

                if artifact_type in COUNTER_ARTIFACTS:
                    # Convert peers to flows.
                    if artifact_type == 'peer':
                        client, peer, ignore = result.split(';')
                        result = '{};{};(many);flow'.format(client, peer)
                    
                    artifact_data.add( result, False, 1 )
                    continue
                
                artifacts.add( result )
                if len(artifacts) >= ARTIFACT_BUCKET_SIZE:
                    artifact_jobs.append( (server, artifacts) )
                    artifacts = set()
                
            if artifacts:
                artifact_jobs.append( (server, artifacts) )

    #print( time() - t )
    #t = time()
    #artifact_data = ArtifactDict()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        threads = set()
        for job in artifact_jobs:
            threads.add( executor.submit( read_artifacts, r_client.pool, *job ) )
        for thread in concurrent.futures.as_completed( threads ):
            for result in thread.result():
                artifact_data.add( *result )

    #print( time() - t )
    #t = time()
    all_artifacts = []
    for k,v in artifact_data.items():
        artifact_type = k.split(';')[-1]
        if isinstance(v, set):
            artifact = ARTIFACT_MAPPER[artifact_type](k, ';{};'.format(';'.join(v)))
        else:
            artifact = ARTIFACT_MAPPER[artifact_type](k, v)
        all_artifacts.append(artifact)
        if isinstance(artifact, ReconArtifact):
            all_artifacts.append(artifact.reversed())
    
    #print( time() - t )
    return all_artifacts

def clear_client_data(r_client, target, all_clients):
    """Clear all data for the target.
    
    THIS IS A NO-OP FOR RKVDNS, which is readonly.
    """
    return

    
