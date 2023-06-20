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

"""Things useful for dealing with Redis."""

from database import *

def get_all_clients(r_client):
    """Return all "our" addresses.
    
    Returns a list of ipaddress *Address objects.
    """
    return [ ipaddress.ip_address(v.split(';',1)[1]) for v in r_client.keys('client;*') ]

def Artifact(r_client, k, types=None):
    """Factory function which returns instances of ClientArtifact for the passed key.
    
    types specifies the key types we're interested in. If not supplied then this
    returns all the things.
    """

    artifact_type = k.split(';')[-1]
    if artifact_type not in ARTIFACT_MAPPER:
        return None
    if types is not None and artifact_type not in types:
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
    if network is None:
        return []

    all_artifacts = []
    for client in all_clients:
        if client not in network:
            continue
        for k in r_client.keys('{};*'.format(str(client))):
            artifact = Artifact(r_client, k)
            if artifact is None:
                continue
            all_artifacts.append(artifact)
            if isinstance(artifact, ReconArtifact):
                all_artifacts.append(artifact.reversed())

    return all_artifacts

def clear_client_data(r_client, target, all_clients):
    """Clear all data for the target.
    
    The target is mapped from the filter in the UI.
    """
    for client in all_clients:
        if target and client not in target:
            continue
        for k in r_client.keys('{};*'.format(str(client))):
            r_client.delete(k)
    return

def merge_mappings(target, mapping):
    """Merge mappings of the same Artifact type."""
    collected = {}
    for artifact in mapping:
        artifact.append_to_mapping(type(artifact), collected)
    return [ merged for k in collected.keys() for merged in k.merge(collected[k], target) ]
    
