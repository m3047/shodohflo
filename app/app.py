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

if __name__ == "__main__":
    from configuration import *
else:
    HTTP_PORT = 3047
    REDIS_SERVER = 'localhost'
    USE_DNSPYTHON = False
    
if USE_DNSPYTHON:
    import dns.resolver as resolver

import ipaddress

import redis
from flask import Flask, request, render_template, url_for, redirect, Markup

from redis_data import get_all_clients, get_client_data, \
                       DNSArtifact, CNAMEArtifact, NXDOMAINArtifact, NetflowArtifact

app = Flask(__name__)

def redis_client():
    if USE_DNSPYTHON:
        redis_server = resolver.query(REDIS_SERVER).response.answer[0][0].to_text()
    else:
        redis_server = REDIS_SERVER
    return redis.client.Redis(redis_server, decode_responses=True)

class Link(object):
    """A single link in a chain."""
    def __init__(self, origin, artifact_list=None)
        """Links in a chain.
        
        Origin (external) links are first created as promises, whereas internal links are
        built at creation time.
        """
        self.artifact = origin
        self.artifact_list = artifact_list
        self.reference_count = 0
        self.children = []
        self.depth = None
        return
    
    def build(self, origin_type, origins, mappings, internal=set()):
        if internal and self.artifact in origins:
            link = origins[self.artifact]
            link.reference_count += 1
            return link

        if self.artifact in internal:   # loop detection
            return self
        internal.add(self.artifact)

        if self.artifact not in mappings:
            return self

        for artifact in mappings[self.artifact]:
            if isinstance(artifact, NXDOMAINArtifact):
                self.children.append(NXDOMAINLink())
                continue
            
            self.children += [ Link(child).build(origin_type, origins, mappings, internal=internal)
                               for child in artifact.children(origin_type)
                             ]
        return self
    
    def depth(self, x=0):
        """Return the depth of the chain."""
        if self.depth is None:
            x = max((child.depth(x+1) for child in self.children))
            self.depth = x
        return self.depth
                    
class Link_Terminals(Link):
    """A special subclass for links which affirmatively end a chain.
    
    Most chains end naturally when there are no more links to follow. In some cases
    however we may want to affirmatively tag something as terminal.
    """
    pass

class NXDOMAINLink(LinkTerminals):
    """Represents an oname for which an NXDOMAIN answer was affirmatively seen."""
    def __init__(self):
        Link.__init__(self,'NXDOMAIN')
        return
    
def calc_prefix(arg, addresses):
    """Calculates the prefix for the list of addresses.
    
    Creates the prefix from arg if one is supplied, otherwise computes the prefix
    from the addresses.
    """
    
    # This can throw an exception if they supplied an invalid netmask.
    if arg:
        return(ipaddress.ip_network(arg))

    # Should be at least one address present or we return nothing.
    if not addresses:
        return None
    
    # Prefix should be the same for both the ORed and ANDed values.
    ival = int(addresses[0])
    ored = ival
    anded = ival
    for address in addresses[1:]:
        ival = int(address)
        ored |= ival
        anded &= ival
        
    v4max = int(ipaddress.IPv4Network('0.0.0.0/0').hostmask)
    v6max = int(ipaddress.IPv6Network('::/0').hostmask)
    
    if ored > v4max:
        all_bits = v6max
        n_bits = 128
    else:
        all_bits = v4max
        n_bits = 32
        
    i = 0
    mask = 2**i - 1
    while mask <= ored:
        mask ^= all_bits
        if (anded & mask) == (ored & mask):
            break
        i += 1
        mask = 2**i - 1
    
    return ipaddress.ip_network(((anded & mask), (n_bits - i)))

def build_options(prefix, clients, selected):
    """Return a list of all clients in the prefix, with the one selected marked selected."""
    addresses = [ ipaddress.ip_address(client) for client in clients ]
    if prefix:
        addresses = [ address for address in addresses if address in prefix ]
    return [{ 'value': '--all--', 'selected':(selected == '--all--') }] + [
            dict(value=str(address), selected=(selected == str(address)))
            for address in sorted(addresses, key=lambda x: int(x))
           ]

def render_chain(chain):
    """Render a single chain."""
    return ''.join([
              chain.artifact, chain.children and '&nbsp;&rarr; ' or '',
              '<div class="iblock">',
                '<br/>'.join((render_chain(element) for element in chain.children)),
              '</div>'
        ])

def render_chains(origin_type, data, target):
    """Render all chains."""
    if target == '--all--':
        target = None
    else:
        target = ipaddress.ip_network(filter)   # a single address network actually

    # Create mappings of artifacts. The keys in all_origins are a subset of what's in
    # all_mappings except when there is no mapping at all.
    all_origins =  {}
    all_mappings = {}

    for artifact in data:
        if target is None or artifact.client_address in target:
            artifact.update_origins(origin_type, all_origins)
        artifact.update_mappings(origin_type, all_mappings)
    
    # Make some promises regarding the origins.
    for origin in all_origins.keys():
        all_origins[origin] = Link(origin, all_origins[origin])
    
    # Build origin chain fragments until they intersect another origin or
    # loop or die out.
    for origin in all_origins.values():
        origin.build(origin_type, all_origins, all_mappings)
    
    # At this point our actual list of "true" origins is the list of things
    # for which all_origins[x].reference_count == 0
    by_depth = [ [] for i in range(10) ]
    for chain in chains:
        if chain.reference_count:
            continue
        depth = chain.depth()
        if depth >= 10:
            depth = 9
        by_depth[depth].append(chain)
    for i in range(10):
        if origin_type == 'address':
            by_depth[i] = [ c[1] for c in
                            sorted(([int(ipaddress.ip_address(chain.artifact)), chain] for chain in depth[i]), 
                                   key=lambda x: x[0] )
                          ]
    
    chains = [ render_chain(chain) for bucket in by_depth for chain in bucket ]
    
    return chains
    
@app.route('/', methods=['GET'])
def root():
    """endpoint: /
    
    Redirects to '/address'.
    """
    return redirect(url_for('graph', origin='address'))
    
@app.route('/<origin>', methods=['GET'])
def graph(origin):
    """endpoint: /<origin>"""

    arg_origin = request.args.get('origin','address')
    if arg_origin not in ('address','fqdn'):
        arg_origin = 'address'
    origin = arg_origin

    r = redis_client()
    all_clients = get_all_clients(r)

    prefix = calc_prefix(request.args.get('prefix',''), all_clients)

    filter = request.args.get('filter','--all--')
    all = request.args.get('all', '')
    if all or filter == '--all--':
        data = get_client_data(r, all_clients, prefix)
    else:
        data = get_client_data(r, all_clients, ipaddress.ip_network(filter))
    
    return render_template('graph.html',
                    origin=origin, prefix=(prefix and str(prefix) or ''),
                    filter_options=build_options(prefix, all_clients, filter),
                    all=True,
                    table=[render_chains(origin, data, filter)],
                    message="")

if __name__ == "__main__":
    app.run(port=HTTP_PORT)
