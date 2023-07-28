#!/usr/bin/python3
# Copyright (c) 2019, 2023 by Fred Morris Tacoma WA
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

HTTP_HOST = 'localhost'
HTTP_PORT = 3047
REDIS_SERVER = 'localhost'
RKVDNS = None
USE_DNSPYTHON = False
DEFAULT_TEMPLATE = 'graph'
AVAILABLE_TEMPLATES = ['graph']

if __name__ == "__main__":
    from configuration import *
    
if USE_DNSPYTHON:
    import dns.resolver as resolver

#import logging
#logging.basicConfig(level=logging.DEBUG)

import importlib
import ipaddress

from flask import Flask, request, render_template, url_for, redirect

if RKVDNS:
    from rkvdns_data import get_all_clients, get_client_data, clear_client_data, merge_mappings, \
                            DNSArtifact, CNAMEArtifact, NXDOMAINArtifact, NetflowArtifact, \
                            RKVDNSConnection
else:
    import redis
    from redis_data import  get_all_clients, get_client_data, clear_client_data, merge_mappings, \
                            DNSArtifact, CNAMEArtifact, NXDOMAINArtifact, NetflowArtifact
import sys
import cProfile
import pstats

app = Flask(__name__)

# If something is this deep from FQDN to address, it's going to run very
# poorly if at all....
TOO_DEEP = 10

def redis_client():
    if USE_DNSPYTHON:
        redis_server = resolver.query(REDIS_SERVER).response.answer[0][0].to_text()
    else:
        redis_server = REDIS_SERVER
    return redis.client.Redis(redis_server, decode_responses=True)

class Link(object):
    """A single link in a chain.
    
    Metadata:

    Metadata which is potentially of use in the rendering operation can
    be found in the metadata attribute. This is a dictionary containing the following
    potential keys. Some of the keys are specific to a ClientArtifact subclass.

    targets     Set of addresses targeted.
    clients     all: Set of all client addresses with this artifact.
    types       all: Set of all artifact types as strings.
    ports       NetflowArtifact: Set of port numbers associated with flows.
    """
    RECON_INDICATORS = set(('ICMP','RST'))
    
    def __init__(self, origin, observations=[], is_target=True):
        """Links in a chain.
        
        Origin (external) links are first created as promises, whereas internal links are
        built at creation time.
        """
        self.artifact = origin
        self.is_target = is_target
        self.reference_count = 0
        self.children = []
        self._depth = None
        md = dict(clients=set(), types=set(), ports=set(), targets=set())
        for obs in observations:
            for k in md.keys():
                md[k] |= obs.metadata_for(k)
        self.metadata = md
        return

    def recon_activity(self):
        """Return True if possible recon activity was detected.
        
        This consists of an artifact (address) being the initiator or recipient of ICMP
        Unreachable notifications or TCP RSTs.
        """
        return not self.metadata['types'].isdisjoint(self.RECON_INDICATORS)

    def build(self, origin_type, origins, mappings, target, internal=None):
        """Build the chain from the origin."""
        if internal is None:
            internal = set()
        if internal and self.artifact in origins:
            link = origins[self.artifact]
            link.reference_count += 1
            return link

        if self.artifact not in mappings:
            return self

        if self.artifact in internal:   # loop detection
            return self
        internal.add(self.artifact)        

        for artifact in mappings[self.artifact]:

            if isinstance(artifact, NXDOMAINArtifact):
                self.children.append(NXDOMAINLink())
                continue
            
            self.children += [ Link(child, child in mappings and mappings[child] or [], is_target
                                ).build(origin_type, origins, mappings, target, internal=internal)
                               for child,is_target in artifact.children(origin_type, target)
                             ]
        return self
    
    def depth(self, x=0):
        """Return the depth of the chain."""
        if self._depth is None:
            if x < TOO_DEEP and self.children:
                x = max((child.depth(x+1) for child in self.children))
            self._depth = x
        return self._depth
    
class LinkTerminals(Link):
    """A special subclass for links which affirmatively end a chain.
    
    Most chains end naturally when there are no more links to follow. In some cases
    however we may want to affirmatively tag something as terminal.
    """
    def depth(self, x=0):
        """Terminals shouldn't count towards depth."""
        x -= 1
        if x < 0:
            x = 0
        return x
    
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
    
    v4max = int(ipaddress.IPv4Network('0.0.0.0/0').hostmask)
    v6max = int(ipaddress.IPv6Network('::/0').hostmask)
    v6bitsonly = v4max ^ v6max
    
    # Prefix should be the same for both the ORed and ANDed values.
    ival = int(addresses[0])
    ored = ival
    if ival <= v4max:
        ival |= v6bitsonly
    anded = ival
    for address in addresses[1:]:
        ival = int(address)
        ored |= ival
        if ival <= v4max:
            ival |= v6bitsonly
        anded &= ival
        
    if ored > v4max:
        all_bits = v6max
        n_bits = 128
    else:
        all_bits = v4max
        n_bits = 32
        
    i = 0
    low_bits = 2**i - 1
    mask = low_bits ^ all_bits
    while low_bits <= ored:
        if (anded & mask) == (ored & mask):
            break
        i += 1
        low_bits = 2**i - 1
        mask = low_bits ^ all_bits
    
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

def render_chains(origin_type, data, target, render_chain, debug=None):
    """Render all chains.
    
    data is a list of items from the redis_data.Artifact factory (ClientArtifacts).
    """
    # Create mappings of artifacts. The keys in all_origins are a subset of what's in
    # all_mappings except when there is no mapping at all.
    all_origins =  {}
    all_mappings = {}

    for artifact in data:
        if target is None or artifact.client_address in target:
            artifact.update_origins(origin_type, all_origins)
        artifact.update_mappings(origin_type, all_mappings)
        
    #debug += [ all_origins[k] for k in ('10.0.0.220', '10.0.0.253') if k in all_origins]
        
    # Normalize mappings. In case something is mapped by both the target and something
    # in the prefix, the target takes preference. After this there is AT MOST one of
    # any particular subclass of ClientArtifact.
    for k in sorted(all_mappings.keys()):
        all_mappings[k] = merge_mappings( target, all_mappings[k] )
        
    # Make some promises regarding the origins.
    for origin in all_origins.keys():
        all_origins[origin] = Link(origin, all_origins[origin])
    
    # Build origin chain fragments until they intersect another origin or
    # loop or die out.
    for origin in all_origins.values():
        origin.build(origin_type, all_origins, all_mappings, target)
    
    # At this point our actual list of "true" origins is the list of things
    # for which all_origins[x].reference_count == 0
    by_depth = [ [] for i in range(TOO_DEEP) ]
    for chain in all_origins.values():
        if chain.reference_count:
            continue
        depth = chain.depth()
        if depth >= TOO_DEEP:
            depth = TOO_DEEP - 1
        by_depth[depth].append(chain)
    
    #debug += [ '{}: {}'.format(link.artifact, link.metadata) for link in by_depth[1][:3] ]
        
    for i in range(TOO_DEEP):
        if origin_type == 'address':
            by_depth[i] = [ c[1] for c in
                            sorted(([int(ipaddress.ip_address(chain.artifact)), chain] for chain in by_depth[i]), 
                                   key=lambda x: x[0] )
                          ]
        else:           # 'fqdn'
            by_depth[i] = [ c[1] for c in
                            sorted(([chain.artifact, chain] for chain in by_depth[i]), 
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

    message = ""

    # NOTE: The endpoint route eventually converges to what's in the argument. IOW
    # we could do a redirect but we're not, so the first response goes back to the
    # submitted endpoint but with the correct endpoint in the submittal form. Oh well.
    # Submitting to either origin endpoint without the origin arg works fine.
    arg_origin = request.args.get('origin',None)
    if arg_origin and arg_origin in ('address','fqdn'):
        origin = arg_origin
    if origin not in ('address','fqdn'):
        origin = 'address'

    if RKVDNS:
        r = RKVDNSConnection( RKVDNS, warn_if_noanswer=True )
    else:
        r = redis_client()

    all_clients = get_all_clients(r)

    try:
        prefix = calc_prefix(request.args.get('prefix',''), all_clients)
    except ValueError:
        message = "{} doesn't appear to be a valid prefix / network".format(request.args.get('prefix',''))
        prefix = calc_prefix('', all_clients)
    
    try:
        filter = request.args.get('filter','--all--')
        if filter == '--all--':
            target = prefix
        else:
            target = ipaddress.ip_network(filter)
    except ValueError:
        message = "{} doesn't appear to be a valid filter / address".format(filter)
        filter = '--all--'
        target = None
        
    template = request.args.get('template',DEFAULT_TEMPLATE)
    if template not in AVAILABLE_TEMPLATES:
        message = "'{}' is not a recognized template.".format(template)
        template = DEFAULT_TEMPLATE
    render_chain = importlib.import_module('renderers.' + template).render_chain
    
    if not RKVDNS:
        if request.args.get('clear',False):
            clear_client_data(r, target, all_clients)
    
    debug = []
    all = request.args.get('all', '')
    if all:
        data = get_client_data(r, all_clients, target, prefix, origin)
    else:
        data = get_client_data(r, all_clients, target, target, origin)
    
    return render_template(template + '.html',
                    origin=origin, prefix=(prefix and str(prefix) or ''),
                    filter_options=build_options(prefix, all_clients, filter),
                    all=all,
                    table=render_chains(origin, data, target, render_chain, debug),
                    debug=debug,
                    message=message,
                    template=template,
                    readonly=(RKVDNS is not None))

if __name__ == "__main__":
    app.run(port=HTTP_PORT, host=HTTP_HOST)
