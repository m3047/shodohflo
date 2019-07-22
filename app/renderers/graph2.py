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
"""Graph -- the Default Renderer"""

def muted(text,mute):
    """Renders some text muted."""
    if mute:
        fmt = '<span class="muted">{}</span>'
    else:
        fmt = '{}'
    return fmt.format(text)

def details(link):
    """Get details for a Link object."""
    md = link.metadata
    detail_list = []
    for k in sorted(md.keys()):
        if md[k]:
            detail_list.append('<span class="header">{}</span><br/>{}<br/>'.format(
                    k, '<br/>'.join( v for v in sorted(md[k]) )
                ))
    
    return detail_list and '<div class="details">' + ''.join(detail_list) + '</div>' or ''

def render_chain(chain, seen=None):
    """Render a single chain.
    
    The only parameter supplied when the method is externally invoked is the chain. Your
    renderer is free to declare additional parameters for internal use, assuming that
    you choose to implement using recursion. ;-) We do that here with the seen parameter
    for loop detection.
    """
    if seen is None:
        seen = set()
    else:
        seen = seen.copy()
    if chain.artifact in seen:
        return muted(chain.artifact, not chain.is_target)
    seen.add(chain.artifact)
    return ''.join([
              '<div class="artifact">',
              muted(chain.artifact, not chain.is_target),
              details(chain),
              '</div>',
              chain.children and '&nbsp;&rarr; ' or '',
              '<div class="iblock">',
                '<br/>'.join((render_chain(element,seen) for element in sorted(chain.children,key=lambda x:x.artifact))),
              '</div>'
        ])
