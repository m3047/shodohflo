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

"""Data for testing purposes."""

# Data in this section builds a chain.

chain_builder = dict(
        fish    = 'green,red',
        balloon = '',
        country = '',
        banana  = '',
        green   = 'fish',
        red     = 'balloon',
        one     = 'country,banana',
        two     = '',
        bar     = 'one',
        baz     = 'two,fish',
        foo     = 'bar,baz'
    )

def build_chain(root, built={}):
    if not root:
        return [ root, [] ]
    if root not in built:
        built[root] = [ root, [] ]
        built[root] = [ root, [ build_chain(element) for element in chain_builder[root].split(',') if element] ]
    return built[root]
