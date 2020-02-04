#!/usr/bin/python3
# Copyright (c) 2020 by Fred Morris Tacoma WA
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

"""Various utility things."""

from time import time
from threading import Lock

class Recent(object):
    """Tracks recently seen things."""
    def __init__(self, cycle=30, buckets=3, frequency=10):
        self.buckets = [ set() for i in range(buckets) ]
        self.working_set = set()
        self.current = self.buckets[0]
        self.last_time = time()
        self.cycle = cycle
        self.frequency = frequency
        self.count = 0
        return
    
    def check_frequency(self):
        """Algorithm to age stuff out of the recent cache."""
        self.count += 1
        if self.count < self.frequency:
            return
        self.count = 0
        now = time()
        if (now - self.last_time) < self.cycle:
            return
        self.last_time = now
        discard = self.buckets.pop()
        working_set = set()
        for bucket in self.buckets:
            working_set |= bucket
        self.working_set = working_set
        self.current = set()
        self.buckets.insert(0, self.current)
        return
    
    def seen(self, thing):
        self.check_frequency()
        if thing in self.working_set:
            return True
        self.working_set.add(thing)
        self.current.add(thing)
        return False

class Once(object):
    """Tests True the first time it's tested, False after."""
    def __init__(self):
        self.count = 1
        return
    
    def __call__(self):
        self.count -= 1
        return self.count >= 0
