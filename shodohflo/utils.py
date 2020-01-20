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

#
# Statistics.
#

class RingBuffer(object):
    """Used for things which need to be averaged."""

    # Ostensibly each bucket is for 1 second of data. A few extra buckets guarantees us
    # a full minute's worth of complete data.
    BUCKETS = 63
    ONE = 1
    TEN = 10
    SIXTY = 60

    def __init__(self, zero=0):
        self.buffer = [zero] * self.BUCKETS
        self.index = 0
        self.current_second = int(time())
        self.zero = zero
        return
    
    def retire_bucket(self):
        """To be overridden by subclasses to finalize a retiring bucket."""
        pass
    
    def update_bucket(self, value):
        """To be overridden by subclasses to update a bucket with an additional value."""
        pass
    
    def retire_elapsed_buckets(self, n):
        for i in range(n):
            self.retire_bucket()
            self.index += 1
            if self.index >= len(self.buffer):
                self.index = 0
            self.buffer[self.index] = self.zero
        return
            
    def add(self, value):
        """This is what you call with new data!"""
        now_seconds = int(time())
        elapsed_seconds = now_seconds - self.current_second
        if elapsed_seconds:
            self.retire_elapsed_buckets(elapsed_seconds)
        self.update_bucket(value)
        self.current_second = now_seconds
        return
    
    def stats(self):
        """Return a statistics summary."""
        j = self.index - 1
        if j < 0:
            j = len(self.buffer) - 1
        v = self.buffer[j]
        minimum = v
        maximum = v
        accum = v
        one = v
        for i in range(self.TEN - self.ONE):
            j -= 1
            if j < 0:
                j = len(self.buffer) - 1
            v = self.buffer[j]
            if minimum > v:
                minimum = v
            if maximum < v:
                maximum = v
            accum += v
        ten = accum / self.TEN
        for i in range(self.SIXTY - self.TEN):
            j -= 1
            if j < 0:
                j = len(self.buffer) - 1
            v = self.buffer[j]
            if minimum > v:
                minimum = v
            if maximum < v:
                maximum = v
            accum += v
        sixty = accum / self.SIXTY
        return dict(minimum=minimum, maximum=maximum, one=one, ten=ten, sixty=sixty)
            
class AveragingRingBuffer(RingBuffer):
    def __init__(self, zero=0):
        RingBuffer.__init__(self, zero)
        self.count = 0
        return
    
    def retire_bucket(self):
        if self.count:
            self.buffer[self.index] /= self.count
        self.count = 0
        return
    
    def update_bucket(self, value):
        self.buffer[self.index] += value
        self.count += 1
        return

class LevelingRingBuffer(RingBuffer):
    def __init__(self, zero=0):
        RingBuffer.__init__(self, zero)
        self.accum = zero
        return
    
    def retire_bucket(self):
        self.buffer[self.index] = self.accum
        return
    
    def update_bucket(self, value):
        self.accum += value
        return
    
class CountingRingBuffer(RingBuffer):
    def retire_bucket(self):
        return
    
    def update_bucket(self, value):
        self.buffer[self.index] += value
        return
    
class StatisticsTimer(object):
    """A thing that a StatisticsCollector produces for context while timing."""

    def __init__(self, collector):
        self.collector = collector
        self.start = time()
        return
    
    def stop(self):
        self.collector.stop_timer(time() - self.start)
        return

class StatisticsCollector(object):
    """Collect statistics over time about something and be able to report about it.
    
    (Thread safe) locking is used, although we're never actually going to do anything
    which releases the GIL in a critical section.
    """
    
    def __init__(self, name):
        self.name = name
        self.elapsed_time = AveragingRingBuffer(0.0)
        self.depth = LevelingRingBuffer(0)
        self.n_per_sec = CountingRingBuffer(0)
        self.lock = Lock()
        return
        
    def start_timer(self):
        self.lock.acquire()
        self.depth.add(1)
        self.n_per_sec.add(1)
        self.lock.release()
        return StatisticsTimer(self)
    
    def stop_timer(self, elapsed):
        """Called by expiring StatisticsTimers."""
        self.lock.acquire()
        self.elapsed_time.add(elapsed)
        self.depth.add(-1)
        self.lock.release()
        return
    
    def stats(self):
        self.lock.acquire()
        statistics = dict( name=self.name,
                           elapsed=self.elapsed_time.stats(),
                           depth=self.depth.stats(),
                           n_per_sec=self.n_per_sec.stats()
                         )
        self.lock.release()
        return statistics

class StatisticsFactory(object):
    """Create federated statistics so that they can be reported on and managed together."""

    def __init__(self, collector=StatisticsCollector):
        self.collectors = []
        self.collector = collector
        return
    
    def Collector(self, name):
        """Allocates a collector with the supplied name."""
        collector = self.collector(name)
        self.collectors.append(collector)
        return collector

    def stats(self):
        return [ collector.stats() for collector in self.collectors ]