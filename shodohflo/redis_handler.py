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

"""Redis Handler.

The Redis Handler is an asyncio event sink using a ThreadPoolExecutor to post to
Redis.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import redis

class RedisBaseHandler(object):
    """Handles calls to Redis so that they can be run in a different thread."""
    
    CONNECT_TIMEOUT = 5

    def redis_server(self):
        """Needs to be subclassed to return the address of the Redis server."""
        pass
    
    def __init__(self, event_loop, ttl_grace):
        self.redis = redis.client.Redis(self.redis_server(), decode_responses=True,
                                        socket_connect_timeout=self.CONNECT_TIMEOUT
                                       )
        # NOTE: Tried to do this with a BlockingConnectionPool but it refused to connect
        #       to anything but localhost. I don't think it matters, the ThreadPoolExecutor
        #       should limit the number of connections to the number of threads, which is 1.
                        #connection_pool=redis.connection.BlockingConnectionPool(
                            #max_connections=2,timeout=5)
                                       #)
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.event_loop = event_loop
        self.ttl_grace = ttl_grace
        # NOTE: This could be protected by a lock, but setting it True is final so it
        #       it doesn't really matter. Worst thing that happens is that multiple
        #       errors get logged. (Look at subclasses to see how this is used.)
        self.stop = False
        return
    
    def client_to_redis(self, client_address):
        """Called internally by the other *_to_redis() methods to update the client."""
        k = 'client;{}'.format(client_address)
        self.redis.incr(k)
        self.redis.expire(k, self.ttl_grace)
        return
    
    def submit(self, func, *args):
        """Submit a Redis update to run."""
        if self.stop:
            self.event_loop.stop()
            return
        self.event_loop.run_in_executor(self.executor, func, *args)
        return
    
    def redis_executor(self, func, *args):
        """Encapsulate exceptions which might occur within redis threads.
        
        All calling of Redis network functions is done inside of one of these
        blocks.
        """
        try:
            func(*args)
        except ConnectionError as e:
            if not self.stop:
                logging.error('redis.exceptions.ConnectionError: {}'.format(e))
                self.stop = True
        except Exception as e:
            if not self.stop:
                traceback.print_exc()
                self.stop = True
        return
