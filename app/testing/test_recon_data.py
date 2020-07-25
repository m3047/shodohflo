#!/usr/bin/python3
"""Test Recon data."""

import redis

if __name__ == "__main__":
    from configuration import *
else:
    REDIS_SERVER = 'localhost'
    USE_DNSPYTHON = False
    TTL_GRACE = 900

if USE_DNSPYTHON:
    import dns.resolver as resolver
    
def write(r, client_address, remote_address, ports, ptype):
    k = 'client;{}'.format(client_address)
    r.incr(k)
    r.expire(k, TTL_GRACE)
    k = "{};{};{};{}".format(client_address, remote_address, ports, ptype)
    r.incr(k)
    r.expire(k, TTL_GRACE)
    return

def main():
    if USE_DNSPYTHON:
        redis_server = resolver.query(REDIS_SERVER).response.answer[0][0].to_text()
    else:
        redis_server = REDIS_SERVER
    redis_client = redis.client.Redis(redis_server, decode_responses=True)

    write(redis_client, '10.1.0.201', '10.1.0.1', '33543:53', 'icmp')
    write(redis_client, '10.1.0.202', '10.1.0.1', '41345:53', 'rst')
    
    return

if __name__ == '__main__':
    main()
