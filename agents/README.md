The agents in this directory capture information and forward it to a _Redis_ instance.

Before attempting to run either of them `cp configuration_sample.py configuration.py` and make
whatever edits are appropriate.

### dns_agent.py

This needs to run on the host running your local caching resolver, which has been compiled with _dnstap_ support.
We assume that your local resolver is inside of your _NAT_ horizon.

You can look in the `examples/` directory for a little more information about _dnstap_ and using it with _BIND_.

It takes no arguments, although you may need to alter `SOCKET_ADDRESS` or `REDIS_SERVER`.

#### expects only CLIENT_RESPONSE messages

For best performance, the this script expects only CLIENT_RESPONSE type messages (see the DnsTap documentation).
Expected configuration in `named.conf` looks like:

```
dnstap { client response; };
dnstap-output unix "/tmp/dnstap";
```

If you fail to do this then a warning message will be generated every time a new connection is extablished.

### pcap_agent.py

Where you run this depends on your network topology. Due to the way it works it only captures traffic coming
_to_ whatever interface you specify. It looks for traffic in both directions, but the efficacy of that
just depends.

Assuming that your internal network is _NATted_, you want to run it somewhere which has visibility of your internal numbering
and on the internal (_NATted_) interfaces.

It takes two command line arguments:

```
pcap_agent.py <interface> <our-network>
```

Theoretically it will work with either IP4 or IP6, figuring that out from _our-network_; however it hasn't been
tested with IP6.

You may also need to alter `REDIS_SERVER`.

### socket.getaddrinfo() observed unreliable (June 2019)

_Redis_ calls `socket.getaddrinfo()` when a hostname is supplied. This has been observed to be case sensitive,
causing issues when using DNS resolution, because DNS is supposed to be case insensitive and `getaddrinfo()`
is not honoring that:

```
# python3
Python 3.6.5 (default, Mar 31 2018, 19:45:04) [GCC] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from socket import getaddrinfo
>>> getaddrinfo('sophia.m3047',6379)
[(<AddressFamily.AF_INET: 2>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('209.221.140.128', 6379)), (<AddressFamily.AF_INET: 2>, <SocketKind.SOCK_DGRAM: 2>, 17, '', ('209.221.140.128', 6379)), (<AddressFamily.AF_INET: 2>, <SocketKind.SOCK_RAW: 3>, 0, '', ('209.221.140.128', 6379))]
>>> getaddrinfo('SOPHIA.m3047',6379)
[(<AddressFamily.AF_INET: 2>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('10.0.0.224', 6379)), (<AddressFamily.AF_INET: 2>, <SocketKind.SOCK_DGRAM: 2>, 17, '', ('10.0.0.224', 6379)), (<AddressFamily.AF_INET: 2>, <SocketKind.SOCK_RAW: 3>, 0, '', ('10.0.0.224', 6379))]
>>> getaddrinfo('does-not-exist.m3047',6379)
[(<AddressFamily.AF_INET: 2>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('209.221.140.128', 6379)), (<AddressFamily.AF_INET: 2>, <SocketKind.SOCK_DGRAM: 2>, 17, '', ('209.221.140.128', 6379)), (<AddressFamily.AF_INET: 2>, <SocketKind.SOCK_RAW: 3>, 0, '', ('209.221.140.128', 6379))]
```

Both agents have an option to use _dnspython_ for hostname resolution by setting `USE_DNSPTYHON = True`. This
isn't an additional dependency for the DNS agent, but it is for the packet capture agent. Look in the
configuraton file for further information.

### Running at the command line

Both agents should be runnable at the command line, a capability which has been preserved for debugging / troubleshooting purposes. This assumes that everything is properly configured (and it's an easy way to find out!).

*DNS agent*

```
cd agents
./dns_agent.py
```

*Packet Capture agent*

```
cd agents
./pcap_agent.py <interface> <netmask-for-our-network>
```

Or for example:

```
./pcap_agent.py eth0 10.0.0.0/8
```

### Statistics

Both agents are instrumented and capable of periodically logging various statistics. How often statistics
are logged depends on the settings of `DNS_STATS` and `PCAP_STATS` respectively (how many seconds between reports).

Conceptually both agents follow much the same pipeline:

1. Receive data.
1. Initial filtering and processing.
1. Update Redis as necessary.

Complicating things somewhat, Redis, being blocking, is run in a thread pool. Statistics are gathered for
the following:

| category | DNS | PCAP |
| -------- | --- | ---- |
| backpressure in the listening connection | | `socket_recv` |
| initial filtering and processing | `consume` | `process_data` |
| updating Redis | `nx_to_redis`, `answer_to_redis` | `flow_to_redis` |
| pending queue for Redis | `redis_backlog` | `redis_backlog` |

The following statistics are gathered (which may or may not have meaning depending on context):

* *e*: average elapsed time per coprocess
* *n*: number of coprocesses per second
* *d*: active coprocesses of this type (queue depth)

The following time frames are given:

* *min*: minimum per second
* *max*: maximum per second
* *1*: most recent second
* *10*: average, most recent 10 seconds
* *60*: average, most recent 60 seconds

In general, as long as `d` stays reasonable (single digits) things are probably ok. `socket_recv` is
inverted, in that a value of `0` (or very close to `0`) means that there is data waiting to be read
immediately, or in other words data is being buffered in the network stack.
