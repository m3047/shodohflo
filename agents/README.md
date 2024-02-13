The agents in this directory capture information and forward it to a _Redis_ instance or, in the
case of DNS data, potentially to other consumers.

Before attempting to run any of them `cp configuration_sample.py configuration.py` and make
whatever edits are appropriate.

### dnstap_agent.py

This needs to run on the host running your local caching resolver, which has been compiled with _dnstap_ support.
We assume that your local resolver is inside of your _NAT_ horizon.

You can look in the `examples/` directory for a little more information about _dnstap_ and using it with _BIND_.

You can run it in basic mode using command line arguments. The following configuration parameters are relevant:

* `SOCKET_ADDRESS`
* `LOG_LEVEL`
* `DNSTAP_STATS`
* `DNS_CHANNEL`
* `DNS_MULTICAST_LOOPBACK`
* `DNS_MULTICAST_TTL`

#### expects only CLIENT_RESPONSE messages

For best performance, this script expects only CLIENT_RESPONSE type messages (see the DnsTap documentation).
Expected configuration in `named.conf` looks like:

```
dnstap { client response; };
dnstap-output unix "/tmp/dnstap";
```

If you fail to do this then a warning message will be generated every time a new connection is extablished.

### dns_agent.py

Consumes `dnstap_agent.py` telemetry and updates _Redis_. The following configuration parameters are relevant:

* `REDIS_SERVER`
* `LOG_LEVEL`
* `TTL_GRACE`
* `DNS_STATS`
* `IGNORE_DNS`
* `DNS_CHANNEL`

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

The following configuration parameters are relevant:

* `REDIS_SERVER`
* `LOG_LEVEL`
* `TTL_GRACE`
* `PCAP_STATS`
* `IGNORE_FLOW`

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

### Multicast

The _Dnstap Agent_ (as well as the _DNS Agent_) supports _multicast_, allowing the same datagram to be
delivered to multiple consumers, as opposed to the normal _unicast_ where the packet is delivered to
a single consumer.

You don't need to configure anything at the system level to use multicast. A _multicast group_ looks
just like an IP address; you specify the group and a port as you would with a normal address.
When using multicast you also specify the interface to send or receive
datagrams on; you specify the interface by specifying the address bound to that interface.

You will probably want to randomly pick a multicast group from either `224.0.0.128/25`, `224.3.0.0/16`, or
`224.4.0.0/16`. The first block above is defined as locally scoped and not routed; the latter two are not. In that case
it is important to set a _TTL_ (time to live) for the packets. The TTL on IP packets is decremented at
each routing / forwarding point. The default is 1, meaning that traffic is confined to the LAN (or other
VMs on the same host).
