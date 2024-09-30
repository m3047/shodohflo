# `pcap_agent` Notes

This document discusses the extended capabilities for filtering and port / service attribution available by configuring
`NETWORK_ENUMERATION` and `FLOW_MAPPING`.

I have several (sub)networks, and two servers with multiple network interfaces. I run instances of the `pcap_agent` listening
to all interfaces on `bert` but only internal interfaces on `ernie`. They write to locally hosted instances of _Redis_ 
(which have [RKVDNS](https://github.com/m3047/rkvdns) in front of them, but that's another story).

I don't run an agent instance listening to `ernie`'s external interface, although I could; it would be noisy because all of the internal hosts
are NATted through this host.

Names and addresses have been changed. It should be understood that the `10.0.0.0` addresses are real, routable internet addresses
in the actual deployment. By default the agent captures all flows it sees to or from our networks and decides service attribution
based on the _lower port number_ heuristic.

I strongly encourage you to review the pydoc for [`shodohflo.pcap_config`](../shodohflo/pcap_config.py).

```
from shodohflo.pcap_config import NetworkEnumeration, FlowMapping, \
                                  OUR_4NETS, SRC, DST, Assign, LowerPort

NETWORK_ENUMERATION = NetworkEnumeration(
            (   'our_nets',      OUR_4NETS          ),
            (   'bert',         '10.0.0.1/32'       ),
            (   'ernie',        '10.0.0.2/32'       ),
            (   'external',     '0.0.0.0/0'         )
        )
FLOW_MAPPING = FlowMapping(
            (    None,      'our_nets',     LowerPort( SRC )                            ),
            (   'our_nets',  None,          LowerPort( DST )                            ),
            (   'external', 'bert',         Assign( DST, SRC, { 53 }, drop=True )       ),
            (   'external', 'bert',         Assign( SRC, DST, { 80, 443 }, drop=True )  ),
            (    None,      'bert',         LowerPort()                                 ),
            (    None,      'ernie',        LowerPort()                                 )
        )
```

### `our_nets`

`our_nets` picks up the command line argument when the agent is started. It encompasses all of the subnets a particular machine can see.

It might be tempting or seem like a good idea to start with a rule just mapping between hosts on `our_nets`:

```
( 'our_nets', 'our_nets',  MappingAction() )
```

but this is unnecessary because we are interested in all flows involving one of the hosts on our networks.

We define two rules to accomplish that:

  * Anything talking to a host on our networks.
  * A host on our network talking to anything.

There are three mapping actions available, but we only use two here:

   * `PortMatch`: service address (source or destination) is determined by which end has a matching port.
   * `Assign`: service address (source or destination) is explicitly determined
   * `LowerPort`: uses the heuristic that whether the source or destination is the service address is determined by the heuristic that the lower port number represents the service address.

In this case we use the `LowerPort` heuristic. The argument (`SRC` or `DST`) is probably superfluous here, it specifies which end of the
should be considered the service address in the case where the source and destination ports are the same. Nonetheless, it reflects
a presumption that lacking any other priors, we presume that the hosts on our network are clients and the service is external.

### Dropping traffic to external DNS servers

The local recursive resolver runs on `bert` and makes many external DNS requests. This activity is logged elsewhere so knowing the
servers which are contacted is not needed. We use the `Assign` action to drop traffic from external addresses
with a source port of `53`. We don't need a companion rule going the other way because _the agent only captures traffic received by the interface._

### Dropping external clients accessing resources we host

`bert` also offers public web services, and likewise the traffic is logged elsewhere. This traffic is going the other direction, but we
still only capture incoming traffic so in this case traffic with a destination port of `80` or `443` is dropped.

### Capturing traffic destined for the VM hosts' external addresses

There is some upstream firewall filtering, and an additional feature of the agent comes into play: _TCP connections are determined solely based
on payload packets_ which is to say without the `SYN` or `FIN` flags.

`athena` is pretty straightforward. It shouldn't be getting any external traffic other than DNS and HTTP(S). If there is any other traffic we want
the flows captured.

`ernie` is more subtle. As noted we don't run the agent on its external interface because it would be too noisy. But if we were seeing its
external address on any of the internal networks we'd want to know about it.
