The agents in this directory capture information and forward it to a _Redis_ instance.

### dns_agent.py

This needs to run on the host running your local caching resolver, which has been compiled with _dnstap_ support.
We assume that your local resolver is inside of your _NAT_ horizon.

You can look in the `examples/` directory for a little more information about _dnstap_ and using it with _BIND_.

It takes no arguments, although you may need to alter `SOCKET_ADDRESS` or `REDIS_SERVER`.

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
