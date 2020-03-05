### tap_example.py

`tap_example.py` captures and displays data written to a unix domain socket in _dnstap_ format.

You should first `cp configuration_sample.py configuration.py` and modify appropriately.

#### Using it with _BIND_

_BIND_ needs to be built with _dnstap_ support:

```
./configure --with-libtool --enable-dnstap
```

Basic configuration in `named.conf` might look like:

```
options {
    ...
    dnstap { all; };
    dnstap-output unix "/tmp/dnstap";
    ...
};
```

### Other examples

There are other examples as well.

* `count_client_keys.py` Returns some statistics about Redis keys associated with client addresses. You should first `cp configuration_sample.py configuration.py` and modify appropriately.
* `../agents/dns_agent.py` Uses a `ThreadPoolExecutor` (with a pool size of 1) to write _Dnstap_ data to Redis.
