### tap_example.py

`tap_example.py` captures and displays data written to a unix domain socket in _dnstap_ format.

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

There are other examples in this directory as well. To run the other examples you
should first `cp configuration_sample.py configuration.py` and modify appropriately.

* `count_client_keys.py` Returns some statistics about redis keys associated with client addresses.
