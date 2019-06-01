`tap_example.py` captures and displays data written to a unix domain socket in _dnstap_ format.

### Using it with _BIND_

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
