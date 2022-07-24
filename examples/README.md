### Using it with _BIND_

_BIND_ needs to be built with _dnstap_ support. **NOTE**: The ISC (https://www.isc.org/bind/) packages are
built with _dnstap_ and _RPZ_ support.

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

### Using it with _Unbound_

Using it with _Unbound_ is similar:

```
./configure --enable-dnstap
```

Make sure you meet the prerequisites first. In particular be aware that _protobuf_ comprises a library,
a compiler program, and another library. You need "dev" packages for everything which is "lib", not just
protobuf.

Configuring the socket would look like:

```
dnstap:
    dnstap-enable: yes
    dnstap-bidirectional: yes
    dnstap-socket-path: /tmp/dnstap
    dnstap-log-client-response-messages: yes
```

**Permissions:** _Unbound_ does a crappy job logging issues with permissions on the Unix socket.
Make sure that both _Unbound_ and the client tool have read and write access to it.

### tap_example.py

`tap_example.py` captures and displays data written to a unix domain socket in _dnstap_ format.

You should first `cp configuration_sample.py configuration.py` and modify appropriately.

### dnstap2json.py

This program writes line-oriented JSON to either STDOUT or a UDP socket. The JSON is intended to be
customizable, see the internal documentation (`pydoc3 dnstap2json.JSONMapper` ).

Run it, listening to the domain socket `/tmp/dnstap`, outputting to STDOUT:

```
./dnstap2json.py /tmp/dnstap
```

Run it, outputting to 127.0.0.1:3047 (UDP):

```
./dnstap2json.py /tmp/dnstap 127.0.0.1:3047
```

Listening for UDP data can be as simple as:

```
nc -luk 127.0.0.1 3047
```

### Other examples

There are other examples as well.

* `count_client_keys.py` Returns some statistics about Redis keys associated with client addresses. You should first `cp configuration_sample.py configuration.py` and modify appropriately.
* `../agents/dns_agent.py` Uses a `ThreadPoolExecutor` (with a pool size of 1) to write _Dnstap_ data to Redis.
