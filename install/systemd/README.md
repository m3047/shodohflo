# Systemd service scripts

### dns-agent.service

Assumes that your DNS server's service is `named.service`.

If you didn't put the repository in `/usr/local/share/` you may have to adjust the `ExecStart` path.

### pcap-agent@.service

Assumes that Redis is present with a target of `redis.target`.

If you didn't put the repository in `/usr/local/share/` you may have to adjust the `ExecStart` path.

Assumes that the "our" network is `10.0.0.0/8`.

Start it with the name of the interface to listen on, e.g.:

```
systemctl start pcap-agent@eth0
```
