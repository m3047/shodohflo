### Building a Docker Image

1. Copy a _BIND_ source tarball into the directory containing this repository and name it `bind.tgz`.
1. From this directory, run `docker build -t shodohflo:latest ../../../` **NOTE:** this puts everything in the directory _CONTAINING_ the `shodohflo` repository in the build context which is not ideal.
1. Run the image: `docker run -it --name shodohflo shodohflo:latest bash`

#### IP6 support

It does indeed work with IP6! To get IP6 support with docker, you need to put something like this in
`/etc/docker/daemon.json`:

```
{
    "ipv6": true,
    "fixed-cidr-v6": "fc00:1::/64",
    "ip-forward": false
}

**There are two critical assumptions there:**

* You don't have a real IP6 network. ;-)
* That specifies an "allocated" private network, `fc00:1::/64`. You might need a different network.

### Testing with the Docker Image

Best thing to do is to launch two containers, naming one `server` and the other `client`. **HINT:** To get the
address of the server, run `ip a` and look for the `fc00:1:...` address.

On `server`:

Run `named -d2`. If for some reason it won't run add `-g` to keep it in the forground and have it log everything
to the console.

#### DNS agent

Run `/usr/local/share/shodohflo/agent/dns_agent.py`. (You can background it or not.)

On the client run `dig @<server-ip6-address> machine-a.test aaaa`

#### Packet capture agent

Run `/usr/local/share/shodohflo/agent/pcap_agent.py eth0 <server-ip6-address>`. (You can background it or not.)

On the client run `dig @<server-ip6-address> machine-a.test aaaa` to test UDP capture. To test TCP capture, append `+tcp`
to the command.
