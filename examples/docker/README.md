### Building a Docker Image

1. Copy a _BIND_ source tarball into this directory and name it `bind.tgz`.
1. From the root directory for this repository, run `docker build -t shodohflo -f examples/docker/Dockerfile .`
1. Run the image: `docker run -it --name shodohflo -p 3047:3047/tcp shodohflo:latest bash`

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

Best thing to do is to launch two containers, naming one `server` and the other `client`. On `server` specify
`-p 3047:3047/tcp` to `docker run`; don't specify this on the `client`. (Only one of them can map the port.)

**HINT:** To get the address of the server, run `ip a` and look for the `fc00:1:...` address.

On `server`:

Run `named -d2`. If for some reason it won't run add `-g` to keep it in the forground and have it log everything
to the console.

To run the _Redis_ server, run `redis-server &` (this will background it).

#### DNS agent

Run `/usr/local/share/shodohflo/agent/dns_agent.py`. (You can background it or not.)

On the client run `dig @<server-ip6-address> machine-a.test aaaa`

#### Packet capture agent

Run `/usr/local/share/shodohflo/agent/pcap_agent.py eth0 <server-ip6-address>`. (You can background it or not.)

On the client run `dig @<server-ip6-address> machine-a.test aaaa` to test UDP capture. To test TCP capture, append `+tcp`
to the command.

#### Web app

Run `/usr/local/share/shodohflo/app/app.py`. You should be able to point a browser at http://localhost:3047/ on the
host machine.
