# Tactical Code: Using ShoDoHFlo for Dynamic Analysis

ShoDoHFlo is a DNS and netflow correlator written in Python which consists of DNS and packet capture agents
feeding a Redis database, and a web-based client for visualizing relationships between the two. Looking at
DNS and netflows is a fundamental part of _Dynamic Analysis 101_.

We've probably all run code we shouldn't have, when we shouldn't have. The difference between us trained
professionals and the masses is that in the words of Peewee Herman, we "meant to do that". Sure malware
detonation sandboxes are great, I carry one around with me all the time... not! Or to put it another way,
maybe you didn't know you were running a sandbox until just a minute ago; at this very moment you're
reaching for Wireshark....

Well, ShoDoHFlo is not a time machine so a little forethought is required, although if you're reaching for
Wireshark right now I feel your pain. Next time you'll have Wireshark running beforehand, right? Maybe
you'll have ShoDoHFlo running, too. Let me show you why and how.

Wireshark is going to show you the event correlations: first it reached out to this host, then it did
some DNS lookups, and then it connected there and so on. But it doesn't connect these artifacts
semantically. I suppose that's what the TIP is for... too bad I left it on the USB drive with the malware
sandbox.

What ShoDoHFlo adds to your picture is:

* What IP addresses resolved to in the DNS.
* IP addresses which failed to resolve in the DNS.
* IP addresses for which no resolution in the DNS was attempted.
* What DNS resolutions were, regardless of whether the client attempted contact or not.

### The hardest part of setting it up is getting a caching resolver which supports Dnstap.

You're probably not going to find support compiled into BIND in your off the shelf Linux distro,
you'll have to compile BIND yourself. (Or some other caching resolver.) It's really pretty easy, when
you run configure for BIND, you need to specify `--enable-dnstap`, probably like this:

    ./configure --with-libtool --enable-dnstap

There are some prerequisites for frame streams and protobuf. You can look at this Dockerfile for inspiration.

### Where and how to run the DNS Agent

Whatever you're going to run has to be configured to use the caching resolver which you just deployed.
This is typically done with DHCP telling the client where to find a resolver at the same time that it
hands it an IP address to use.

Run the agent on the machine running the caching resolver.

Where to run the caching resolver?

You could use it for the entire local network; just sayin'. In which case, you'd probably install it
on a gateway box or in your DMZ. Or if your sandbox really is a virtual machine, then you could run
it on the physical host.

You can run it almost anywhere that is reachable inside your NAT horizon, and manually configure it
on hosts as needed or in a special "radioactive" DHCP lease pool.

### Where and how to run the Packet Capture Agent

I suppose in a perfect world you'd have it running listening to a promiscuous port on the switch,
inside your network. It needs to run inside your network so that it has visibility inside your NAT horizon.
If you are using a Linux host as your router / gateway then you'd run it there, listening to the 
internal interface. If your sandbox really is a virtual machine, then you'd probably run it on the physical
interface connecting the host to the local network, however this can result in all traffic from the virtual
machine being reported as coming from the host; there may be a virtual interface to attach to, depending on
how your virtualization environment works and how networking is set up.

### Running the App

You can run the app (without authentication and encryption) by simply running the python script. By
default it will bind to localhost and look for Redis locally as well; if Redis is running on the host
where you're attempting to run the browser, that should just work right out of the box.

As long as Redis is available and collecting data (minimally restricted to only accept input from
the hosts running the agents), you don't need to run the app until you need it. If you want to leave
the app running, then securing it as well as Redis is an exercise for the reader, and subject to your
appetite for risk.

### Other odds and ends

**How long does it keep data?** By default, Redis keeps data for a minimum of 15 minutes. Depending
on your use case, you may want to adjust `TTL_GRACE`.

**Recipes, scripts, etc.** I'll accept (Apache 2.0 licensed) contributions on GitHub.

I welcome your comments, and I'll be happy to repost this somewhere else if you think
that would be helpful. 