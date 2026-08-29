# `dnstap2json` and `dnstap_agent`... Reloaded!

July 2026

**What's going on?**

Major changes have been made to both `examples/dnstap2json.py` and `agents/dnstap_agent.py`. Hopefully these changes will
improve your workflow in the long run. If you're just taking the output of `dnstap2json.py` or `dnstap_agent.py` at _face value_
(as Sherry Turckle might say) you can keep on, keepin' on.

On the `fwm` branch this is still a work in progress.

## Changes, Changes

### Code changes

#### `FieldMapping` handlers

If you've written your own `FieldMapping` handlers: `p.field('response_message')` now returns a tuple of (`dns.message`, _raw data_),
so references need to change from `p.field('response_message')[1]` to `p.field('response_message')[1][0]`. This only affects
protobuf fields which are type `DnsMessageField`. See `shodohflo/protobuf/dnstap.py` for further information.

#### `build_resolution_chain()` in particular

The algorithm has been changed:

* performs some temporally limited caching across upstream events
* backfills, and forward fills, from the cache

If you need the previous behavior, you may want to replace it with an earlier version (mind the `response_message` issue
mentioned above).

#### `bkf` field

There is an additional field in the JSON output: `bkf`. This is the count of backfilled (as opposed to forward) references.
See the following _Semantic changes_ section for further details.

Used to be that you could presume that whatever was at `chain[-1]` in the JSON was the query name. Now the correct
reference for the actual query name is `chain[-1*(1+bkf)]`.

#### some things didn't happen

I mused about processing field mappings as _coroutines_, so that they could implicitly depend on each other. That ran into
architectural issues (below); therefore I mused about `requires` as a `FieldMapping` attribute... that might still happen
someday.

The architectural issue with delaying processing is that events get an `id`, and receiving code relies on "the number only
goes up" for integrity... or at least nagging rights. Some people are implementing much more rigid verification and I
presume it is also ordered, didn't want to mess that up.

### Semantic changes

Things in the monitored environment have changed, other things which are theoretically changing... not so much or so fast or they're still being
studied (or mumble).

From the perspective of DNS, what drove me to create ShoDoHFlo was, is, and remains: ___track what FQDNs resolve to in a fashion which is
easily consumable via automation___. Other things were, and remain, important: ___what client requested resolution for a
particular FQDN?___ (because you can correlate it with netflows)

These two objectives were largely synonymous, but changes in the environment are straining that equivalence. In particular:

* apps which ship with self-contained caching + recursing resolvers
* "6+4" / "happy eyeballs" (gratuitous DNS requests because somebody just discovered DNS)
* `SVCB` compatible types

My views on the foregoing are undeniably political, and nuanced. If you want further details or discussion... reach out!
You don't have to agree with me, I write opinionated software for opinionated people: it comes with the territory.

**Bottom line:** Emitted event data is no longer bounded by a single upstream Dnstap event, it can be informed by
information from multiple upstream events.

There is a presumption that if a query name can be backfilled, then whatever was backfilled represents the user's
actual _intent_ but this signal has been subjected to intermediation upstream of the resolver providing us with
Dnstap data.

### `SVCB` Compatible types

This includes `HTTPS`. These are similar to `CNAME` records for our purposes, and can be located at the end of `CNAME`
chains, and can beget further `A` and `AAAA` queries in particular which can also result in `CNAME` chains. This is
the promise, but it's not what's seen in the wild today. Basically `HTTPS` records are utilized today in a fetishistic
performance to avoid some small actual HTTP overhead. Still they do exist, and they're being queried for, and it
loads the cache up, etc.

`dnstap2json` includes an implementation of `SVCB` to support older versions of dnspython, work is ongoing.

I welcome your thoughts.

## _Capture_ and _Replay_: New Functionality to Support Your Workflow

`dnstap2json.py` supports capture and replay, although the implementation is more mature in `dnstap_agent.py`. (It's not
that different, either will replay the other's captures.) What this is:

* Raw Dnstap frames can be written to a UDP datagram sink, and then presumably to a file.
* The file containing these frames can be replayed.

This is intended primarily for development and debugging, although I won't be surprised if somebody finds other uses.

## The Workflow

`dnstap2json` and `dnstap_agent` are ___intended to be useful from initial Dnstap tasting, into production, until you truly need
something more performant (which might be longer than you think)___

_This is something of a biased random walk, two steps forward and one step back..._

**Tasting** You set up _BIND_ or _Unbound_ with Dnstap enabled, and answer a few basic questions: Is it working? What
does the data actually look like?

```
cd examples; cp configuration_sample.py configuration.py; ./dnstap2json.py /tmp/dnstap
```

...assuming that `/tmp/dnstap` is the unix socket Dnstap data is being written to.

**Customizing** You have a use in mind, and the data coming out of either `dnstap2json` or `dnstap_agent` isn't what you need.
Maybe you want something besides JSON. The intention is that you can accomplish this by subclassing `JSONMapper` and overriding
parts of it, or by overriding `Dnstap.consume()`. `agents/dnstap_agent.py` subclasses `examples/dnstap2json.py`, look there
for a sense of the lift.

**Operationalizing** You don't have a use in mind, but you really want to get the data into some kind of store, why not
Redis? Maybe a proof of concept. Look around in `agents/`: set up `dnstap_agent` and `dns_agent`, and you can get it into your Redis database.
Maybe you'll want to set up some instances of `pcap_agent` listening on select interfaces so you can correlate DNS
activity with netflows.

**Pub-Sub** Setting up `dnstap_agent` and `dns_agent` in the previous section relies on _UDP datagrams_, a form of message delivery
which operates at the level of the network stack. It's _connectionless_, and supports _many senders to one receiver_
as the default. So you can send the output from multiple Dnstap sources / servers, to a central collection point.
`dnstap_agent` also supports _multicast datagrams_ a special addressing scheme which enables _many senders
**and many** receivers_... at the network level! I know it sounds incredible, but it's true! I apologize for the
sarcasm.

You're also welcome, and encouraged, to point it at your own automated data pipelines; maybe _multicast_ will
inspire you.

**What Else?** ShoDoHFlo is part of "Poor Fred's SIEM", a notion which also includes [Rear View RPZ](https://github.com/m3047/rear_view_rpz)
and [RKVDNS](https://github.com/m3047/rkvdns). If you're to this point I've got additional docs and whatnot if you reach out and introduce yourself.

**The Loop** At some point you're going to get into a testing situation related to something going on in production.
Odds are this will be related in some fashion to the inputs, or particularly the Dnstap data for our purposes here.
`JSONMapper.filter_raw()` makes it possible to select Dnstap frames matching whatever criteria are of interest
so that they can be written to a different UDP socket, where presumably something listening can write them to a
file or database. That file can then be replayed by `dnstap2json` (or `dnstap_agent`) to test code operation within
`dnstap2json`, or to generate test data for some downstream process.
