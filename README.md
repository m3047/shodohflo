# Prologue

There's a perfectly good _dnstap_ dissector here. You'll find it in `shodohflo/`, with an example: `examples/tap_example.py`.

Look in `app/` for screenshots from the web reporting interface. At this point I consider the web interface to be mostly of
historical interest.

**Dnstap Reloaded (July 2026):** Major work has been done (collectively) on `exampless/dnstap2json.py` as well as on the Dnstap telemetry
pipeline including `agents/dnstap_agent.py`, `agents/dns_agent.py`, and [the Rear View RPZ agent](https://github.com/m3047/rear_view_rpz).
___See___ [DNSTAP_RELOADED.md](DNSTAP_RELOADED.md).

# shodohflo

This a DNS and netflow (IP address) correlator. _DNS_ is the service which turns a web site name into an address which
your computer can connect to (it also does other things, and has indirection). A _netflow_ is the observed fact of two
computers at different addresses exchanging data. Typically a DNS lookup is done to find the address, and then a
connection with the address is created and data is exchanged. It's possible for an application to explicitly connect
with an address without performing a DNS lookup.

It also includes pure Python implementations of Frame Streams and Protobuf, useful in their own right.

_Dnstap_ is a technology for DNS traffic capture within a DNS server, therefore capturing both UDP and TCP queries and
responses with fidelity. http://dnstap.info/

## Prerequisites

Aside from standard libraries the only dependencies for the core `shodohflo` package components are:

* Python 3
* dnspython

Dependencies for the agents are:

* dnspython (mandatory for the dns agent, optional for pcap)
* dpkt (mandatory for pcap)
* a local caching resolver compiled with _dnstap_ support (mandatory for dns)
* redis

Dependencies for the `app/` at the present time (may change in the future) are:

* redis
* dnspython (optional)
* flask

It is developed and tested on _Linux_. In particular the agents will likely not run except on _Linux_.

## Installation

### `shodohflo` package (Dnstap listener)

This is a pure python _dnstap_ protocol implementation for _Linux_, with potentially reusable _frame streams_
and _protocol buffer_ implementations.

1. Download or clone the repo.
1. Make sure the _dnspython_ package is installed (see _PyPI.org_)
1. Make sure your DNS server is compiled with _dnstap_ and configured to write `CLIENT_RESPONSE` messages to a unix domain socket.
1. Make sure that `SOCKET_ADDRESS` in `tap_example.py` references the socket location.
1. You should be able to run the `tap_example.py` program.
1. You can symlink / move / copy the `shodohflo` package wherever you wish.

You can find additional pointers in the `install/` directory.

### Agents

There are three agents: one to write packet capture / netflow data to _Redis_, one to consume _Dnstap_ telemetry
and convert it to UDP datagrams, one to take those datagrams and write them to _Redis_.

1. Follow the instructions in the `install/` directory.
1. Review the README in the `agents/` directory and copy `configuration_sample.py` to `configuration.py`.
1. Look in `install/systemd/` for service scripts and review the README there.

### The ShoDoHFlo app

This is a browser-based DNS and netflow correlator, mostly of historical interest.

1. Follow the instructions in the `install/` directory
1. Review the README in the `app/` directory and copy `configuration_sample.py` to `configuration.py`.
1. To run the app run `app.py` with _Python 3_.

## Examples

* `tap_example.py` is a working example of listening to a Unix domain socket receiving _dnstap_ data and
has no dependencies beyond those for core components.
* `dnstap2json.py` is a "ready to eat" customizable example of converting selected Dnstap data to JSON and writing that to STDOUT / a UDP socket asynchronously, and `agents/dnstap_agent.py` is subclassed from it.

Look in the `examples/` directory.

## Collaborators welcomed!

Send me an email, or file an issue or PR.

Please look at [proposed issues](https://github.com/m3047/shodohflo/issues?q=is%3Aissue+is%3Aopen+label%3Aproposal) and give feedback, vote them up or down (+1 / -1), or submit one of your own. Proposals won't be worked on without some third party expression of interest.

## Versioning

This code has always had _revision control_ but until September 2026 it didn't have explicit _versioning_. This is when `pyproject.toml`
was added to the trunk at [3229307](https://github.com/m3047/shodohflo/commit/3229307b54c7378d7153104efc88f96d7a7addbc)
(see [PR #15](https://github.com/m3047/shodohflo/pull/15)).

___The trunk / `master` was, is, and remains the "system of record"___. Work will continue to be done on branches with the expectation that
what's committed to the trunk is safe to eat. That said, having `pyproject.toml` implies versioning from which it follows that
the project needs a _versioning policy_.

__Version history__ will be tracked in this file (below) according to the `pyproject.toml` version on `master`. The version history
here will be kept up to date with the version in `pyproject.toml`

__Versioning__ will follow the `<breaking change>.<API change>.<functional change>` paradigm.

* _Breaking changes_ MUST always be memorialized in the version history.
* _API changes_ SHOULD be memorialized in the version history.
* _Functional changes_ SHOULD be memorialized if deemed potentially visible and of interest outside of this project.

__Versioned artifacts__ are:

* the `shodohflo` package / library tree, e.g. `shodohflo.fstrm` and `shodohflo.protobuf.dnstap`
* `agents/*.py`
* `examples/dnstap2json.py`

The rationale for including the artifacts in `agents` along with `dnstap2json.py` is that these constitute the actual working
reference implementations based upon the `shodohflo` package / tree, their behavior is closely tied to the
package tree, and external projects rely on them.

__The Version__ will be the one expressed by the setting of `project.version` in `pyproject.toml` in `master`.

### Version history

**0.1.0** Initial version merged from PR #15.
