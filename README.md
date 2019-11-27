# Prologue

There's a perfectly good _dnstap_ dissector here. You'll find it in `shodohflo/`, with an example: `examples/tap_example.py`.

Look in `app/` for screenshots from the web reporting interface.

# shodohflo

This a DNS and netflow (IP address) correlator. _DNS_ is the service which turns a web site name into an address which your computer can connect to (it also does other things, and has indirection). A _netflow_ is the observed fact of two computers at different addresses exchanging data. Typically a DNS lookup is done to find the address, and then a connection with the address is created and data is exchanged. It's possible for an application to explicitly connect with an address without performing a DNS lookup.

It also includes pure Python implementations of Frame Streams and Protobuf, useful in their own right.

_Dnstap_ is a technology for DNS traffic capture within a DNS server, therefore capturing both UDP and TCP queries and responses with fidelity. http://dnstap.info/

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
1. Make sure your DNS server is compiled with _dnstap_ and configured to write to a unix domain socket.
1. Make sure that `SOCKET_ADDRESS` in `tap_example.py` references the socket location.
1. You should be able to run the `tap_example.py` program.
1. You can symlink / move / copy the `shodohflo` package wherever you wish.

You can find additional pointers in the `install/` directory.

### Agents

There are two agents, one for packet capture and one for DNS traffic (using _dnstap_). Both of them write to _Redis_.

1. Follow the instructions in the `install/` directory.
1. Review the README in the `agents/` directory and copy `configuration_sample.py` to `configuration.py`.
1. Look in `install/systemd/` for service scripts and review the README there.

### The ShoDoHFlo app

This is a browser-based DNS and netflow correlator.

1. Follow the instructions in the `install/` directory
1. Review the README in the `app/` directory and copy `configuration_sample.py` to `configuration.py`.
1. To run the app run `app.py` with _Python 3_.

## Examples

`tap_example.py` is a working example of listening to a Unix domain socket receiving _dnstap_ data and
has no dependencies beyond those for core components.

There are other examples as well, look in the `examples/` directory.

## Collaborators welcomed!

Send me an email, or file an issue or PR.

Please look at [proposed issues](https://github.com/m3047/shodohflo/issues?q=is%3Aissue+is%3Aopen+label%3Aproposal) and give feedback, vote them up or down (+1 / -1), or submit one of your own. Proposals won't be worked on without some third party expression of interest.
