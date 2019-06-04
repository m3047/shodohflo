# Prologue

There's a perfectly good _dnstap_ dissector here. You'll find it in `shodohflo/`, with an example: `examples/tap_example.py`.

# shodohflo

Ultimately this is going to be a DNS and netflow (IP address) correlator. It also includes pure Python implementations of Frame Streams and Protobuf, useful in their own right.

_Dnstap_ is a technology for DNS traffic capture within a DNS server, therefore capturing both UDP and TCP queries and responses with fidelity. http://dnstap.info/

## Prerequisites

Aside from standard libraries the only dependencies for the core `shodoflo` package components are:

* Python 3
* dnspython

Additionally for the `app/` (under construction) additional anticipated dependencies are:

* redis
* dpkt
* flask
* flask_restful

It is developed and tested on _Linux_. In particular the agents will likely not run except on _Linux_.

## Examples

`tap_example.py` is a working example of listening to a Unix domain socket receiving _dnstap_ data and
has no dependencies beyond those for core components.

## Collaborators welcomed!

Send me an email, or file an issue or PR.
