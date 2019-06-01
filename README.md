# shodohflo

Ultimately this is going to be a DNS and netflow (IP address) correlator. It also includes pure Python implementations of Frame Streams and Protobuf, useful in their own right.

_Dnstap_ is a technology for DNS traffic capture within a DNS server, therefore capturing both UDP and TCP queries and responses with fidelity. http://dnstap.info/

## Prerequisites

Aside from standard libraries the only dependencies are:

* Python 3
* dnspython

It is developed and tested on Linux.

## Examples

`tap_example.py` is a working example of listening to a Unix domain socket receiving _dnstap_ data.
