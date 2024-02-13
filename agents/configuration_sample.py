# Used only by dns_agent.py
SOCKET_ADDRESS = '/tmp/dnstap'

REDIS_SERVER = 'localhost'
# WARNING! Redis translation of hostnames to addresses using DNS is unreliable
# because it calls socket.getaddrinfo() which in turn may exhibit incorrect case
# sensitivity. DNS is not supposed to be case sensitive.
#
# If you want to use hostnames and DNS, then you may want to set USE_DNSPTYHON
# to True. Of course, dnspython has to be installed. This isn't an issue with
# the DNS agent but the PCAP agent has no intrinsic dependency on it.
USE_DNSPYTHON = False

import logging
# Set this to a logging level to change it from the default of WARN.
# LOG_LEVEL = logging.INFO
LOG_LEVEL = None

# This sets the expire time for Redis entries.
TTL_GRACE = 900         # 15 minutes

# Number of seconds between performance logging events. Can be set individually
# for the PCAP and DNS agents. If set to None or 0 then no logging occurs. Events
# are logged at INFO level.
# PCAP_STATS = 600 # 10 minutes
PCAP_STATS = None
DNS_STATS = None
DNSTAP_STATS = None

# Strings to ignore in DNS traffic. Should be lowercased. Intended use is for stems,
# but bear in mind that because of seach lists if it doesn't find for example
# example.com, system will probably also try example.com.com, etc.
IGNORE_DNS = None
# Ignore anything containing test.example.com, such as server.test.example.com,
# server.test.example.com.example.com, server.test.example.com.com...:
# IGNORE_DNS = { 'test.example.com' }

# By default flows (but not recon artifacts) are suppressed for own network
# flows. Setting this to FALSE records all own network flows. Regardless,
# FLOWS ORIGINATING FROM THE MONITORED INTERFACE WILL NOT BE RECORDED. This
# technical limitation is discussed elsewhere.
# SUPPRESS_OWN_NETWORK = True

# Sometimes we have services which answer questions from local clients and which
# generate a nontrivial number of flows. IGNORE_FLOW allows you to define tuples
# which do not generate flows if they represent either end of the flow. This does
# not affect the recording of peers.
IGNORE_FLOW = None
# We have a nameserver on 10.0.11.23 which answers a lot of questions and we don't
# care to see it. We also have a web server which receives telemetry updates which
# we don't care to see.
# IGNORE_FLOW = { ('10.0.11.23', 53), ('10.0.11.42', 443) }

# The DNS Agent has been split into two agents with telemetry:
#
# * The Dnstap Agent listens to the unix socket and sends UDP datagrams.
# * The DNS Agent listens for UDP datagrams.
#
# Both unicast and multicast datagrams are supported. Both agents allow the rudimentary
# parameters to create unicast telemetry to be specified on the command line. More
# advanced use cases can be addressed by setting parameters here.
#
# Use the command line arguments.
DNS_CHANNEL = None
# Unicast datagrams are sent to (unicast) address 10.0.1.253, port 3053.
# DNS_CHANNEL = dict(recipient='10.0.1.253', port=3053)
# Assuming that 10.0.3.55 is bound to the eth1 network interface on the sender and
# 10.0.4.76 is bound to eth0 on the receiving system, the following will
# result in datagrams addressed to group 233.252.0.229, port 3053. The interface
# on which the datagram is to be sent/received needs to be specified. The sender
# specifies send_interface and the recipient specifies recv_interface.
# Both the sender and receiver read this (same) configuration file, so both should be
# specified here... presuming you're running both the Dnstap and DNS agents on the
# same host. (NOTE: If you are running both agents on the same host then the interface
# address is likely the same for both.)
# DNS_CHANNEL = dict(
#        recipient='233.252.0.229', port=3053,
#        send_interface='10.0.3.55', recv_interface='10.0.4.76'
#    )

# The following apply only to multicast. Defaults are shown.
# Controls whether or not the datagrams loop back to the sender (on the same interface).
# DNS_MULTICAST_LOOPBACK = 1
# Sets the internet protocol packet TTL, kind of like a "transmit range". 1 is the
# most limited. TTL is decremented at each packet routing step.
# DNS_MULTICAST_TTL = 1

