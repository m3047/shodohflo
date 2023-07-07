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

# This sets the minimum expire time for Redis entries. In the case of DNS
# events this is added to the TTL of the artifact; in the case of packet
# captures it is the expire time.
TTL_GRACE = 900         # 15 minutes

# Number of seconds between performance logging events. Can be set individually
# for the PCAP and DNS agents. If set to None or 0 then no logging occurs. Events
# are logged at INFO level.
# PCAP_STATS = 600 # 10 minutes
PCAP_STATS = None
DNS_STATS = None

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