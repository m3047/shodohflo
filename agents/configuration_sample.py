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
