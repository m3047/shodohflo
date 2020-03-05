# Used by: count_client_keys.py
REDIS_SERVER = 'localhost'

# WARNING! Redis translation of hostnames to addresses using DNS is unreliable
# because it calls socket.getaddrinfo() which in turn has been observed to
# exhibit incorrect case sensitivity. DNS is not supposed to be case sensitive.
#
# If you want to use hostnames and DNS, then you may want to set USE_DNSPTYHON
# to True. Of course, dnspython has to be installed.
# Used by: count_client_keys.py
USE_DNSPYTHON = False

# Location of the Dnstap unix domain socket.
# Used by: tap_example.py
SOCKET_ADDRESS = '/tmp/dnstap'

