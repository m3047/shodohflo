REDIS_SERVER = 'localhost'
# WARNING! Redis translation of hostnames to addresses using DNS is unreliable
# because it calls socket.getaddrinfo() which in turn exhibits incorrect case
# sensitivity. DNS is not supposed to be case sensitive.
#
# If you want to use hostnames and DNS, then you may want to set USE_DNSPTYHON
# to True. Of course, dnspython has to be installed.
USE_DNSPYTHON = False

# How long to persist test data in the database.
TTL_GRACE = 900

