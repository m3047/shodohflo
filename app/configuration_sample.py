# The host and port used by Werkzeug.
HTTP_HOST = 'localhost'
HTTP_PORT = 3047

# Two different Redis access mechanisms are supported.
# REDIS_SERVER makes a direct Redis connection to the database.
REDIS_SERVER = 'localhost'
# RKVDNS uses the RKVDNS DNS proxy for Redis. It is readonly.
# If defined, then REDIS_SERVER is ignored. RKVDNS can point to the zone
# name for an RKVDNS instance, or to an FQDN which resolves to PTR records
# identifying one or more RKVDNS zones. Using this also requires that the
# rkvdns_examples be cloned in the same parent directory as shodohflo and
# the rkvdns_links.sh script to be run, or that some other mechanism is used
# to make the rkvdns_examples/fanout/fanout.py and
# rkvdns_examples/peers/rkvdns.py modules available in the app/ directory.
RKVDNS = None

# WARNING! Redis translation of hostnames to addresses using DNS is unreliable
# because it calls socket.getaddrinfo() which in turn exhibits incorrect case
# sensitivity. DNS is not supposed to be case sensitive.
#
# If you want to use hostnames and DNS, then you may want to set USE_DNSPTYHON
# to True. Of course, dnspython has to be installed.
USE_DNSPYTHON = False

# Presentation templates. Templates consist of a template in templates/ and a
# python module in renderers/ of the same name. For example: /templates/graph.html
# and renderers/graph.py
DEFAULT_TEMPLATE = 'graph2'
AVAILABLE_TEMPLATES = ['graph','graph2']

