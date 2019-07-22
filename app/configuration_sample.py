# The host and port used by Werkzeug.
HTTP_HOST = 'localhost'
HTTP_PORT = 3047

REDIS_SERVER = 'localhost'
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

