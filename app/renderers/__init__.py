"""Rendering Framework.

A Renderer is a combination of a python module (in this directory) and a template of the
same name in the ../templates/ directory. In other words, a Renderer named graph has a
python module named graph.py and a template named graph.html.

The magic ingredient in the python module is simply a method named render_chain with one
mandatory argument: the chain. The chain is composed of Link objects.

The list of rendered chains is passed to the template as the variable "table".

Which renderer does the app use? This is determined by the setting of DEFAULT_TEMPLATE,
which can be overridden with the "template" parameter. The list of templates which can
be specified with the template parameter is determined by the list specified as
AVAILABLE_TEMPLATES.
"""

