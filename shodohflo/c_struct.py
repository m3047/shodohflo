#!/usr/bin/python3
# (c) 2020 Fred Morris, Tacoma WA. All rights reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Classes to construct structures from.

Emphasis is on c structures and interoperability with struct.pack and struct.unpack.

An Array is a fixed-length sequence of AtomicElements or Structs.
A Struct is a (declared) sequence of Elements and Arrays.

Naming of Items
---------------

Items don't have to have names, although it's hard to reference them with the
Struct methods element_index() and element(offset) if they don't.

For any number of the same reasons people use typedef in C, you might want
to assign an item to a variable and use it anonymously. Then you'll need to name
it later when using it in a struct. Use Instance() to accomplish this.

As a consequence of this the name property is first class and must be referenced
as .name on the item, but all other properties must be referenced on .item, for
example .item.format or .item.size.

An Example
----------

We define two structs. The second struct includes an instance of the first one.
For the Element cases, the constructor parses the definition saving two quotes
and a comma.

    iw_point = Struct(
            Element('ptr    pointer'),
            Element('u16    length'),
            Element('u16    flags')
        )
    
    siocgiwrange_arg = Struct(
            String(         16,     'ifname'),      # 16 octets
            Instance(iw_point,      'data'),        # Only 12 octets
            Element('u32             padding')      # Pad to 32 octets total
        )

We can reference items in various ways:

    buf = array.array('B',b'\x00'*iw_point.item.size)
    ptr, length = buf.buffer_info()
    arg = struct.pack(siocgiwrange_arg.item.format, ("wlan0".encode()+b'\x00'*16)[:16], ptr, iw_point.item.size, 0, 0)

Let's unpack (pun intended) that a bit:

    >>> iw_point.item.size
    12

Same thing:

    >>> siocgiwrange_arg.element['data'].item.size
    12

Format (for use with struct.pack() and struct.unpack()):

    >>> siocgiwrange_arg.item.format
    '16sPHHI'

Contents of ifname from the arg buffer:

    >>> arg[siocgiwrange_arg.element_offset['ifname']:
    ...     siocgiwrange_arg.element_offset['ifname']+siocgiwrange_arg.element['ifname'].item.size]
    b'wlan0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    
siocgiwrange_arg.element_index provides a similar index into the tuple returned by unpack():

    >>> struct.unpack(siocgiwrange_arg.item.format, arg)[siocgiwrange_arg.element_index['ifname']]
    b'wlan0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

"""

import struct

class BaseItem(object):
    """Allows us to have instance names which always work.
    
    The name property should always be referenced on the object. All other
    properties should always be referenced on .item.
    """
    
    @property
    def item(self):
        return self

class Element(BaseItem):
    """Elements for Arrays and Structs.
    
    Properties
        item.format  The struct format string.
        item.signed  Signed or unsigned?
        item.length  The number of elements (1)
        item.size    The length in bytes (calculated from the format string).
        name         The element name. Defaults to None.
    """

    ATOMIC_TYPE = dict(
            s8= ('b',True),
            u8= ('B',False),
            s16=('h',True),
            u16=('H',False),
            s32=('i',True),
            u32=('I',False),
            ptr=('P',False)
        )
    
    def __init__(self, declaration):
        """The constructor takes a string consisting of an ATOMIC_TYPE followed by an optional name."""
        declaration = declaration.split()
        atype = declaration[0]
        self.format, self.signed = self.ATOMIC_TYPE[atype]
        self.length = 1
        self.name = len(declaration) == 2 and declaration[1] or None
        self.size = struct.calcsize(self.format)
        return

class String(BaseItem):
    """A string of bytes of the specified length."""
    
    def __init__(self, length, name=None):
        self.length = 1
        self.format = '{}s'.format(length)
        self.name = name
        self.size = struct.calcsize(self.format)
        return
    
class Array(BaseItem):
    """A fixed-length list of Atomic Elements or Structs."""
    
    def __init__(self, atype, length, name=None):
        self.atype = atype
        self.length = length * atype.item.length
        self.name = name
        self.format = length * atype.item.format
        self.size = struct.calcsize(self.format)
        return

class Struct(BaseItem):
    """A list of Elements, Arrays and Structs.
    
    Elements and Arrays can be named or unnamed. Structs are always unnamed; to
    name a struct encapsulate it as an Instance.
    
    In addition to length, format and size the class has two additional dictionary properties:
    
      element_index     Index of the element in the tuple returned by struct.unpack()
      element_offset    Byte offset of the element in raw bytes.
    """
    
    def __init__(self, *elements):
        self.element_list = elements
        self.element = { e.name:e for e in elements if e.name }

        self.element_index = {}
        self.element_offset = {}
        this_index = 0
        accumulated_format = ''
        for element in elements:
            if element.name:
                self.element_index[element.name] = this_index
                self.element_offset[element.name] = accumulated_format and struct.calcsize(accumulated_format) or 0
            this_index += element.item.length
            accumulated_format += element.item.format

        self.format = accumulated_format
        self.length = this_index
        self.size = struct.calcsize(self.format)

        return

class Instance(object):
    """Give a name to an Element, Array or Struct.
    
    This is a wrapper around the actual item.
    """
    
    def __init__(self, item, name):
        self._item = item
        self.name = name
        return
    
    @property
    def item(self):
        return self._item
    