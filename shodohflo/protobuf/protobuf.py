#!/usr/bin/python3
# Copyright (c) 2017 by Fred Morris Tacoma WA and/or Farsight Security, Inc. San Mateo CA
# Copyright (c) 2019 by Fred Morris Tacoma WA
#
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

"""Pure Python protobuf implementation.

The following field types are supported:
    PbAnyField      Any kind/id field. Data is decoded according to the embedded
                    id value and type specification.
    PbBytesField    Container for strings, nested protobufs, variable length data.
    PbFixed32Field  Unsigned 32 bit integer.
    PbInt32Field    Signed 32 bit varint.
    PbUInt32Field   Unsigned 32 bit varint.
    PbInt64Field    Signed 64 bit varint.
    PbUInt64Field   Unsigned 64 bit varint.

Protobufs are both a Packet and a Field. For instance if you have a protobuf
called NmsgNewDomain, you would use it in a Packet definition (in fields_desc)
with the idiom NmsgNewDomain.Field().
"""

import struct

class FieldIDMismatchError(TypeError):
    pass

class FieldTypeMismatchError(TypeError):
    pass

class ProtobufField(object):
    """Protobuf field type base class.
    
    All Protobuf fields support the following parameters:
        id          An integer protobuf field id value.
        multi       Can the field occur multiple times?
        
    Protobuf fields are unordered in the stream. They are preceded by
    an id value and a weak type specification, and sometimes a length.
    
    Field values are not stored in an individual field but in the ProtoBuf
    object containing them.
    """
    def __init__(self,name,default=None,id=None,multi=False):
        self.pb_name = name
        self.pb_default = default
        self.pb_id = id
        self.pb_multi = multi
        return
    
    def set_format(self,size):
        """Bytes on the wire is determined by protobuf."""
        self.fmt = "!" + str(size) + "s"
        self.sz = struct.calcsize(self.fmt)
        return
    
    def check_field_id(self,pkt,id):
        if id != self.pb_id:
            raise FieldIDMismatchError(
                        'Expected %s/%d saw %s/%d' %
                        (   self.pb_name, self.pb_id,
                            (id in pkt.fields_by_id) and pkt.fields_by_id[id].pb_name or '--', id
                        )
                    )
        return
    
    @staticmethod
    def get_varint(s):
        i = 0
        bytes = []
        while i < len(s):
            byte = s[i]
            i += 1
            bytes.append(byte & 0x7f)
            if not (byte & 0x80): break
        accum = bytes.pop()
        while bytes:
            accum <<= 7
            accum |= bytes.pop()
        return s[i:],accum
    
    @staticmethod
    def get_field_header(s):
        s,header = ProtobufField.get_varint(s)
        id = header >> 3
        wtype = header & 0x07
        return s,id,wtype
    
    def getfield(self,pkt,s):
        """Used to extract a field from a packet.
        
        pkt:    The containing Protobuf.
        s:      The (ever shrinking) stream of data.
        """
        s,id,wtype = self.get_field_header(s)
        if wtype == 2:  # descriptor
            s,l = self.get_varint(s)
            self.set_format(l)
            return s[l:],self.m2i(pkt,s[:l])
        if wtype == 0:  # varint
            olen = len(s)
            s,v = self.get_varint(s)
            self.set_format(olen - len(s))
            return s,self.m2i(pkt,v)
        if wtype == 1:
            self.set_format(8)
            return s[8:],self.m2i(pkt,s[:8])
        if wtype == 5:
            self.set_format(4)
            return s[4:],self.m2i(pkt,s[:4])
        return s,''
    
    def m2i(self,pkt,s):
        """Convert from "over the wire" to internal representation."""
        return s
    
    def i2repr(self,pkt,i):
        """Convert from internal representation to __repr__() format.
        
        By default this calls i2h().
        """
        return self.i2h(pkt,i)
    
    def i2h(self,pkt,i):
        """Convert from internal representation to "human readable" format."""
        return str(i)
        
    def __repr__(self):
        """Return printable representation."""
        # TODO ?
        return 'Protobuf field: ' + str(type(self))
        

class PbAnyField(ProtobufField):
    """Any type of PB field with this id.
    
    See Protobuf.log_wire_type for special debugging powers.
    """
    
    def getfield(self,pkt,s):
        s,id,wtype = self.get_field_header(s)
        if pkt.log_wire_type:
            print("({}) {}: {}".format(id, self.pb_name, wtype))
        if self.pb_id is None:
            self.pb_id = id
        else:
            self.check_field_id(pkt,id)
        if wtype == 2:  # descriptor
            s,l = self.get_varint(s)
            self.set_format(l)
            return s[l:],self.m2i(pkt,s[:l])
        if wtype == 0:  # varint
            olen = len(s)
            s,v = self.get_varint(s)
            self.set_format(olen - len(s))
            return s,self.m2i(pkt,v)
        if wtype == 1:
            self.set_format(8)
            return s[8:],self.m2i(pkt,s[:8])
        if wtype == 5:
            self.set_format(4)
            return s[4:],self.m2i(pkt,s[:4])
        return s,''

class PbBytesField(ProtobufField):
    """Byte String field.

    Additionally supports the parameters:
        length_from         When a protobuf is embedded within another protobuf
                            protobuf derives the length of the embedded field. When a
                            protobuf is embedded in a "standard" packet the field
                            length is specified in another field or runs to the end
                            of the enclosing packet.
        cls                 This is the field type with which the bytes are overlaid.
        provide_length_from If true, then length_from is overridden in getfield with
                            the actual length from the descriptor.
    """
    def __init__(self,name,default=None,id=None,multi=False,length_from=None,cls=None,provide_length_from=False):
        self.length_from = length_from
        self.pb_override_class = cls
        self.provide_length_from = provide_length_from
        ProtobufField.__init__(self,name,default,id,multi)
        return
    
    def i2h(self,pkt,x):
        if self.pb_override_class:
            return self.pb_override_class.i2h(pkt,x)
        return x

    def getfield(self,pkt,s):
        if self.length_from:
            l = self.length_from(pkt)
        else:
            s,id,wtype = self.get_field_header(s)
            if self.pb_id is None:
                self.pb_id = id
            else:
                self.check_field_id(pkt,id)
            if wtype == 2:  # descriptor
                s,l = self.get_varint(s)
            else:
                raise FieldTypeMismatchError('Expected type 2, got type %d' % (wtype,))
        self.set_format(l)
        if self.pb_override_class:
            if self.provide_length_from:
                self.pb_override_class.length_from = lambda pkt: l
            discard,v = self.pb_override_class.getfield(pkt,s[:l])
        else:
            v = self.m2i(pkt,s[:l])
        return s[l:],v

class ProtobufVarintField(ProtobufField):
    """Varint base class."""
    
    @staticmethod
    def svi2si(v):
        """Signed Varint to Integer decoder.
        
        Handles both 32 bit and 64 bit values. Crazy, but that's the way
        snakes are!
        """
        neg = v & 0x01
        v = (v >> 1)
        if neg:
            v = (v + 1) * -1
        return v
    
    def getfield(self,pkt,s):
        s,id,wtype = self.get_field_header(s)
        if self.pb_id is None:
            self.pb_id = id
        else:
            self.check_field_id(pkt,id)
        if wtype == 0:  # varint
            olen = len(s)
            s,v = self.get_varint(s)
            self.set_format(olen - len(s))
        else:
            raise FieldTypeMismatchError('Expected type 0, got type %d' % (wtype,))

        return s,self.m2i(pkt,v)


class ProtobufFixedIntField(ProtobufField):
    """FixedInt base class."""

    def m2i(self,pkt,x):
        i = len(x) - 1
        accum = x[i] & 0xff
        i -= 1
        while i >= 0:
            accum <<= 8
            accum |= x[i] & 0xff
            i -= 1
        return accum
    
    @staticmethod
    def signed(x,ones,sign_bit):
        if x & sign_bit:
            x = (x ^ ones) + 1
            x *= -1
        return x

    def getfield(self,pkt,s):
        s,id,wtype = self.get_field_header(s)
        if self.pb_id is None:
            self.pb_id = id
        else:
            self.check_field_id(pkt,id)
        if wtype == self.WTYPE:
            self.set_format(self.BYTES)
        else:
            raise FieldTypeMismatchError('Expected type %d, got type %d' % (self.WTYPE,wtype))

        return s[self.BYTES:],self.m2i(pkt,s[:self.BYTES])

class PbFixed32Field(ProtobufFixedIntField):
    """Unsigned 32 bit integer."""
    WTYPE = 5
    BYTES = 4

class PbInt32Field(ProtobufVarintField):
    
    def m2i(self,pkt,v):
        return self.svi2si(v)

class PbUInt32Field(ProtobufVarintField):
    pass

class PbInt64Field(ProtobufVarintField):

    def m2i(self,pkt,v):
        return self.svi2si(v)
    
class PbUInt64Field(ProtobufVarintField):
    pass

class ProtobufEmbeddedField(PbBytesField):
    """This is the special field which represents a protobuf packet embedded as a field.
    
    Normally this field is instantiated by calling the Field() factory method of a
    Protobuf derived packet class.
    """
    def __init__(self,name,default=None,id=None,multi=False,length_from=None,packet_class=None):
        self.pb_packet_class = packet_class
        self.pb_log_wire_type = False
        PbBytesField.__init__(self,name,default,id,multi,length_from)
        return
        
    def m2i(self,pkt,x):
        protobuf = self.pb_packet_class(x,self.pb_log_wire_type)
        return protobuf
    
    def i2repr(self,pkt,x):
        v = repr(x)
        if not isinstance(pkt,Protobuf):
            x.suppress_repr(1)
        return v
    
    def getfield(self,pkt,s):
        if self.length_from:
            l = self.length_from(pkt)
        else:
            s,id,wtype = self.get_field_header(s)
            if self.pb_id is None:
                self.pb_id = id
            else:
                self.check_field_id(pkt,id)
            if wtype != 2:
                raise FieldTypeMismatchError('Expected type 2, got type %d' % (wtype,))
            s,l = self.get_varint(s)
        self.set_format(l)
        return s[l:], self.m2i(pkt,s[:l])

class Protobuf(object):
    """Protobufs are both a packet and a field.
    
    They are a field when they appear in a packet. The contents of that field
    are interpreted as a Protobuf packet type.
    
    Additionally supports the parameters:
        length_from     When a protobuf is embedded within another protobuf
                        protobuf derives the length of the embedded field. When a
                        protobuf is embedded in a "standard" packet the field
                        length is specified in another field or runs to the end
                        of the enclosing packet.
    """
    
    # TODO: If fields_desc is (missing? none?) then default to dumping the ids/values
    # from the data, i.e. treat all found fields as PbAnyField more or less (won't
    # have field names).
    #
    # TODO: Maybe fields_desc order determines output order? I dunno. It's not much
    # intrinsic use.
    def __init__(self,wire_data=None,log_wire_type=False):
        """Protobuf.
        
        wire_data:      If passed, then the data is dissected.
        log_wire_type:  If true, then the wire type of instances of PbAnyField are printed.
        """
        self.fields_by_id = { f.pb_id:f for f in self.fields_desc }
        self.fields_by_name = { f.pb_name:f for f in self.fields_desc }
        self.fields_seen = []
        self.dummy_count = 0
        self.repr_output_suppressed = 0
        self.fields = {}
        self.log_wire_type = log_wire_type
        if wire_data is not None:
            self.more = self.do_dissect(wire_data)
        else:
            self.more = bytes()
        return
        
    @classmethod
    def Field(cls,name,default=None,id=None,multi=False,length_from=None):
        """Factory method for a protobuf embedded as a field.
        
        Call this to instantiate a field representing an embedded protobuf. In the
        case where the protbuf is embedded in a "regular" packet, supply length_from.
        """
        return ProtobufEmbeddedField(name,default,id,multi,length_from,packet_class=cls)
    
    def field(self,name,occurrence=None):
        """Return a tuple of the ProtobufField and associated value.
        
        If a field is multi-occurring then by default the first occurrence is returned.
        A specific occurrence can be specified with occurrence.
        """
        proto_field = self.fields_by_name[name]
        field_internal = self.fields[name]
        if isinstance(field_internal,list):
            if occurrence is None:
                occurrence = 0
            field_internal = field_internal[occurrence]
        return proto_field, field_internal
        
    def DummyField(self):
        """Factory method to produce dummy fields."""
        self.dummy_count += 1
        field = PbAnyField("(unknown_%d)" % (self.dummy_count,))
        self.fields_by_id[field.pb_name] = field
        return field
    
    def suppress_repr(self,count=0):
        """__repr__ output suppression.
        
        A Protobuf is both a field and a packet. When _repr_ is called, we
        want the nested packet to print out as the contents of the field
        containing it.
        
        In __repr__() the call to print out fields happens before the
        call to print out nested packets. This complete and utter hack relies
        on the execution order there to suppress the second call to __repr__.
        """
        suppressed = self.repr_output_suppressed > 0
        self.repr_output_suppressed += count or -1        
        if self.repr_output_suppressed < 0:
            self.repr_output_suppressed = 0
        return suppressed
    
    def __repr__(self):
        """Return printable representation."""
        if self.suppress_repr():
            return ''

        field_values = []
        for f in self.fields_seen:
            field = f[0]
            field_internal = self.fields[field.pb_name]
            if f[1] is not None:
                field_internal = field_internal[f[1]]
            fv = field.i2repr(self, field_internal)
            field_values.append('='.join((field.pb_name,fv)))
        return "<%s %s |>" % ( self.__class__.__name__, ' '.join(field_values))
    
    def do_dissect(self,s):
        while s:
            discard,id,wtype = ProtobufField.get_field_header(s)
            field = (id in self.fields_by_id) and self.fields_by_id[id] or self.DummyField()
            if isinstance(field,ProtobufEmbeddedField):
                field.pb_log_wire_type = self.log_wire_type
            s,fval = field.getfield(self,s)
            if field.pb_multi:
                if field.pb_name not in self.fields:
                    self.fields[field.pb_name] = []
                self.fields[field.pb_name].append(fval)
                self.fields_seen.append([field,len(self.fields[field.pb_name])-1])
            else:
                self.fields[field.pb_name] = fval
                self.fields_seen.append([field,None])
        self.explicit = True
        return s

