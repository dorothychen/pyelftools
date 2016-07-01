#-------------------------------------------------------------------------------
# elftools: dwarf/aranges.py
#
# DWARF aranges section decoding (.debug_aranges)
#
# Dorothy Chen (dorothchen@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
import os
from collections import namedtuple
from ..common.utils import struct_parse
from bisect import bisect_left
import math

ARangeEntry = namedtuple('ARangeEntry', 'begin_addr length info_offset')

class ARanges(object):
    """ ARanges table in DWARF
    """
    def __init__(self, stream, size, structs):
        self.stream = stream
        self.size = size
        self.structs = structs

        # entries is a sorted list of ARangeEntry tuples, 
        # sorted by beginning address
        self.entries = self._get_entries()
        self.entries.sort(key=lambda entry: entry[0])
        self.keys = [entry[0] for entry in self.entries]

    def cu_offset_at_addr(self, addr):
        tup = self.entries[bisect_left(self.keys, addr)]
        return tup[2] # "info_offset"
        

    #------ PRIVATE ------#
    def _get_entries(self):
        """ Populate self.entries with ARangeEntry tuples for each range of addresses
        """
        entries = []
        offset = 0

        # one loop == one "set" == one CU
        while offset < self.size :
            aranges_header = struct_parse(self.structs.Dwarf_aranges_header, 
                self.stream, offset)
            addr_size = self._get_addr_size(aranges_header["address_size"])

            # No segmentation
            if aranges_header["segment_size"] == 0:
                # pad to nearest multiple of tuple size
                tuple_size = aranges_header["address_size"] * 2 
                fp = self.stream.tell()
                seek_to = int(math.ceil(fp/float(tuple_size)) * tuple_size)
                self.stream.seek(seek_to)

                # entries in this set/CU
                addr = struct_parse(addr_size('addr'), self.stream)
                length = struct_parse(addr_size('length'), self.stream)
                while addr != 0 and length != 0:
                    entries.append(
                        ARangeEntry(begin_addr=addr, 
                            length=length, 
                            info_offset=aranges_header["debug_info_offset"]))
                    addr = struct_parse(addr_size('addr'), self.stream)
                    length = struct_parse(addr_size('length'), self.stream)

            # Segmentation exists in executable
            elif segment_size != 0:
                raise NotImplementedError("Segmentation not supported")

            offset = (offset 
                + aranges_header.unit_length 
                + self.structs.initial_length_field_size())

        return entries

    def _get_addr_size(self, addr_header_value):
        """ Given this set's header value (int) for the address size, 
            get the Construct representation of that size
        """
        if addr_header_value == 4:
            return self.structs.Dwarf_uint32
        else: 
            assert addr_header_value == 8
            return self.structs.Dwarf_uint64
