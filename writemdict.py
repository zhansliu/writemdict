from __future__ import unicode_literals, print_function, absolute_import, division
import struct, zlib, operator, sys

def _mdx_compress(data, compression_type=2):
	header = (struct.pack("<L", compression_type) + 
	         struct.pack(">L", zlib.adler32(data)))
	if compression_type == 0: #no compression
		return header + data
	elif compression_type == 2:
		return header + zlib.compress(data)
	else:
		raise NotImplementedError()

class MDictWriter:
	
	def __init__(self, d, block_size=65536):
		"""
		Prepares the records. A subsequent call to write() writes 
		the mdx file.
		   
		d is a dictionary, with key, value both being (unicode) strings. 
		key is the headword, and value is a html string, with no final newline, 
		with the explanation for that headword.
		   
		block_size is the approximate number of bytes (uncompressed)
		before starting a new block.
		"""

		self._num_entries = len(d)
		self._block_size = block_size
		self._build_offset_table(d)
		self._build_key_blocks()
		self._build_keyb_index()
		self._build_record_blocks()
		self._build_recordb_index()
		
	def _build_offset_table(self,d):
		""" Sets self._offset_table to a table of entries (key, offset, record) 
		
		where:
		  key: utf-8-encoded version of the key, null-terminated
		  offset: the cumulative sum of len(record) for preceding records
		  record: utf-8-encoded version of the record, null-terminated
		
		Also sets self._total_record_len to the total length of all record fields.
		"""
		items = list(d.items())
		items.sort(key=operator.itemgetter(0))
		
		self._offset_table = []
		offset = 0
		for key, record in items:
			key_enc = key.encode("utf_8") + b"\x00"
			record_enc = record.encode("utf_8") + b"\x00"
			self._offset_table.append((key_enc, offset, record_enc))
			offset += len(record_enc)
		self._total_record_len = offset
	
	def _split_blocks(self, block_type):
		"""
		Returns a list of MdxBlock, where the decompressed size of each block is (as
		far as practicable) less than self._block_size.
		
		block_type should be a subclass of MdxBlock, i.e. either MdxRecordBlock or 
		MdxKeyBlock."""
		
		this_block_start = 0
		cur_size = 0
		blocks = []
		for ind in range(len(self._offset_table)+1):
			if ind != len(self._offset_table):
				t = self._offset_table[ind]
			else:
				t = None
			
			if ind == 0:
				flush = False 
				# nothing to flush yet
				# this part is needed in case the first entry is longer than
				# self._block_size.
			elif ind == len(self._offset_table):
				flush = True #always flush the last block
			elif cur_size + block_type._len_block_entry(t) > self._block_size:
				flush = True #Adding this entry to make us larger than
				             #self._block_size, so flush now.
			else:
				flush = False
			if flush:
				blocks.append(block_type(
				    self._offset_table[this_block_start:ind]))
				cur_size = 0
				this_block_start = ind
			if t is not None: #mentally add this entry to list of things 
				cur_size += block_type._len_block_entry(t)
		return blocks
		
	def _build_key_blocks(self):
		""" Sets self._key_blocks to a list of MdxKeyBlocks."""
		self._key_blocks = self._split_blocks(MdxKeyBlock)
	
	def _build_record_blocks(self):
		self._record_blocks = self._split_blocks(MdxRecordBlock)
		
	def _build_keyb_index(self):
		""" 
		Sets self._keyb_index to a bytes object, containing the index of key blocks, in
		a format suitable for direct writing to the file.
		
		Also sets self._keyb_index_comp_size and self._keyb_index_decomp_size.
		"""
		
		decomp_data = b"".join(b.get_index_entry() for b in self._key_blocks)
		self._keyb_index_decomp_size = len(decomp_data)
		self._keyb_index = _mdx_compress(decomp_data)
		self._keyb_index_comp_size = len(self._keyb_index)
	
	def _build_recordb_index(self):
		""" 
		Sets self._recordb_index to a bytes object, containing the index of key blocks,
		in a format suitable for direct writing to the file.
		
		Also sets self._recordb_index_size.
		"""
		
		self._recordb_index = b"".join(
		    (b.get_index_entry() for b in self._record_blocks))
		self._recordb_index_size = len(self._recordb_index)
	
	def _write_key_sect(self, outfile):
		""" 
		Writes the key section header, key block index, and all the key blocks to
		outfile.
		
		outfile: a file-like object, opened in binary mode.
		"""
		keyblocks_total_size = sum(len(b.get_block()) for b in self._key_blocks)
		preamble = struct.pack(">QQQQQ",
		    len(self._key_blocks),
		    self._num_entries,
		    self._keyb_index_decomp_size,
		    self._keyb_index_comp_size,
		    keyblocks_total_size)
		preamble_checksum = struct.pack(">L", zlib.adler32(preamble))
		outfile.write(preamble)
		outfile.write(preamble_checksum)
		outfile.write(self._keyb_index)
		for b in self._key_blocks:
			outfile.write(b.get_block())
			
	def _write_record_sect(self, outfile):
		""" 
		Writes the record section header, record block index, and all the record blocks
		to outfile.		
		
		outfile: a file-like object, opened in binary mode.
		"""
		recordblocks_total_size = sum(
		    (len(b.get_block()) for b in self._record_blocks))
		outfile.write(struct.pack(">QQQQ",
		    len(self._record_blocks),
		    self._num_entries,
		    self._recordb_index_size,
		    recordblocks_total_size))
		outfile.write(self._recordb_index)
		for b in self._record_blocks:
			outfile.write(b.get_block())
		    
   
	
	def write(self, outfile):
		"""
		Write the mdx file to outfile.
		
		outfile: a file-like object, opened in binary mode.
		"""
		
		self._write_header(outfile)
		self._write_key_sect(outfile)
		self._write_record_sect(outfile)


	def _write_header(self, f):
		header_string = (
		"""<Dictionary """
		"""GeneratedByEngineVersion="2.0" """ 
		"""RequiredEngineVersion="2.0" """
        """Encrypted="0" """
        """Encoding="UTF-8" """
        """Format="Html" """
        """CreationDate="2011-1-16" """
        """Compact="No" """
        """Compat="No" """
        """KeyCaseSensitive="No" """
        """Description="Dictionary for testing MDictWriter" """
        """Title="Test Dictionary" """
        """DataSourceFormat="106" """
		"""StyleSheet=""/>\r\n\x00""").encode("utf_16_le")
		f.write(struct.pack(">L", len(header_string)))
		f.write(header_string)
		f.write(struct.pack("<L",zlib.adler32(header_string)))

class MdxBlock:
	"""
	Base base class for MdxRecordBlock and MdxKeyBlock.
	
	Defines methods for getting both the block itself, as well as the entry in the
	corresponding index (either record block index or key block index) for the
	block.
	"""
	
	def __init__(self, offset_table):
		"""
		Builds the data from offset_table.
		
		offset_table is a iterable containing tuples (key, offset, record) such as the
		one constructed by MdxWriter._build_offset_table().
		"""
		
		decomp_data = b"".join(
		    type(self)._block_entry(t)
		    for t in offset_table)
		self._decomp_size = len(decomp_data)
		self._comp_data = _mdx_compress(decomp_data, 2)
		self._comp_size = len(self._comp_data)
	
	def get_block(self):
		"""Returns a bytes object, containing the data for this block."""
		return self._comp_data
		
	def get_index_entry(self):
		"""
		Returns a bytes object, containing the entry for this block in the
		corresponding key block index or record block index.
		"""
		raise NotImplementedError()
		
	def _block_entry(t):
		"""
		Returns the data corresponding to a single entry in offset.
		
		t is a tuple (key, offset, record)
		"""
		raise NotImplementedError()
	
	def _len_block_entry(t):
		"""Should be approximately equal to len(_block_entry(t)).
		
		Used by MdxWriter._split_blocks() to determine where to split into blocks."""
		raise NotImplementedError()
		
class MdxRecordBlock(MdxBlock):
	"""
	A class representing a record block.
	
	Has the ability to return (in the format suitable for insertion in an mdx file) 
	both the block itself, as well as the entry in the record block index for that
	block.
	"""
	def __init__(self, offset_table):
		"""
		Builds the data for offset_table.
		
		offset_table is a iterable containing tuples (key, offset, record) such as the
		one constructed by MdxWriter._build_offset_table().
		
		Actually only uses the record parts.
		"""
		MdxBlock.__init__(self, offset_table)
		
	def get_index_entry(self):
		"""
		Returns a bytes object, containing the entry for this block in the record
		block index.
		"""
		return struct.pack(">QQ", self._comp_size, self._decomp_size)
	
	def _block_entry(t):
		return t[2]
	
	def _len_block_entry(t):
		return len(t[2])
	
class MdxKeyBlock(MdxBlock):
	"""
	A class representing a key block.
	
	Has the ability to return (in the format suitable for insertion in an mdx file) 
	both the block itself, as well as the entry in the record block index for that
	block.
	"""
	def __init__(self, offset_table):
		"""
		Builds the data for offset_table.
		
		offset_table is a iterable containing tuples (key, offset, record) such as the
		one constructed by MdxWriter._build_offset_table(). offset_table must be sorted
		by key.
		
		Only uses the key and offset fields, and effectively ignores record.
		"""
		MdxBlock.__init__(self, offset_table)
		self._num_entries = len(offset_table)
		self._first_key = offset_table[0][0]
		self._last_key = offset_table[len(offset_table)-1][0]
	
	def _block_entry(t):
		return struct.pack(">Q", t[1])+t[0]
	
	def _len_block_entry(t):
		return 8 + len(t[0])
		
	def get_index_entry(self):
		"""Returns a bytes object, containing the header data for this block"""
		return (
		      struct.pack(">QH",
		        self._num_entries,
		        len(self._first_key) - 1 #minus one for null char
		      ) 
		    +   self._first_key
		    + struct.pack(">H", 
		        len(self._last_key) - 1 #minus one for null char
		      )
		    +   self._last_key
		    + struct.pack(">QQ",
		        self._comp_size,
		        self._decomp_size
		    ))
		
	
	
		
