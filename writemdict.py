import struct, zlib, operator, sys, datetime

assert(sys.version_info >= (3, 0))

from ripemd128 import ripemd128
from html import escape
from pureSalsa20 import Salsa20

class ParameterError(Exception):
	pass

def _mdx_compress(data, compression_type=2):
	header = (struct.pack("<L", compression_type) + 
	         struct.pack(">L", zlib.adler32(data)))
	if compression_type == 0: #no compression
		return header + data
	elif compression_type == 2:
		return header + zlib.compress(data)
	else:
		raise NotImplementedError()
		
def _fast_encrypt(data, key):
	b = bytearray(data)
	key = bytearray(key)
	previous = 0x36
	for i in range(len(b)):
		t = b[i] ^ previous ^ (i&0xff) ^ key[i%len(key)]
		previous = b[i] = ((t>>4)|(t<<4)) & 0xff
	return bytes(b)
	
def _mdx_encrypt(comp_block):
	key = ripemd128(comp_block[4:8] + struct.pack("<L", 0x3695))
	return comp_block[0:8] + _fast_encrypt(comp_block[8:], key)
	
def _salsa_encrypt(plaintext, dict_key):
	if(type(dict_key) == str):
		dict_key = dict_key.encode("utf8")
	assert(type(dict_key) == bytes)
	assert(type(plaintext) == bytes)
	encrypt_key = ripemd128(dict_key)
	s20 = Salsa20(key=encrypt_key,IV=b"\x00"*8,rounds=8)
	return s20.encryptBytes(plaintext)

def hexdump(bytes_blob):
	return "".join("{:02X}".format(c) for c in bytes_blob)
	
def encrypt_key(dict_key, email):
	"""
	Generates a hexadecimal key for use with the official MDict program.
	
	dict_key and email should be of type bytes (representing ascii strings), and outfile should be a file
	open for writing in text mode.
	
	Returns a string of 32 hexadecimal digits. This should be place in a file of its own, with
	the same name and location as the mdx file but the extension changed to '.key'. """
	
	email_digest = ripemd128(email)
	dict_key_digest = ripemd128(dict_key)
	
	s20 = Salsa20(key=email_digest,IV=b"\x00"*8,rounds=8)
	output_key = s20.encryptBytes(dict_key_digest)
	return hexdump(output_key)
	

class OffsetTableEntry:
	def __init__(self, *, key, key_null, key_len, offset, record_null):
		self.key = key
		self.key_null = key_null
		self.key_len = key_len
		self.offset = offset
		self.record_null = record_null

class MDictWriter:
	
	def __init__(self, d, title, description, *, 
	             block_size=65536, 
							 encrypt_index=False,
							 encoding="utf8",
							 compression_type=2,
							 version="2.0",
							 encrypt_key = None):
		"""
		Prepares the records. A subsequent call to write() writes 
		the mdx file.
		   
		d is a dictionary, with key, value both being (unicode) strings. 
		key is the headword, and value is a html string, with no final newline, 
		with the explanation for that headword.
		
		title is a (unicode) string, with the title of the dictionary
		description is a (unicode) string, with a short description of the dictionary.
		   
		block_size is the approximate number of bytes (uncompressed)
		before starting a new block.
		
		encrypt_index is true if the keyword index should be encrypted.
		
		encrypt_key should be a bytes object, containing the dictionary key. If encrypt_key is None,
			no encryption will be applied. Usually, encrypt_key will be an ASCII string.
		"""

		self._num_entries = len(d)
		self._title=title
		self._description=description
		self._block_size = block_size
		self._encrypt_index = encrypt_index
		self._encrypt = (encrypt_key is not None)
		self._encrypt_key = encrypt_key
		self._compression_type = compression_type
		encoding = encoding.lower()
		if encoding in ["utf8", "utf-8"]:
			self._python_encoding = "utf_8"
			self._encoding = "UTF-8"
			self._encoding_length = 1
		elif encoding in ["utf16", "utf-16"]:
			self._python_encoding = "utf_16_le"
			self._encoding = "UTF-16"
			self._encoding_length = 2
		elif encoding == "gbk":
			self._python_encoding = "gbk"
			self._encoding = "GBK"
			self._encoding_length = 1
		elif encoding == "big5":
			self._python_encoding = "big5"
			self._encoding = "BIG5"
			self._encoding_length = 1
		else:
			raise ParameterError("Unknown encoding")
		if version not in ["2.0", "1.2"]:
			raise ParameterError("Unknown version")
		self._version = version
		self._build_offset_table(d)
		self._build_key_blocks()
		self._build_keyb_index()
		self._build_record_blocks()
		self._build_recordb_index()
		
	def _build_offset_table(self,d):
		""" Sets self._offset_table to a table of entries OffsetTableEntry objects e.
		
		where:
		  e.key: encoded version of the key, not null-terminated
			e.key_null: encoded version of the key, null-terminated
		  e.key_len: the length of the key, in either bytes or 2-byte units, not counting the null character
			        (as required by the MDX format in the keyword index)
		  e.offset: the cumulative sum of len(record_null) for preceding records
		  e.record_null: encoded version of the record, null-terminated
		
		Also sets self._total_record_len to the total length of all record fields.
		"""
		items = list(d.items())
		items.sort(key=operator.itemgetter(0))
		
		self._offset_table = []
		offset = 0
		for key, record in items:
			key_enc = key.encode(self._python_encoding)
			key_null = (key+"\0").encode(self._python_encoding)
			key_len = len(key_enc) // self._encoding_length
			record_null = (record+"\0").encode(self._python_encoding) 
			self._offset_table.append(OffsetTableEntry(
			    key=key_enc,
					key_null=key_null,
					key_len=key_len,
					record_null=record_null,
					offset=offset))
			offset += len(record_null)
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
				    self._offset_table[this_block_start:ind], self._compression_type, self._version))
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
		if self._version == "2.0":
			self._keyb_index = _mdx_compress(decomp_data, self._compression_type)
			if self._encrypt_index:
				self._keyb_index = _mdx_encrypt(self._keyb_index)
			self._keyb_index_comp_size = len(self._keyb_index)
		else:
			self._keyb_index = decomp_data
	
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
		if self._version == "2.0":
			preamble = struct.pack(">QQQQQ",
			    len(self._key_blocks),
			    self._num_entries,
			    self._keyb_index_decomp_size,
			    self._keyb_index_comp_size,
			    keyblocks_total_size)
			preamble_checksum = struct.pack(">L", zlib.adler32(preamble))
			if(self._encrypt):
				preamble = _salsa_encrypt(preamble, self._encrypt_key)
			outfile.write(preamble)
			outfile.write(preamble_checksum)
		else:
			preamble = struct.pack(">LLLL",
			    len(self._key_blocks),
			    self._num_entries,
			    self._keyb_index_decomp_size,
			    keyblocks_total_size)
			if(self._encrypt):
				preamble = _salsa_encrypt(preamble, self._encrypt_key)
			outfile.write(preamble)
		
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
		if self._version == "2.0":
			format = ">QQQQ"
		else:
			format = ">LLLL"
		outfile.write(struct.pack(format,
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
		encrypted = 0
		if self._encrypt_index:
			encrypted = encrypted | 2
		if self._encrypt:
			encrypted = encrypted | 1
		
		header_string = (
		"""<Dictionary """
		"""GeneratedByEngineVersion="{version}" """ 
		"""RequiredEngineVersion="{version}" """
        """Encrypted="{encrypted}" """
        """Encoding="{encoding}" """
        """Format="Html" """
        """CreationDate="{date.year}-{date.month}-{date.day}" """
        """Compact="No" """
        """Compat="No" """
        """KeyCaseSensitive="No" """
        """Description="{description}" """
        """Title="{title}" """
        """DataSourceFormat="106" """
		"""StyleSheet=""/>\r\n\x00""").format(
		    version = self._version,
		    encrypted = encrypted,
		    encoding = self._encoding, 
		    date = datetime.date.today(), 
		    description=escape(self._description, quote=True),
		    title=escape(self._title, quote=True)
		    ).encode("utf_16_le")
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
	
	def __init__(self, offset_table, compression_type, version):
		"""
		Builds the data from offset_table.
		
		offset_table is a iterable containing OffsetTableEntry objects.
		"""
		
		decomp_data = b"".join(
		    type(self)._block_entry(t, version)
		    for t in offset_table)
		self._decomp_size = len(decomp_data)
		self._comp_data = _mdx_compress(decomp_data, compression_type)
		self._comp_size = len(self._comp_data)
		self._version = version
	
	def get_block(self):
		"""Returns a bytes object, containing the data for this block."""
		return self._comp_data
		
	def get_index_entry(self):
		"""
		Returns a bytes object, containing the entry for this block in the
		corresponding key block index or record block index.
		"""
		raise NotImplementedError()
		
	@staticmethod
	def _block_entry(t, version):
		"""
		Returns the data corresponding to a single entry in offset.
		
		t is an OffsetTableEntry object
		"""
		raise NotImplementedError()
	
	@staticmethod
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
	def __init__(self, offset_table, compression_type, version):
		"""
		Builds the data for offset_table.
		
		offset_table is a iterable containing OffsetTableEntry objects.
		
		Actually only uses the record parts.
		"""
		MdxBlock.__init__(self, offset_table, compression_type, version)
		
	def get_index_entry(self):
		"""
		Returns a bytes object, containing the entry for this block in the record
		block index.
		"""
		if self._version == "2.0":
			format = ">QQ"
		else:
			format = ">LL"
		return struct.pack(format, self._comp_size, self._decomp_size)
	
	@staticmethod
	def _block_entry(t, version):
		return t.record_null
	
	@staticmethod
	def _len_block_entry(t):
		return len(t.record_null)
	
class MdxKeyBlock(MdxBlock):
	"""
	A class representing a key block.
	
	Has the ability to return (in the format suitable for insertion in an mdx file) 
	both the block itself, as well as the entry in the record block index for that
	block.
	"""
	def __init__(self, offset_table, compression_type, version):
		"""
		Builds the data for offset_table.
		
		offset_table is a iterable containing OffsetTableEntry objects.
		
		Only uses the key, key_len, key_null and offset fields, and effectively ignores record_null.
		"""
		MdxBlock.__init__(self, offset_table, compression_type, version)
		self._num_entries = len(offset_table)
		if version=="2.0":
			self._first_key = offset_table[0].key_null
			self._last_key = offset_table[len(offset_table)-1].key_null
		else:
			self._first_key = offset_table[0].key
			self._last_key = offset_table[len(offset_table)-1].key
		self._first_key_len = offset_table[0].key_len
		self._last_key_len = offset_table[len(offset_table)-1].key_len
	
	@staticmethod
	def _block_entry(t, version):
		if version == "2.0":
			format = ">Q"
		else:
			format = ">L"
		return struct.pack(format, t.offset)+t.key_null
	
	@staticmethod
	def _len_block_entry(t):
		return 8 + len(t.key_null) #This is only accurate for version 2.0, but we only need approximate size anyway
	
	def get_index_entry(self):
		"""Returns a bytes object, containing the header data for this block"""
		if self._version == "2.0":
			long_format = ">Q"
			short_format = ">H"
		else:
			long_format = ">L"
			short_format = ">B"
		return (
		    struct.pack(long_format, self._num_entries)
		  + struct.pack(short_format, self._first_key_len)
		  + self._first_key
		  + struct.pack(short_format, self._last_key_len)
		  + self._last_key
		  + struct.pack(long_format, self._comp_size)
		  + struct.pack(long_format, self._decomp_size)
		  )
		
	
	
		
