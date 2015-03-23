# Introduction

This is a description of the MDX file format, used by the [MDict](http://www.octopus-studio.com/product.en.htm) dictionary software. The software is not open-source, nor is the file format openly specified, so the following description is based on reverse-engineering, and is likely incomplete and inaccurate in its details.

Most of the information comes from https://bitbucket.org/xwang/mdict-analysis. While xwang mostly focuses on being able to read this unknown format, I have added details that are necessary to also write MDX files.

# Concepts

MDX files is designed to store a dictionary, i.e. a collection of pairs (keyword, record), which could be, for example, keyword="reverse engineering", record="<i>noun:</i> a process of analyzing and studying an object or device, in order to understand its inner workings".

# File structure

The basic file structure is a follows:

| MDX File       |            |
|----------------|------------|
| `header_sect`       | Header section. See "Header Section" below.  |
| `keyword_sect` | Keyword section. See "Keyword Section" below. |
| `record_sect`  | Record section. See "Record Section" below.  | 

# Header Section

| `header_sect` |Length  |   |
|---------------|---|-----------------|
| `length`      | 4 bytes | Length of `header_str`, in bytes. Big-endian.
| `header_str`  | varying | An XML string, encoded in UTF-16LE. See below for details. |
| `checksum`    | 4 bytes | ADLER32 checksum of `header_str`, stored little-endian.  |

The `header_str` consists of a single, XML tag `dictionary`, with various attributes. An example is (newlines added for clarity)


# Keyword Section

The keyword section contains all the keywords in the dictionary, divided into blocks, as well as information about the sizes of these blocks.

| `keyword_sect` | Length|      |
|----------------|--|------|
| `num_blocks`   | 8 bytes |Number of items in key_blocks. Big-endian. Possibly encrypted, see below. |
| `num_entries`  | 8 bytes | Total number of keywords. Big-endian. Possibly encrypted, see below. |
| `key_index_decomp_len` | 8 bytes | Number of bytes in decompressed version of key_index. Big-endian. Possibly encrypted, see below. |
| `key_index_comp_len`   | 8 bytes | Number of bytes in compressed version of key_index (including the `comp_type` and `checksum` parts). Big-endian. Possibly encrypted, see below. |
| `key_blocks_len`       | 8 bytes | Total number of bytes taken up by key_blocks. Big-endian. Possibly encrypted, see below. |
| `checksum`             | 4 bytes | ADLER32 checksum of the preceding 40 bytes. If those are encrypted, it is the checksum of the decrypted version. Big-endian. |
| `key_index`            | varying | The keyword index, compressed and possibly encrypted. See below. |
| `key_blocks[0]`         | varying | A compressed block containing keywords, compressed. See below.  |
| ...                    |    ...  | ...|
| `key_blocks[num_blocks-1]`         | varying |... |

## Encryption:

If the parameter `Encrypted` in the header has the lowest bit set (i.e. `Encrypted | 1` is nonzero), then the 40-byte block from `num_blocks` are encrypted. The encryption used is Salsa20/8 (Salsa20 with 8 rounds instead of 20). The parameters are:

* Key length: 128 bits
* IVs length: 64 bits.
* Ivs: all zeros (i.e. "\x00\x00\x00\x00\x00\x00\x00\x00").
* Key: `RIPEMD128(encryption_key)`, where `encryption_key` is the dictionary password specified on creation of the MdxDocument.

## Keyword index

The keyword index lists some basic data about the key blocks. It it compressed (see "Compression"), and possibly encrypted (see "Keyword index encryption"). After decompression and decryption, it looks like this

| `decompress(keyword_sect)` | Length |  |
|----------------------------|--|----|
| `num_entries[0]`          | 8 bytes | Number of keywords in the first keyword block. |
| `first_size[0]`           | 2 bytes | Length of `first_word[0]`, not including trailing null character. In number of "basic units" for the encoding, so e.g. bytes for UTF-8, and 2-byte units for UTF-16. |
| `first_word[0]`           | varying | The first keyword (alphabetically) in the `key_blocks[0]` keyword block. Encoding given by `Encoding` attribute in the header. |
| `last_size[0]`           | 2 bytes | Length of `last_word[0]`, not including trailing null character. In number of "basic units" for the encoding, so e.g. bytes for UTF-8, and 2-byte units for UTF-16. |
| `last_word[0]`            | varying | The last keyword (alphabetically) in the `key_blocks[0]` keyword block. Encoding given by `Encoding` attribute in the header. |
| `comp_size[0]`            | 8 bytes | Compressed size of key_blocks[0]. |
| `decomp_size[0]`          | 8 bytes | Decompressed size of key_blocks[0]. |
| `num_entries[1]`          | 8 bytes |...|
| ...                       |      ...|...|
| `decomp_size[num_blocks-1]` | 8 bytes |...|

### Keyword index encryption:

If the parameter `Encrypted` in the header has its second-lowest bit set (i.e. `Encrypted | 2` is nonzero), then the keyword index is further encrypted. In this case, the `comp_type` and `checksum` fields will be unchanged (refer to the section Compression), the following C function
will be used to encrypt the `compressed_data` part, after compression.

    #define SWAPNIBBLE(byte) (((byte)>>4) | ((byte)<<4))
    void encrypt(unsigned char* buf, size_t buflen, unsigned char* key, char* keylen) {
    	unsigned char prev=0x36;
    	for(size_t i=0; i < buflen; i++) {
    		buf[i] = SWAPNIBBLE(buf[i] ^ ((unsigned char)i) ^ key[i%keylen] ^ previous);
    		previous = buf[i];
    	}
    }

The encryption key used is `ripemd128(checksum + "\x95\x36\x00\x00")`, where + denotes string concatenation.

## Keyword blocks

Each keyword is compressed (see "Compression"). After decompressing, they look like this:

| `decompress(key_blocks[0])` | Length  |   |
|-----------------|---------|---|
| `offset[0]`     | 8 bytes | Offset where the record corresponding to `key[0]` can be found, see below. Big-endian. |
| `key[0]`        | varying | The first keyword in the dictionary, null-terminated and encoded using `Encoding`.  |
| `offset[1]`     | 8 bytes | ... |
| `key[1]`        | varying | ... |
| ...             |   ... | ... |

The offset should be interpreted as follows: Decompress all record blocks, and concatenate them together, and let `records` denote
the resulting array of bytes. The record corresponding to `key[i]` then starts at `records[offset[i]]`. 

# Record section

The record section looks like this:

| `record_sect`   | Length  |    |
|-----------------|---------|----|
| `num_blocks` | 8 bytes | Number items in `record_blocks`. Does not need to equal the number of keyword blocks. Big-endian. |
| `num_entries` | 8 bytes | Total number of records in dictionary. Should be equal to `keyword_sect.num_entries`. Big-endian. |
| `index_len` | 8 bytes | Total size of the `comp_size[i]` and `decomp_size[i]` variables, in bytes. In other words, should equal 16 times `num_blocks`. Big-endian. |
| `blocks_len` | 8 bytes | Total size of the `rec_block[i]` sections, in bytes. Big-endian. |
| `comp_size[0]` | 8 bytes | Length of `rec_block[0]`, in bytes. Big-endian. |
| `decomp_size[0]` | 8 bytes | Decompressed size of `rec_block[i]`, in bytes. Big-endian. |
| `comp_size[1]` | 8 bytes | Length of `rec_block[1]`, in bytes. Big-endian. |
| ...           |   ...    |  ... |
| `decomp_size[num_blocks-1]` | 8 bytes | ... |
| `rec_block[0]` | varying | A compressed block containing records. See below. |
| ...           |     ... | ... |
| `rec_block[num_blocks-1]` | varying |...|

## Record block

Each record block is compressed (see "Compression"). After decompressing, they look like this:

| `decompress(rec_block[0])` | Length | |
|----------------------------|--------|--|
| `record[0]`                | varying | The first record, null-terminated and encoded using `Encoding`. |
| `record[1]`                | varying |...|
| ...                        |   ...   |...|

# Compression:

Various data blocks are compressed using the same scheme. These all look like these:

| `compress(data)`  | Length |  |
|-------------------|--------|--|
| `comp_type`       | 4 bytes | Compression type. See below. |
| `checksum`        | 4 bytes | ADLER32 checksum of the uncompressed data. Big-endian. |
| `compressed_data` | varying | Compressed version of `data`.|

The compression type can be indicated by `comp_type`. There are three options:

 * If `comp_type` is `'\x02\x00\x00\x00'`, then no compression is applied at all, and `compressed_data` is equal to `data`.
 * If `comp_type` is `'\x01\x00\x00\x00'`, LZO compression is used.
 * If `comp_type` is `'\x00\x00\x00\x00'`, zlib compression is used. It so happens that the zlib compression format appends an ADLER32 checksum, so in this case, `checksum` will be equal to the last four bytes of `compressed_data`.
