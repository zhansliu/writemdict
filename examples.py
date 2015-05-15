# -*- coding: utf8 -*-

from __future__ import unicode_literals, print_function, absolute_import, division

# This file contains examples of how to use the different features of the writemdict library.
# Run it with "python examples.py". It will create various .mdx files in the example_output/
# directory.

from writemdict import MDictWriter, encrypt_key
from ripemd128 import ripemd128
import io


# This is the dictionary we will use.
d = {
    "alpha":"<i>alpha</i>",
    "beta":"Letter <b>beta</b>",
    "gamma":"Capital version is Γ &lt;"}

### Example 1: Basic writing. All options default.
outfile = open("example_output/basic.mdx", "wb")
writer = MDictWriter(d, "Basic dictionary", "This is a basic test dictionary.")
writer.write(outfile)
outfile.close()


### Example 2: Demonstrates the use of UTF-16 encoding.
outfile = open("example_output/utf16.mdx", "wb")
writer = MDictWriter(d, 
                     "UTF-16 dictionary", 
                     "This is a test for the \"UTF-16\" encoding.",
                     encoding="utf-16")
writer.write(outfile)
outfile.close()

### Example 3: This is a test to create a UTF-16 dictionary containing characters outside the
#              Basic Multilingual Plane
d2 = {"𩷶":"A fish"}
outfile = open("example_output/utf16nonbmp.mdx", "wb")
writer = MDictWriter(d2, 
                     "UTF16 non-BMP dictionary", 
                     "This test support for characters outside the Basic Multilingual Plane",
                     encoding="utf-16")
writer.write(outfile)
outfile.close()

### Example 4: Uses the Big5 encoding.
outfile = open("example_output/big5.mdx", "wb")
writer = MDictWriter(d, 
                     "Big5 dictionary",
                     "This is a test for the \"Big5\" encoding.",
                     encoding="big5")
writer.write(outfile)
outfile.close()

### Example 5: Uses the GBK encoding.
outfile = open("example_output/gbk.mdx", "wb")
writer = MDictWriter(d, 
                     "GBK dictionary", 
                     "This is a test for the \"GBK\" encoding", 
                     encoding="gbk")
writer.write(outfile)
outfile.close()


### Example 6: Demonstrate encryption of the keyword index. (Option "Disallow export" in MdxBuilder.)
outfile = open("example_output/key_index_encryption.mdx", "wb")
writer = MDictWriter(d, 
                     "Dictionary disallowing export",
                     "This dictionary demonstrates keyword index encryption",
                     encrypt_index=True)
writer.write(outfile)
outfile.close()

### Example 7: Use version 1.2 of the file format instead.
outfile = open("example_output/version12.mdx", "wb")
writer = MDictWriter(d, 
                     "Version 1.2 dictionary",
                     "This dictionary tests version 1.2 of the file format",
                     version="1.2")
writer.write(outfile)
outfile.close()

### Example 8: A version 1.2 dictionary using UTF-16.
outfile = open("example_output/version12utf16.mdx", "wb")
writer = MDictWriter(d, 
                     "Version 1.2 UTF-16 dictionary",
                     "This dictionary tests version 1.2 of the file format, using UTF-16",
                     encoding="utf16",
                     version="1.2")
writer.write(outfile)
outfile.close()

### Example 9: Encryption test, using an external .key file
#              This creates two files: encrypted_external_regcode.mdx and encrypted_external_regcode.key.
#              To open, the user needs to set his/her email to "example@example.com" in the MDict reader.
outfile = open("example_output/encrypted_external_regcode.mdx", "wb")
writer = MDictWriter(d,
                     "Encrypted dictionary",
                     "This dictionary tests encryption",
                     encoding="utf8",
                     version="2.0",
                     encrypt_key=b"my password")
writer.write(outfile)
outfile.close()
key = encrypt_key(b"my password", "example@example.com".encode("ascii"))
keyfile = io.open("example_output/encrypted_external_regcode.key", "w", encoding="ascii")
keyfile.write(key)
keyfile.close()

### Example 10: Encryption test, with the registration code supplied with the dictionary.
#               To open, the user needs to set his/her email to "example@example.com" in the MDict reader.
outfile = open("example_output/encrypted_internal_regcode.mdx", "wb")
writer = MDictWriter(d, 
                     "Encrypted dictionary",
                     "This dictionary tests encryption, with key supplied in dictionary header",
                     encoding="utf8",
                     version="2.0",
                     encrypt_key=b"abc",
                     user_email="example@example.com".encode("ascii"))
writer.write(outfile)
outfile.close()

### Example 11: Basic dictionary, with no compression. 
outfile = open("example_output/no_compression.mdx", "wb")
writer = MDictWriter(d,
                     "Uncompressed dictionary",
                     "This is a test of the basic dictionary, with compression type 0 (no compression).",
                     compression_type=0)
writer.write(outfile)
outfile.close()

### Example 12: Basic dictionary, with LZO compression:
#               Only works if python-lzo is installed.
outfile = open("example_output/lzo_compression.mdx", "wb")
try:
	writer = MDictWriter(d, "LZO compressed dictionary", "This tests the LZO compression type.", compression_type=1)
	writer.write(outfile)
except NotImplementedError:
	print("python-lzo not installed. Skipping LZO test.")
outfile.close()
	


