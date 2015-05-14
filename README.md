# Summary

writemdict is a Python library that generates dictionaries in the .mdx file format used by [Mdict](http://www.octopus-studio.com/index.en.htm). In addition to the official client, there are various other 
applications for different platforms that can use the generated dictionary files. 

It works in Python 2 (>=2.6) as well as in Python 3.

The .mdx file format is not openly documented. Therefore, this library only supports some of the (presumed)
features of the format. Among the supported features are:

* Versions 1.2 and 2.0 of the file format
* gzip or LZO compression (the latter with the python-lzo library).
* encrypted .mdx files (two different encryption schemes)
* 4 different character encodings.

# Files

* writemdict.py: the main file of the project.
* ripemd128.py: a simple implementation of RIPEMD128 in pure Python.
* pureSalsa20.py: implements the Salsa20 stream cipher in pure Python. This version includes support for Python 3.
* testwrite.py: tests the functionality of the library by writing dictionaries using different options to the subdirectory
testoutput/. These should be opened with the official MDict client to verify that they are correctly written.
* README.md: this file.
* fileformat.md: A description of the mdx file format.

# Optional dependency

To support LZO compression, the python-lzo library must be installed.

# Usage example

The main file

A very simple example, demonstrating the use of this library:

    from __future__ import unicode_literals
    from writemdict import MDictWriter

    dictionary = {"doe": "<b>doe</b> <i>n.</i> a deer, a female deer.",
                  "ray": "<b>ray</b> <i>n.</i> a drop of golden sun.",
                  "me": "<b>me</b> <i>pron.</i> a name I call myself.",
                  "far": "<b>far</b> <i>adv.</i> a long, long way to run."}

    writer = MDictWriter(dictionary, title="Example Dictionary", description="This is an example dictionary.")
    outfile = open("dictionary.mdx", "wb")
    writer.write(outfile)
    outfile.close()

This creates a dictionary with four entries: "doe", "ray", "me", and "far", and their corresponding definitions.

# File format

This project primarily represents an effort in reverse-engineering and documenting the file format used for .mdx files.
A description of the format (version 2.0 only) can be found in [fileformat.md](./fileformat.md)

# See also

This project is based on [xwang's mdict analysis](https://bitbucket.org/xwang/mdict-analysis), the first attempt to
publically document the Mdict file format. That project also includes a python library for reading mdx files.

# To do

* Add support for MDD files
* Describe version 1.2 of the file format as well.




