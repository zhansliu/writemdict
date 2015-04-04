#!/usr/bin/env python
# coding: utf-8
from __future__ import print_function

"""
    testSalsa20.py -- tests for pySalsa20.py and pureSalsa20.py
    This is based on the test code in Larry Bugbee's pySalsa20.py.
     
    Usage:
        python testSalsa20.py   [tries to import and test both]
    or  python testSalsa20.py pySalsa20
    or  python testSalsa20.py pureSalsa20
"""

_version = 'p4.0'

# import pySalsa20/libsalsa20 and/or pureSalsa20 with import_salsa(), below.

from struct import Struct
little16_i32 = Struct( "<16i" )  # 16 little-endian 32-bit signed ints.
native16_i32 = Struct( "=16i" )  # 16 native-order 32-bit signed ints.

from ctypes import c_buffer
from sys import argv
import binascii



# -----------------------------------------------------------------------
# Salsa20, the class, gets imported from pySalsa20 or pureSalsa20,
# depending on which is being tested.
#
# Subclass the two Salsa20 implementations to 
#       provide a "salsa20core()" method, and
#       allow forcing the number of rounds to strange numbers.
#
# The job of the salsa20core() method is
#       Input is an already-prepared 64-character (512 bit) key block with
#          no data block to be xor'd with; return the hashed bits as a string.
#       Use the innermost function Python has access to:
#          For pySalsa20:   libSalsa20.ECRYPT_encrypt_bytes
#          For pureSalsa20: its own salsa20_wordtobyte()
#       NOT to be judged for speed since it's a test wrapper.
# Because we won't know until runtime whether a given implementation exists
# or is going to be tested, here are functions that define and return
# the subclassed Salsa20 class.

def patch_pySalsa20():
    """ \
    Define and return a testing version of pySalsa20's Salsa20 class.
    """

    class Testing_pysalsa20( pySalsa20.Salsa20 ):

        def salsa20core( self, input, nRounds ):
            """ Do nRounds Salsa20 rounds on input, a 64-byte string.
                Returns a 64-byte string.  SETS ROUNDS GLOBAL IN LIBSALSA20.
                """
            try:
                libSalsa20.set_rounds( nRounds )
            except:
                msg  = '*** Your libsalsa20 does not support the '  \
                     + 'set_rounds() function; some tests will fail ' \
                     + 'because of this.'
                print(msg)

            assert type( input ) == bytes, 'input must be byte string'
            assert len( input ) == 64, 'input must be 64-byte string'

            NUL_message = c_buffer( 64 ) # to be xored with hash output
            output = c_buffer( 64 )
            # Interpret each four input bytes as a little-endian word,
            # then repack as native-order words for the C routine:
            ctx = native16_i32.pack( *little16_i32.unpack( input ) )
            libSalsa20.ECRYPT_encrypt_bytes( ctx, NUL_message, output, 64 )
            return output.raw[:64]


        def force_nRounds( self, nRounds ):
            """ \
            Set # of rounds bypassing the "in [8,12,20]" check, for testing.
            """
            libSalsa20.set_rounds( nRounds )


    # Return the class:
    return Testing_pysalsa20


def patch_pureSalsa20():
    """ \
    Define and return a testing version of pureSalsa20's Salsa20 class.
    """

    class Testing_puresalsa20( pureSalsa20.Salsa20 ):

        def salsa20core( self, input, nRounds ):
            assert type( input ) == bytes, 'input must be byte string'
            assert len( input ) == 64, 'input must be 64-byte string'

            # Interpret each four input bytes as a little-endian word,
            # placing into a Python list of ints.
            ctx = little16_i32.unpack( input )
            w2b = pureSalsa20.salsa20_wordtobyte
            return w2b( ctx, nRounds, checkRounds=False )


        def force_nRounds( self, nRounds ):
            """ \
            Set # of rounds bypassing the "in [8,12,20]" check, for testing.
            """
            self.setRounds( nRounds, testing=True )

    # Return the class:
    return Testing_puresalsa20


def trunc32( w ):
    """ Return the bottom 32 bits of w as a Python int.
        This may create a long temporarily, but returns an int. """
    w = int( ( w & 0x7fffFFFF ) | ( - ( w & 0x80000000 ) ) )
    assert type(w) == int
    return w


def t32( a ):  return tuple( trunc32(x) for x in a )

# These are the blocks in the example in "The Salsa20 family of cyphers,"
# http://cr.yp.to/snuffle/salsafamily-20071225.pdf , section 4.1:

input_block = t32( [ 0x61707865, 0x04030201, 0x08070605, 0x0c0b0a09, 
                     0x100f0e0d, 0x3320646e, 0x01040103, 0x06020905, 
                     0x00000007, 0x00000000, 0x79622d32, 0x14131211, 
                     0x18171615, 0x1c1b1a19, 0x201f1e1d, 0x6b206574  ] )

below_diag = t32( [ 0x61707865, 0x04030201, 0x08070605, 0x95b0c8b6, 
                    0xd3c83331, 0x3320646e, 0x01040103, 0x06020905, 
                    0x00000007, 0x91b3379b, 0x79622d32, 0x14131211, 
                    0x18171615, 0x1c1b1a19, 0x130804a0, 0x6b206574  ] )

below_below = t32( [ 0x61707865, 0x04030201, 0xdc64a31d, 0x95b0c8b6, 
                     0xd3c83331, 0x3320646e, 0x01040103, 0xa45e5d04, 
                     0x71572c6d, 0x91b3379b, 0x79622d32, 0x14131211, 
                     0x18171615, 0xbb230990, 0x130804a0, 0x6b206574  ] )

continues_down = t32( [ 0x61707865, 0xcc266b9b, 0xdc64a31d, 0x95b0c8b6, 
                        0xd3c83331, 0x3320646e, 0x95f3bcee, 0xa45e5d04, 
                        0x71572c6d, 0x91b3379b, 0x79622d32, 0xf0a45550, 
                        0xf3e4deb6, 0xbb230990, 0x130804a0, 0x6b206574  ] )

modifies_diag = t32( [ 0x4dfdec95, 0xcc266b9b, 0xdc64a31d, 0x95b0c8b6, 
                       0xd3c83331, 0xe78e794b, 0x95f3bcee, 0xa45e5d04, 
                       0x71572c6d, 0x91b3379b, 0xf94fe453, 0xf0a45550, 
                       0xf3e4deb6, 0xbb230990, 0x130804a0, 0xa272317e  ] )

one_round = t32( [ 0x4dfdec95, 0xd3c83331, 0x71572c6d, 0xf3e4deb6, 
                   0xcc266b9b, 0xe78e794b, 0x91b3379b, 0xbb230990, 
                   0xdc64a31d, 0x95f3bcee, 0xf94fe453, 0x130804a0, 
                   0x95b0c8b6, 0xa45e5d04, 0xf0a45550, 0xa272317e  ] )

two_rounds = t32( [ 0xba2409b1, 0x1b7cce6a, 0x29115dcf, 0x5037e027, 
                    0x37b75378, 0x348d94c8, 0x3ea582b3, 0xc3a9a148, 
                    0x825bfcb9, 0x226ae9eb, 0x63dd7748, 0x7129a215, 
                    0x4effd1ec, 0x5f25dc72, 0xa6c3d164, 0x152a26d8  ] )

twenty_rounds = t32( [ 0x58318d3e, 0x0292df4f, 0xa28d8215, 0xa1aca723, 
                       0x697a34c7, 0xf2f00ba8, 0x63e9b0a1, 0x27250e3a, 
                       0xb1c7f1f3, 0x62066edc, 0x66d3ccf1, 0xb0365cf3, 
                       0x091ad09e, 0x64f0c40f, 0xd60d95ea, 0x00be78c9  ] )

output_block = t32( [ 0xb9a205a3, 0x0695e150, 0xaa94881a, 0xadb7b12c, 
                      0x798942d4, 0x26107016, 0x64edb1a4, 0x2d27173f, 
                      0xb1c7f1fa, 0x62066edc, 0xe035fa23, 0xc4496f04, 
                      0x2131e6b3, 0x810bde28, 0xf62cb407, 0x6bdede3d  ] )


def test_salsa20core( module, module_name ):
    print("Testing " + module_name + ".salsa20core" + "...")
    passed = True

    input_block_packed = little16_i32.pack( *input_block )
    assert little16_i32.unpack( input_block_packed ) == input_block

    s20 = salsa20_test_classes[module_name]( )    
    x = s20.salsa20core( little16_i32.pack( *input_block), 2 )
    y = t32( ti + ii for (ti,ii) in zip( two_rounds, input_block ) )
    if little16_i32.unpack(x) != y:
        print("salsa20core( input_block, 2 ) should ==", end=" ")
        print("two_rounds + input_block, but it doesn't.")
        passed = False

    x = s20.salsa20core( little16_i32.pack( *input_block), 20 )
    if little16_i32.unpack(x) != output_block:
        print("salsa20core( input_block, 20 ) should ==", end=" ")
        print("output_block, but it doesn't.")
        passed = False

    if passed:
        print("Passed.")

    return passed


 
#---------------------------------------------------------------------------
# Tests for the 32-bit operations in pureSalsa20.py .


def rot32long( w, nLeft ):
    """ \
    A simpler, slower rot32 to test the tester and compare speeds.
    This creates longs temporarily, but returns an int.
    For comparison with rot32().  It's about half as fast.
    """
    w &= 0xffffFFFF
    nLeft &= 31  # which makes nLeft >= 0
    w = ( w << nLeft ) | ( w >> ( 32 - nLeft ) )
    return int( ( w & 0x7fffFFFF ) | ( - ( w & 0x80000000 ) ) )



def test_add32( add32, name ):
    import random

    print("Testing"+ name + "...")
    passed = True
    # Try all combinations of these groups of bits:
    groups = [ 0x00000001, 0x00003FFE, 0x00004000,  0x00008000, 
               0x00010000, 0x3FFE0000, 0x40000000, -0x80000000 ]
    ng = len( groups )
    inputs = []
    for i in range( 2 ** ng ):
        inputs.append( sum( [ groups[p] for p in range(ng) if (1<<p) & i ] ) )
    # Also mix in some random numbers:
    for i in range( 2 ** ng ):
        inputs.append( int( random.randrange( -1 << 31, 1 << 31 ) ) )
    for a in inputs:
        for b in inputs:
            x = add32( a, b )
            y = trunc32( a + b )
            if x != y:
                print(name + (
                      "( 0x%08x, 0x%08x ) => 0x%08x, should be 0x%08x." % (
                      a & 0xffffFFFF,  b & 0xffffFFFF, x & 0xffffFFFF,  
                      y & 0xffffFFFF )
                      ))
                passed = False

            if type(x) != type(0):
                print(name + "( 0x%08x, 0x%08x ) => 0x%08x, but" % (
                      a & 0xffffFFFF,  b & 0xffffFFFF, x & 0xffffFFFF,  
                      ) +  type(x))
                passed = False

    if passed:
        print("Passed.")
    else:
        print("Failed.")
        return passed

    from time import time

    print("speed test...")
    start = time()
    for i in range(100):
        a = int( random.randrange( -1 << 31, 1 << 31 ) )
        for j in range( 100 ):
            b = int( random.randrange( -1 << 31, 1 << 31 ) )
            for k in range( 10 ):
                add32( a, b )
                add32( a, b )
                add32( a, b )
                add32( a, b )
                add32( a, b )
                add32( a, b )
                add32( a, b )
                add32( a, b )
                add32( a, b )
                add32( a, b )
    duration = time() - start
    nCalls = 100 * 100 * 10 * 10
    print("Seconds per call:", duration/nCalls, "--", 
          nCalls/duration, "calls/sec")
    return passed


def test_rot32( rot32, name ):
    import random

    print("Testing", name, "...")
    passed = True
    for j in range( -32, 33 ):
        for i in range( 32 ):
            w = trunc32( 1 << i )
            x = rot32( w, j )
            y = trunc32( 1 << ( ( i + j ) & 31 ) )
            if x != y:
                print(name + "( 0x%08x, %d ) => 0x%08x, should be 0x%08x." % (
                       w & 0xffffFFFF,  j,  x & 0xffffFFFF,  y & 0xffffFFFF ))
                passed = False
            if type(x) != type(0):
                print(name + "( 0x%08x, %d ) => 0x%08x, but" % (
                        w & 0xffffFFFF,  j,  x & 0xffffFFFF ), type(x))
                passed = False

            if passed:
                w = int( random.randrange( -1 << 31, 1 << 31 ) )
                x = rot32( w, j )
                y = rot32( x, -j )
                if y != w:
                    print(name + "( 0x%08x, %d ) => 0x%08x,  " % (
                           w & 0xffffFFFF,  j,  x & 0xffffFFFF ), end="")
                    print(name + "( 0x%08x, %d ) => 0x%08x" % (
                           x & 0xffffFFFF,  -j,  y & 0xffffFFFF ))
                    passed = False
            
    if passed:
        print("Passed.")
    else:
        print("Failed.")
        return passed

    from time import time

    print("speed test...")
    start = time()
    for k in range(100):
        w = int( random.randrange( -1 << 31, 1 << 31 ) )
        for i in range( 10 ):
            for j in range( -31, 32 ):
                rot32( w, j )
                rot32( w, j )
                rot32( w, j )
                rot32( w, j )
                rot32( w, j )
                rot32( w, j )
                rot32( w, j )
                rot32( w, j )
                rot32( w, j )
                rot32( w, j )
    duration = time() - start
    nCalls = 100 * 10 * 63 * 10
    print("Seconds per call:", duration/nCalls, "--", end="")
    print(nCalls/duration, "calls/sec")
    return passed


#--------------------------------------------------------------------------
# utilities

def savetofile(filename, content):
    "write content to a file [as binary]"
    f = open(filename, 'wb')
    f.write(content)
    f.close()
    
def loadfmfile(filename):
    "get [binary] content from a file"
    f = open(filename, 'rb')
    content = f.read()
    f.close()
    return content

def bytestring(hex):
    "remove whitespace and convert hex string to a byte string"
    return binascii.unhexlify(hex.replace(' ', '').replace('\n', ''))

#--------------------------------------------------------------------------
# Run 32-bit-ops tests if pureSalsa20, and test encryption per se.

def test( module, module_name ):
    print("===== Testing", module_name, "version", module._version, "=====")
    from sys import stdout

    passed = True

    if 1:  # Test these if the module has them:
        if "rot32" in module.__dict__:
            passed &= test_rot32( module.rot32, module_name+".rot32" )
            # Compare to slow version:
            passed &= test_rot32( rot32long, "rot32long" )
        print()

        if "add32" in module.__dict__:
            passed &= test_add32( module.add32, module_name+".add32" )

    if 1 and passed:
        test_salsa20core( module, module_name )

    if 1 and passed:
        rounds  = 8                     # may be 8, 12, or 20
    
        if 0:
            message = loadfmfile('testdata.txt')
        else:
            message = b'Kilroy was here!  ...there, and everywhere.'
        key     = b'myKey67890123456'    # 16 or 32 bytes, exactly
        nonce   = b'aNonce'              # do better in real life
        IV      = (nonce+b'*'*8)[:8]     # force to exactly 64 bits

        print("Testing decrypt(encrypt(short_message))==short_message...")
        # encrypt
        s20 = salsa20_test_classes[module_name]( key, IV, rounds )
        ciphertxt = s20.encryptBytes(message)
        
        # decrypt
        s20 = salsa20_test_classes[module_name]( key, IV, rounds )
        plaintxt  = s20.encryptBytes(ciphertxt)
    
        if message == plaintxt:
            print('    *** good ***')
        else:
            print('    *** bad ***')
            passed = False


    if 1 and passed:    # one known good 8-round test vector 
        print("Testing known 64-byte message and key...")
        rounds = 8      # must be 8 for this test
        message = b'\x00'*64
        key = binascii.unhexlify('00000000000000000000000000000002')
        IV  = binascii.unhexlify('0000000000000000')
        out64 = bytestring("""
               06C80B8CEC60F0C2E73EB6ED5DCB1B9C
               39B210F1AB76FEDF1A6B7AE370DA0F20
               0CEBCAD6EF6E57AC80E4375C035FA44D
               3AE4DC2C2507757DAF37B14F36643489""")
        s20 = salsa20_test_classes[module_name]( key, IV, rounds )
        s20.setIV(IV)
        ciphertxt = s20.encryptBytes(message)
        s20 = salsa20_test_classes[module_name]( key, IV, rounds )
        plaintxt  = s20.encryptBytes(ciphertxt)
        if (message == plaintxt and
            ciphertxt[:64] == out64):
            print('    *** vector 1 good ***')
        else:
            print('    *** vector 1 bad ***')
            passed = False
        
    if 1 and passed:    # one known good 8-round test vector 
        print("Testing known key and 64k message...")
        rounds = 8      # must be 8 for this test
        message = b'\x00'*65536
        key = binascii.unhexlify('0053A6F94C9FF24598EB3E91E4378ADD')
        IV  = binascii.unhexlify('0D74DB42A91077DE')
        out64 = bytestring("""
               75FCAE3A3961BDC7D2513662C24ADECE
               995545599FF129006E7A6EE57B7F33A2
               6D1B27C51EA15E8F956693472DC23132
               FCD90FB0E352D26AF4DCE5427193CA26""")
        out65536 = bytestring("""
               EA75A566C431A10CED804CCD45172AD1
               EC4930E9869372B8EDDF303098A8910C
               EE123BF849C51A33554BA1445E6B6268
               4921F36B77EADC9681A2BB9DDFEC2FC8""")
        s20 = salsa20_test_classes[module_name]( key, IV, rounds )
        ciphertxt = s20.encryptBytes(message)
        s20 = salsa20_test_classes[module_name]( key, IV, rounds )
        plaintxt  = s20.encryptBytes(ciphertxt)
        if (message == plaintxt and
            ciphertxt[:64] == out64 and
            ciphertxt[65472:] == out65536):
            print('    *** vector 2 good ***')
        else:
            print('    *** vector 2 bad ***')
            passed = False

    if 1 and passed:    # some rough speed tests
        from time import time
        from math import ceil

        print("Speed tests...")
        names = {}
        speeds = {}
        message_lens = [ 64, 2**16 ]
        #                    64-byte message     65536-byte message
        # Salsa20/4000: 12345678.9 bytes/sec   12345678.9 bytes/sec
        namefmt = "%13s"
        print(namefmt % " ", end=" ")
        msg_len_fmt =  "%7d-byte message  "
        speed_fmt =    "%10.1f bytes/sec  "
        for msg_len in message_lens:
            print(msg_len_fmt % msg_len,end=" ")
        print()

        for nRounds in [ 8, 20, 4000 ]:
            names[ nRounds ] = "Salsa20/" + repr(nRounds) + ":"
            print(namefmt % names[ nRounds ], end=" ")
            speeds[ nRounds ] = {}
            if nRounds <= 20: lens = message_lens
            else:             lens = message_lens[ 0 : -1 ]
            for msg_len in lens:
                message = b'\x00' * msg_len
                key = binascii.unhexlify('00000000000000000000000000000002')
                IV  = binascii.unhexlify('0000000000000000')
                s20 = salsa20_test_classes[module_name]( key, IV, 20 )
                s20.force_nRounds( nRounds )
                nreps = 1
                duration = 4.0
                while duration < 5: # sec.
                    # Aim for 6 seconds:
                    nreps = int( ceil( nreps * min( 4, 6.0/duration ) ) )
                    start = time()
                    for i in range( nreps ):
                        ciphertxt = s20.encryptBytes(message)
                    duration = time() - start
                speeds[ nRounds ][ msg_len ] = msg_len * nreps / duration
                print(speed_fmt % speeds[ nRounds ][ msg_len ], end=" ")
                stdout.flush()
            print()

    return passed
        
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

salsa20_modules = { "pureSalsa20": None, "pySalsa20": None }
salsa20_test_classes = { "pureSalsa20": None, "pySalsa20": None }


def import_salsa( module_names, verbose=False ):
    """ \
    Import the named salsa20 module(s), plus related stuff used for testing.
    Tolerates errors but for any failure leaves salsa20_modules[name] = None.
    """
    for name in module_names:
        if name == "pureSalsa20":
            try:
                global pureSalsa20
                import pureSalsa20
                salsa20_test_classes[name] = patch_pureSalsa20()
                salsa20_modules[name] = pureSalsa20
            except:
                if verbose: print("Problem importing pureSalsa20")
        elif name == "pySalsa20":
            try:
                global pySalsa20
                import pySalsa20
                global libSalsa20
                libSalsa20 = pySalsa20.loadLib('salsa20')
                salsa20_test_classes[name] = patch_pySalsa20()
                salsa20_modules[name] = pySalsa20
            except:
                if verbose:
                    print("Problem importing pySalsa20", end=" ")
                    print("or loading libsalsa20.so or salsa20.lib")
        else:
            if verbose:
                print("Don't know how to import", repr(n), "module.")


if __name__ == '__main__':
    passed = True
    if len(argv) > 1:
        asked = argv[ 1: ]
    else:
        asked = [ name for name in salsa20_modules ]
    import_salsa( asked )
    for name in asked:
        module = salsa20_modules[ name ]
        if module:
            passed &= test( module, name )
        elif len(argv) > 1: # Asked for it by name, but couldn't import?
            passed = False

    # Run import(s) again to show any problems:
    import_salsa( asked, verbose=True )
    if not passed:
       from sys import exit
       exit( 1 )

#--------------------------------------------------------------------------
#--------------------------------------------------------------------------
#--------------------------------------------------------------------------
