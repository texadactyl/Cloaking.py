'''
The following code provides a password-based security of a single file or
a single file system archive file (E.g. .tar.gz).

The source code is dependent on pycrypto, using the following capabilities:

    Password-based Key Derivation Function version 2 (PBKDF2)
    AES256 data cryptography in Cipher-Block Chaining (CBC) mode
    Hash-based Message Authentication Code (HMAC) function SHA512

This code is based on an example by Eli Bendersky (used as a starting point).
https://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/

Pycrypto reference: https://www.dlitz.net/software/pycrypto/
'''
from os.path import getsize
from os import urandom
from time import time
from struct import pack, unpack, calcsize
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA512

SIZE_HMAC = 64 # Bytearray size of an HMAC
SIZE_IV = 16 # Bytearray size of an IV
CHUNK_SIZE_MODULUS = 16 # Modulus for checking ciphertext chunk size (must = 0)
PAD = b'\xff'
STRUCT_LEULL = "<Q" # Little Endian Unsigned Long Long
STRUCT_ULL = "Q" # Unsigned Long Long
BOUNDARY = "BOUNDARY"
DEBUGGING = False

TIFF_PREFIX = [
    0x4d, 0x4d, 0x00, 0x2a, # TIFF Big Endian format
    0x00, 0x00, 0x00, 0x08, # Offset of the first IFD
    0x00, 0x08,             # There are 8 IFD entries (Tag)
    0x01, 0x00,             # Tag=ImageWidth (256)
    0x00, 0x04,                 #    Type=unsigned long
    0x00, 0x00, 0x00, 0x01,     #    Count=1
    0x00, 0x00, 0x00, 0x20,     #    Value=32
    0x01, 0x01,             # Tag=ImageLength (257)
    0x00, 0x04,                 #    Type=unsigned long
    0x00, 0x00, 0x00, 0x01,     #    Count=1
    0x00, 0x00, 0x00, 0x01,     #    Value=1
    0x01, 0x02,             # Tag=BitsPerSample (258)
    0x00, 0x03,                 #    Type=unsigned short
    0x00, 0x00, 0x00, 0x01,     #    Count=1
    0x00, 0x08, 0xff, 0xff,     #    Value=8
    0x01, 0x03,             # Tag=ImageCompression (259)
    0x00, 0x03,                 #    Type=unsigned short
    0x00, 0x00, 0x00, 0x01,     #    Count=1
    0x00, 0x01, 0xff, 0xff,     #    Value=1 (none)
    0x01, 0x06,             # Tag=PhotometricInterpretation (262)
    0x00, 0x03,                 #    Type=unsigned short
    0x00, 0x00, 0x00, 0x01,     #    Count=1
    0x00, 0x01, 0xff, 0xff,     #    Value=1 (BlackIsZero)
    0x01, 0x11,             # Tag=StripOffsets (273)
    0x00, 0x03,                 #    Type=unsigned short
    0x00, 0x00, 0x00, 0x01,     #    Count=1
    0x00, 0x6e, 0xff, 0xff,     #    Value=110 (offset to start of strip)
    0x01, 0x16,             # Tag=RowsPerStrip (278)
    0x00, 0x03,                 #    Type=unsigned short
    0x00, 0x00, 0x00, 0x01,     #    Count=1
    0x00, 0x01, 0xff, 0xff,     #    Value=1 (1 row per strip)
    0x01, 0x17,             # Tag=StripByteCounts (279)
    0x00, 0x03,                 #    Type=unsigned short
    0x00, 0x00, 0x00, 0x01,     #    Count=1
    0x00, 0x20, 0xff, 0xff,     #    Value=32 (same as ImageWidth)
    0x00, 0x00, 0x00, 0x00, # Offset to next IFD (none)
    0x4d, 0x4d              # 2 bytes of pad up to 7*16=112 bytes
]

def cloak_file(in_password,
               in_filename,
               out_filename,
               chunksize=64*1024):
    """
    Encrypts a file using AES (CBC mode) with
    a key produced from the given password.

    Parameters:
        in_password:
            This password is securely hashed to produce a 32-byte digest.
            The digest is used as the AES256 key.

        in_filename:
            Path name of the input cleartext file

        out_filename:
            Path name of output ciphertext file.

        chunksize:
            Sets the size of the read-file chunk which is
            used to read and encrypt the file.
            Larger chunk sizes can be faster for some files and machines.
            The chunksize must be divisible by 16.
            Default value: 64k.

    Returns:
        Elapsed time in seconds

    Raises:
        ValueError if chunksize mod 16 != 0
        IOError if something is wrong with input or output file
    """
    # Take start time
    tstart = time()
    # Get input file size (bytes)
    original_file_size = getsize(in_filename)
    # Validate chunksize
    if chunksize % CHUNK_SIZE_MODULUS != 0:
        raise ValueError("chunksize modulo 16 must be zero")
    # Convert password to an AES256 key
    key = sha256(in_password.encode()).digest()
    # Create a random Initialization Vector (IV)
    iv = urandom(SIZE_IV)
    # Create bytearray = TIFF prefix
    bytes_tiff_prefix = bytearray(TIFF_PREFIX)
    # Initialize AES encryptor and HMAC
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    hmac = HMAC.new(key, digestmod=SHA512)
    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            # Write out TIFF prefix (112 bytes)
            outfile.write(bytes_tiff_prefix)
            hmac.update(bytes_tiff_prefix)
            # Write out IV (16 bytes)
            outfile.write(iv)
            hmac.update(iv)
            # Write out file size unsigned long long field (8 bytes)
            packed_fs = pack(STRUCT_LEULL, original_file_size)
            outfile.write(packed_fs)
            hmac.update(packed_fs)
            # Write out boundary.
            boundary = BOUNDARY.encode()
            outfile.write(boundary)
            hmac.update(boundary)
            if DEBUGGING:
                print("\nDEBUG cloak hmac after boundary:", hmac.hexdigest())
            # Begin read/write loop
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    # Hit end of input file
                    if DEBUGGING:
                        print("\nDEBUG cloak hmac after last block:", hmac.hexdigest())
                    break
                elif len(chunk) % CHUNK_SIZE_MODULUS != 0:
                    # Final short block.  Apply padding
                    pad_size = CHUNK_SIZE_MODULUS \
                                - (len(chunk) % CHUNK_SIZE_MODULUS)
                    chunk += PAD * pad_size
                # else not final block.  It is full-sized.
                # Padded or not, write out encrypted block.
                outfile.write(encryptor.encrypt(chunk))
                # If padded, the pads are included in HMAC
                hmac.update(chunk)
            # Done with read/write loop: Write out HMAC.
            outfile.write(hmac.digest())

    # Done - return elapsed time
    return time() - tstart

def uncloak_file(in_password,
                 in_filename,
                 out_filename,
                 chunksize=64*1024):
    """
    Decrypts a file using AES (CBC mode) with
    a key produced from the given password.

    Parameters:
        in_password:
            Same description as for cloak_file.

        in_filename:
            Path name of the input ciphertext file

        out_filename:
            Path name of output cleartext file.

        chunksize:
            Same description as for cloak_file..

    Returns:
        Elapsed time in seconds

    Raises:
        ValueError if chunksize mod 16 != 0
        IOError if something is wrong with input or output file
        UserWarning if the input file as not created with cloak_file()
            or is corrupted
    """
    # Take start time
    tstart = time()
    # Convert password to an AES256 key
    key = sha256(in_password.encode()).digest()
    # Create bytearray = expected TIFF prefix
    expected_tiff_prefix = bytearray(TIFF_PREFIX)
    # Initialize HMAC accumulation.
    hmac = HMAC.new(key, digestmod=SHA512)

    with open(in_filename, 'rb') as infile:
        # Get input file TIFF prefix and validate it.
        observed_tiff_prefix = infile.read(len(expected_tiff_prefix))
        if observed_tiff_prefix != expected_tiff_prefix:
            raise UserWarning("*** Uncloak_file: Input file is missing the standard prefix")
        hmac.update(observed_tiff_prefix)
        # Get IV
        iv = infile.read(SIZE_IV)
        hmac.update(iv)
        # Get input file file size as a unsigned long long
        packed_fs = infile.read(calcsize(STRUCT_ULL))
        original_file_size = unpack(STRUCT_LEULL, packed_fs)[0]
        hmac.update(packed_fs)
        # Get boundary.
        observed_boundary = expected_boundary = BOUNDARY.encode()
        expected_boundary = infile.read(len(observed_boundary))
        if expected_boundary != observed_boundary:
            raise UserWarning("*** Uncloak_file: Input file missing the boundary")
        hmac.update(observed_boundary)
        if DEBUGGING:
            print("\nDEBUG uncloak hmac after boundary:", hmac.hexdigest())
        # Initialize AES256 decryptor with IV
        decryptor = AES.new(key, AES.MODE_CBC, iv)
        # Initialize byte-countdown = original file size + pad size
        countdown = original_file_size
        if countdown % CHUNK_SIZE_MODULUS != 0:
            pad_size = CHUNK_SIZE_MODULUS - (countdown % CHUNK_SIZE_MODULUS)
            countdown += pad_size

        computed_file_size = 0
        with open(out_filename, 'wb') as outfile:
            while True:
                # Down to the HMAC (last) chunk)?
                if countdown == 0:
                    chunk = infile.read(SIZE_HMAC)
                    expected_hmac = hmac.digest()
                    if expected_hmac == chunk:
                        # Success. Break out of read/write loop.
                        break
                    else:
                        # Oops. Invalid HMAC detected in input file
                        print("\n*** Uncloak_file computed   hmac: len=", \
                              len(expected_hmac), ", data=", hmac.hexdigest())
                        print("\n*** Uncloak_file input file hmac: len=", \
                              len(chunk), ", data=", "".join(format(bite, '02x') for bite in chunk))
                        raise UserWarning("*** Uncloak_file: Input file has an incorrect HMAC")
                # Not the HMAC (final) block.  Read next file chunk.
                # If the countdown < chunksize, then we found the last data block
                # before the HMAC.
                if countdown < chunksize:
                    read_size = countdown
                else:
                    read_size = chunksize
                chunk = infile.read(read_size)
                len_chunk = len(chunk)
                # At this point, len_chunk should be = read_size.
                if len_chunk == 0:
                    # Missing HMAC detected in input file; hit end of file.
                    raise UserWarning("*** Uncloak_file: Input file is missing the HMAC")
                if len_chunk != read_size:
                    raise UserWarning("*** Uncloak_file: Read a short block from input file")
                # All is well so far.  Decrease count down by amount just read.
                countdown -= len_chunk
                # Write out decrypted block.
                dechunk = decryptor.decrypt(chunk)
                outfile.write(dechunk)
                computed_file_size += len(dechunk)
                # Accumulate expected value of HMAC.
                hmac.update(dechunk)
            # Read/write loop done.  Truncate file to exclude the pad bytes.
            outfile.truncate(original_file_size)
            if DEBUGGING:
                print("DEBUG uncloak_file: original size:", original_file_size)
                print("DEBUG uncloak_file: computed size (possibly, padded):", computed_file_size)

    # Done - return elapsed time
    return time() - tstart

#======================================================================

if __name__ == "__main__": # stand-alone self-imposed test
    PASSWORD = "Mary Had a Little Lamb"
    CLEARTEXT_FILE_1 = "/tmp/nil"
    CLEARTEXT_FILE_1 = "/etc/hosts"
    CLEARTEXT_FILE_1 = "/usr/bin/pandoc"
    CIPHERTEXT_FILE = "/tmp/cloaked"
    CLEARTEXT_FILE_2 = "/tmp/uncloaked.txt"
    et = cloak_file(PASSWORD, CLEARTEXT_FILE_1, CIPHERTEXT_FILE)
    print("cloak_file elapsed time(s) = %.3f" %et)
    et = uncloak_file(PASSWORD, CIPHERTEXT_FILE, CLEARTEXT_FILE_2)
    print("uncloak_file elapsed time(s) = %.3f" %et)
    filesize1 = getsize(CLEARTEXT_FILE_1)
    print("Original file size:", filesize1)
    cloakedsize = getsize(CIPHERTEXT_FILE)
    print("Cloaked file size:", cloakedsize)
    filesize2 = getsize(CLEARTEXT_FILE_2)
    print("Uncloaked file size:", filesize2)
