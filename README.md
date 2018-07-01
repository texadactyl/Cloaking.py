OVERVIEW

This project constitutes a file cloaking utility that provides password-based security of a single file or a single file system archive file (E.g. .tar.gz). The utility is probably most useful in the following situations:

* Storing backups of sensitive information on the Internet
* Transporting sensitive information electronically (E.g. email) or manually (E.g. using a flash drive)

The design is based on pycrypto, using:

* Password-based Key Derivation Function version 2 (PBKDF2)
* AES256 data cryptography in Cipher-Block Chaining (CBC) mode
* Hash-based Message Authentication Code (HMAC) function SHA512

The Python project code is based on an example by Eli Bendersky (used as a starting point):
https://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/

Pycrypto reference: https://www.dlitz.net/software/pycrypto/

LICENSING

This is NOT commercial software; instead, usage is covered by the GNU General Public License version 3 (2007). In a nutshell, please feel free to use the project and share it as you will but please don't sell it. Thank you!

See the LICENSE file for the GNU licensing information.

SAMPLE CALLING PROGRAM

    import pycloaking

    PASSWORD = "Mary Had a Little Lamb"
    CLEARTEXT_FILE_1 = "/etc/hosts"
    CIPHERTEXT_FILE = "/tmp/cloaked"
    CLEARTEXT_FILE_2 = "/tmp/uncloaked.txt"
    et = cloak_file(PASSWORD, CLEARTEXT_FILE_1, CIPHERTEXT_FILE)
    print("cloak_file et=", et)
    et = uncloak_file(PASSWORD, CIPHERTEXT_FILE, CLEARTEXT_FILE_2)
    print("uncloak_file et=", et)
    filesize1 = getsize(CLEARTEXT_FILE_1)
    print("Original file size ", filesize1)
    cloakedsize = getsize(CIPHERTEXT_FILE)
    print("Cloaked file size ", cloakedsize)
    filesize2 = getsize(CLEARTEXT_FILE_2)
    print("Uncloaked file size ", filesize2)    

The API is explained in api_doc.txt.

CIPHERTEXT ANATOMY

The ciphertext file created by cloak_file() has the following layout:

    TIFF prefix to make the file appear as a TIFF (112 bytes)
    Initialization Vector (16 bytes)
    Original file size as a binary Little Endian Unsigned Long Long (8 bytes)
    "BOUNDARY" as a Python bytearray (8 bytes)
    Encrypted file data 
        (last cleartext block was padded if necessary to an 8-byte boundary)
    HMAC bytearray (64 bytes)
    ==========================
    Total overhead = 208 bytes

Feel free to contact richard.elkins@gmail.com for inquiries and issues, especially if you find any bugs. I'll respond as soon as I can.

Richard Elkins Dallas, Texas, USA, 3rd Rock, Sol

