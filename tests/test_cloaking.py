import hashlib
import tempfile
from os.path import getsize, dirname
from os import system
from pycloaking import cloak_file, uncloak_file, mains

TEMPDIR = tempfile.gettempdir()
HERE = dirname(__file__)
CLEAR_FILE_SIZE = 100000000
CLEAR_BLOCK_SIZE = 4096
PASSWORD = "Mary_Had_a_Little_Lamb"
CLEARTEXT_FILE_1 = HERE + "/cleartext_1.txt"
CIPHERTEXT_FILE = TEMPDIR + "/cloaked.tif"
CLEARTEXT_FILE_2 = TEMPDIR + "/uncloaked.txt"

def hasher(file_path):
    with open(file_path, encoding="UTF-8") as handle:
        data = handle.read()
        return hashlib.md5(data.encode("utf-8")).hexdigest()

def test_and_compare():
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
    hash_1 = hasher(CLEARTEXT_FILE_1)
    hash_2 = hasher(CLEARTEXT_FILE_2)
    assert hash_1 == hash_2
    print("Success!")

def test_mains():
    args = ["-p", PASSWORD, "-i", CLEARTEXT_FILE_1, "-o", CIPHERTEXT_FILE]
    mains.main_cloak(args)
    args = ["-p", PASSWORD, "-i", CIPHERTEXT_FILE, "-o", CLEARTEXT_FILE_2]
    mains.main_uncloak(args)
    hash_1 = hasher(CLEARTEXT_FILE_1)
    hash_2 = hasher(CLEARTEXT_FILE_2)
    assert hash_1 == hash_2
    print("Success!")

def test_cmdline():
    cmd = "cloak -p " + PASSWORD + " -i " + CLEARTEXT_FILE_1 + " -o " + CIPHERTEXT_FILE
    cloak_rc = system(cmd)
    assert cloak_rc == 0
    cmd = "uncloak -p " + PASSWORD + " -i " + CIPHERTEXT_FILE + " -o " + CLEARTEXT_FILE_2
    uncloak_rc = system(cmd)
    assert uncloak_rc == 0
    hash_1 = hasher(CLEARTEXT_FILE_1)
    hash_2 = hasher(CLEARTEXT_FILE_2)
    assert hash_1 == hash_2
    print("Success!")

if __name__ == "__main__": # stand-alone main program
    test_cmdline()
