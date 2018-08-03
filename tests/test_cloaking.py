from os.path import getsize
from pycloaking import *

if __name__ == "__main__": # stand-alone self-imposed test

    PASSWORD = "Mary Had a Little Lamb"
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
