from os.path import getsize
from os import urandom, remove
from pycloaking import cloak_file, uncloak_file

PASSWORD = "Mary Had a Little Lamb"
CLEARTEXT_FILE_1 = "/tmp/cleartext.txt"
CIPHERTEXT_FILE = "/tmp/cloaked.tiff"
CLEARTEXT_FILE_2 = "/tmp/uncloaked.txt"
CLEAR_FILE_SIZE = 100000000
CLEAR_BLOCK_SIZE = 4096

def try_cloaking(arg_path):
    filesize1 = getsize(arg_path)
    et = cloak_file(PASSWORD, arg_path, CIPHERTEXT_FILE)
    print("[{}] cloak_file() elapsed time(s) = {:.2f}".format(arg_path, et))
    et = uncloak_file(PASSWORD, CIPHERTEXT_FILE, CLEARTEXT_FILE_2)
    print("[{}] uncloak_file() elapsed time(s) = {:.2f}".format(arg_path, et))
    print("[{}] Original file size = {}".format(arg_path, filesize1))
    cloakedsize = getsize(CIPHERTEXT_FILE)
    print("[{}] Cloaked file size = {}".format(arg_path, cloakedsize))
    filesize2 = getsize(CLEARTEXT_FILE_2)
    print("[{}] Uncloaked file size = {}".format(arg_path, filesize2))
    assert filesize1 == filesize2
    with open(arg_path, 'rb') as infile1:
        with open(CLEARTEXT_FILE_2, 'rb') as infile2:
            nblocks = 0
            byte_countdown = filesize1
            while byte_countdown > 0:
                nblocks += 1
                if byte_countdown < CLEAR_BLOCK_SIZE:
                    read_size = byte_countdown
                else:
                    read_size = CLEAR_BLOCK_SIZE
                chunk1 = infile1.read(read_size)
                chunk2 = infile2.read(read_size)
                assert chunk1 == chunk2
                byte_countdown -= read_size
    print("[{}] Block bytesize = {}".format(arg_path, CLEAR_BLOCK_SIZE))
    print("[{}] Blocks compared = {}".format(arg_path, nblocks))
    print("[{}] Cloaked and uncloaked as expected".format(arg_path))
    infile1.close()
    infile2.close()
    remove(CIPHERTEXT_FILE)
    remove(CLEARTEXT_FILE_2)

if __name__ == "__main__": # stand-alone test
    path_cleartext = CLEARTEXT_FILE_1
    byte_countdown = CLEAR_FILE_SIZE
    with open(path_cleartext, 'wb') as outfile:
        while byte_countdown > 0:
            if byte_countdown < CLEAR_BLOCK_SIZE:
                write_size = byte_countdown
            else:
                write_size = CLEAR_BLOCK_SIZE
            blk = urandom(write_size)
            outfile.write(blk)
            byte_countdown -= write_size
    try_cloaking(path_cleartext)
    remove(CLEARTEXT_FILE_1)
