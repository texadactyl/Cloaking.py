"""
https://github.com/Legrandin/pycryptodome/issues/393
in AES Mode - CFB, OFB, CTR when I enter the PASSWORD it is not raising an error,
instead, it gives random data.
"""
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

PASSWORD1 = "1234567890123456"
PASSWORD2 = "1234567890123456wrong"
ENCODING = "utf-8"
CLEARTEXT = bytearray("12345678901234567890123456789012", ENCODING)

def hexdump(arg_label, arg_data, arg_line_size):
    """
    Dump hex portion on the lect, displayable portion on the right.
    Non-printable characters are replaced with a '.' in the displayable portion.

    arg_label: first line (What am I dumping?).
    arg_data: blob to dump.
    arg_line_size = number of characters dumped per line.

    Result returned is a string of the form: "label\nline1\nline2\netc.\n".
    """

    def _printable(arg_int):
        if arg_int in range(32, 127):
            return chr(arg_int)
        return '.'

    byte_array = bytearray(arg_data)
    cookedlines = [arg_label]
    fmt = "%%04X   %%-%ds   %%s" % (3 * arg_line_size - 1,)
    fmtlinesize = 7 + 3*arg_line_size + 3 + arg_line_size
    for ndx in range(0, len(byte_array), arg_line_size):
        line = byte_array[ndx:ndx+arg_line_size]
        intlist = []
        for bite in line:
            intlist.append(int(bite))
        hextext = " ".join('%02x' % b for b in intlist)
        rawtext = "".join(_printable(b) for b in intlist)
        cookedlines.append(fmt % (ndx, str(hextext), str(rawtext)))
    if cookedlines:
        cookedlines[-1] = cookedlines[-1].ljust(fmtlinesize)
    cookedlines.append("")
    return "\n".join(cookedlines)

class CTR:

    def encrypt(self, data, key):
        cipher = AES.new(key, AES.MODE_CTR)
        e_data = cipher.encrypt(data)
        return e_data, cipher.nonce

    def decrypt(self, data, key, nonce):
        try:
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
            ue_data = cipher.decrypt(data)
            return ue_data
        except (ValueError, KeyError) as e:
            print("decrypt Exception:\n", e)
            return False

print("Original cleartext (size={}): {}".format(len(CLEARTEXT), CLEARTEXT))
CTR = CTR()
key1 = SHA256.new(PASSWORD1.encode()).digest()
print(hexdump("key1 from password #1", key1, 16))
ciphertext, nonce1 = CTR.encrypt(CLEARTEXT, key1)
print(hexdump("ciphertext after encryption", ciphertext, 16))
print(hexdump("nonce1 after encryption", nonce1, 16))

cleartext2 = CTR.decrypt(ciphertext, key1, nonce1)
print("cleartext after decryption (size={}): {}\n".format(len(cleartext2), cleartext2))

key2 = SHA256.new(PASSWORD2.encode()).digest()
print(hexdump("key2 from password #2 (bogus)", key2, 16))
cleartext2 = CTR.decrypt(ciphertext, key2, nonce1)
print(hexdump("bogus cleartext after decrypting with key2", cleartext2, 16))

nonce2 = bytearray("12345678", ENCODING)
print(hexdump("nonce2 (bogus)", nonce2, 16))
cleartext2 = CTR.decrypt(ciphertext, key1, nonce2)
print(hexdump("bogus cleartext after decrypting with nonce2", cleartext2, 16))