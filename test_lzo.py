import struct
from binascii import b2a_hex
import lzo
import zlib
import os
import binascii

COMPR_NONE = 0
COMPR_LZO = 1
COMPR_ZLIB = 2
COMPR_ZSTD = 3

def decompress(data, buflen, compr_type):
    if compr_type==COMPR_NONE:
        return data
    elif compr_type==COMPR_LZO:
        return lzo.decompress(data, False, buflen)
    elif compr_type==COMPR_ZLIB:
        return zlib.decompress(data, -zlib.MAX_WBITS)
    else:
        raise Exception("unknown compression type")


dependencies = [
    'python-lzo>=1.11',
    'crcmod>=1.7'
]



def main():
    #lzo_compressed_bytearray = b"\x00\x0bSAM WAYPT V01.00\x08\x00`/\x87\x07@\x03\xb0\x1bP2 \x80\x00\x0b\x00\x0c\x00\x02'/\x87\x07\xab\xb3\xaf\x1bP3\x89\x02 n\x02\x17\x12\xcd\x024(O\x00s\xdf\x86\xbd\x045(L\x00\x078\x1c\x87\x07\xa7\xda\xaf\x1bP6(L\x00\x07\x05\xc2\x86\x07C4\xaf\x1bP7(O\x00\x02\x07\x87\xad\x028(N\x00\xfa5\xcd\x029(L\x00\x05\x00\xd9O\x13\x00d?M\xa5\x02 m\x11\x03 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00(L\x00\x11\x00\x00"
    hdrsize = 48
    filename = 'test_hex_1.bin'
    with open(filename, 'rb') as f:
        content = f.read()
    d = decompress(content[hdrsize:], 4096, 1)
    print(d.hex())

if __name__ == '__main__':
    main()
