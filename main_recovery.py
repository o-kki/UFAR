import contextlib
import math
import lzo
import zlib
import argparse
import logging
from ubi_struct import *

logging.basicConfig(
    format='%(asctime)s:%(levelname)s:%(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    level=logging.DEBUG
)

del_file = {}
i = 0


def checkformat(file):
    with open(file, "rb") as fh:
        magic = fh.read(4)
        if magic != b'UBI#':
            raise Exception("not an UBI image")


def processblocks(fh, args):
    """
    Perform operations on a UbiBlocks type image: starting with bytes 'UBI#'
    """
    blks = UbiBlocks(fh)
    for volid in range(128):
        vrec = blks.getvrec(volid)
        if vrec.empty():
            continue
        vol = blks.getvolume(volid)

        try:
            print("== volume %s ==" % vrec.name)

            processvolume(vol, vrec.name, args)
        except Exception as e:
            print("E: %s" % e)


def processvolume(vol, volumename, args):
    """
    Perform actions specified by `args` on `vol`.

    `vol` can be either a RawVolume ( an image file containing only the filesystem,
    no flash block management layer.

    Or a UbiVolume, with the block management layer.
    """
    nr_symlink_warnings = 0
    args.masteroffset = None
    fs = UbiFs(vol, args.masteroffset)
    root = fs.root
    if args.dumptree:
        fs.printrecursive(root)


def printrecursive(self, idx):
    """
    Recursively dump all b-tree nodes.
    """
    print("[%03d:0x%05x-0x%05x] %s" % (idx.hdr.lnum, idx.hdr.offs, idx.hdr.offs + idx.hdr.len, idx))
    if not hasattr(idx, 'branches'):
        # print(idx)
        return
    for i, b in enumerate(idx.branches):  ## 여기서 결정돼 분기가 집중해
        print("%s %d %s -> " % ("  " * (6 - idx.level), i, b), end=" ")
        try:
            n = self.readnode(b.lnum, b.offs)  ## 다음 노드 읽는곳??
            self.printrecursive(n)
        except Exception as e:
            print("ERROR %s" % e)


## EXPORT FIELS(DATA)(data)
def exportdata(file_nm, file_cont):
    with open(file_nm, "ab") as recovery_file:
        recovery_file.write(file_cont)


def search_del_data(del_file):
    i = 0
    f.seek(i)
    data = f.read(8)
    while data != b"":
        f.seek(i)
        data = f.read(8)
        if data.find(b'UBI#\x01\x00\x00\x00') != -1:
            i += 512
            f.seek(i)
            data = f.read(16)
            while data == b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff':
                i += 16
                f.seek(i)
                data = f.read(16)
                if data.find(b'\xff\xff\xff\xff\xff\xff\xff\xff') == -1:
                    break
        # signature find
        if data.find(b'\x31\x18\x10\x06') != -1:
            f.seek(i + 20)
            print(hex(i))
            node_gbn = f.read(1)
            if node_gbn == b'\x01':  # data Node
                f.seek(i + 24)
                inum_data_v = f.read(4)
                for name in list(del_file.keys()):
                    inum_data_r = del_file.get(name)
                    # print(inum_data_v.hex())
                    if inum_data_r == inum_data_v:
                        f.seek(i + 44)
                        compr_type = f.read(4)
                        if compr_type == b'\x01\x00\x00\x00':  # 압축된 노드
                            # print(f.tell())
                            hdrsize = 48
                            f.seek(i + 40)
                            buff_len = int(f.read(2)[::-1].hex(), base=16)
                            f.seek(i + 16)
                            data_len = int(f.read(2)[::-1].hex(), base=16)
                            f.seek(i)
                            content = f.read(data_len)
                            data_recovery = decompress(content[hdrsize:], buff_len, 1)
                        else:  # 압축 안된 노드
                            f.seek(i + 40)
                            _data_hex = int(f.read(2)[::-1].hex(), base=16)
                            f.seek(i + 48)
                            data_recovery = f.read(_data_hex)

                        rec_file = ".\\recovery\\" + folder + os.sep + name.decode('utf-8')
                        exportdata(rec_file, data_recovery)
        i += 8


# Scanning Meta nodes
def meta_analyze():
    logging.debug('Scanning Meta Nodes')
    i = 0
    data = f.read(8)
    if data.find(b'UBI#\x01\x00\x00\x00') == 0:
        i += 131072  # hex 20000 jump
        f.seek(i)
    while data != b"":
        # print(hex(i))
        f.seek(i)
        data = f.read(8)
        if data.find(b'UBI#\x01\x00\x00\x00') != -1:
            i += 4096
            f.seek(i)
            print(hex(i))
            data = f.read(16)
            while data == b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff':
                i += 16
                f.seek(i)
                data = f.read(16)
                if data.find(b'\xff\xff\xff\xff\xff\xff\xff\xff') == -1:
                    break
        # signature find
        if data.find(b'\x31\x18\x10\x06') != -1:
            f.seek(i + 20)
            node_gbn = f.read(1)
            # directory node
            if node_gbn == b'\x02':
                f.seek(i + 40)
                del_gbn = f.read(4)
                if del_gbn == b'\x00\x00\x00\x00':
                    print('------------------------------------')
                    print('offset:' + str(f.tell()))
                    # file 명 찾기
                    f.seek(i + 50)
                    data = f.read(1)  # file name 길이
                    print('file len ::' + str(data))  # file name 길이
                    file_len = int(data.hex(), base=16)
                    print('file len:::' + str(file_len))
                    f.seek(i + 56)
                    file_nm = f.read(file_len)  # file name
                    print('fileNm ::' + str(file_nm))

                    f.seek(i + 16)
                    node_len = f.read(2)
                    # node_len[::-1].hex()
                    len_8 = math.ceil(int(node_len[::-1].hex(), base=16) / 8) * 8
                    f.seek(i + len_8)  # 끝나는 노드

                    # i = i + int(node_len[::-1].hex(), base=16)
                    # f.seek(i)
                    data = f.read(4)
                    if data.find(b'\x31\x18\x10\x06') != -1:
                        i = f.tell()
                        f.seek(i + 12)
                        node_len = f.read(2)
                        f.seek(i + 16)
                        node_gbn = f.read(1)
                        # i-node
                        if node_gbn == b'\x00':
                            f.seek(i + 20)
                            inum_real = f.read(4)
                            print(str(inum_real))
                            print('삭제 전 INODE ::' + str(inum_real))
                            i = i - 4 + int(node_len[::-1].hex(), base=16)

                        del_file[file_nm] = str(inum_real)
                        del_file.update({file_nm: inum_real})

        i += 8  # OFFSET 위치 10진수
    print('삭제된 파일 List :::::' + str(del_file))
    search_del_data(del_file)


# Scanning Data nodes
def data_analyze():
    logging.debug('Scanning Data Nodes')
    i = 0
    data = f.read(8)
    if data.find(b'UBI#\x01\x00\x00\x00') != -1:
        i += 131072  # hex 20000 jump
        f.seek(i)
    while data != b"":
        # print(hex(i))
        f.seek(i)
        data = f.read(8)
        if data.find(b'UBI#\x01\x00\x00\x00') != -1:
            i += 4096  # 바로 데이터로 jump
            f.seek(i)
            data = f.read(16)
            while data == b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff':
                i += 16
                f.seek(i)
                data = f.read(16)
                if data.find(b'\xff\xff\xff\xff\xff\xff\xff\xff') == -1:
                    break
        # signature find
        if data.find(b'\x31\x18\x10\x06') != -1:
            f.seek(i + 20)
            node_gbn = f.read(1)
            # directory node
            if node_gbn == b'\x01':
                hdrsize = 48
                i = f.tell()
                f.seek(i - 5)
                data_len = int(f.read(2)[::-1].hex(), base=16)
                f.seek(i - 21)
                content = f.read(data_len)
                f.seek(i + 3)
                inode_num = f.read(4)
                i += 19
                f.seek(i)
                compr_datlen = int(f.read(4)[::-1].hex(), base=16)
                f.seek(i + 4)
                compr_type = f.read(4)
                if compr_type == b'\x01\x00\x00\x00':  # 압축된 노드
                    i += 1
                    # print(f.tell())
                    d = decompress(content[hdrsize:], compr_datlen, 1)
                    rec_file = ".\\recovery\\" + str(inode_num.hex())
                    exportdata(rec_file + '_' + str(i), d)
                else:  # 압축 안된 노드
                    i += 1
                    rec_file = ".\\recovery\\" + str(inode_num.hex())
                    exportdata(rec_file + '_' + str(i), content[hdrsize:])
                i = f.tell()
                # print(inode_num)

        i += 8  # OFFSET 위치 10진수



class ChangeImageFormat(object):
    def __init__(self):
        self.ubi_data = b''

    def dump_to_uart(self, data):
        self.ubi_data = b''
        dummy_start_offset = [0x200, 0x40E, 0x61C]

        spare_data = b''
        end = dummy_start_offset[0]
        self.ubi_data += data[0: end]

        start = end + 14
        end = dummy_start_offset[1]
        self.ubi_data += data[start: end]

        start = end + 14
        end = dummy_start_offset[2]
        self.ubi_data += data[start: end]

        start = end + 14
        end = 0x800
        self.ubi_data += data[start: end]

        spare_start_sig = data[end: end + 0x6]
        start = 0x83E
        spare_end_sig = data[start: start + 0x2]

        if spare_start_sig == b'\xff\xff\xff\xff\xff\xff' and spare_end_sig == b'\xff\xff':
            start = end + 0x6
            spare_data = data[start: start + 0x2A]
            self.ubi_data += spare_data
        else:
            print("실패하였습니다. 이미지를 다시 한번 확인해주세요!")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Recovery UBIFS deleted file')
    parser.add_argument('-f', '--file', required=True, help='Target UBIFS image file')
    parser.add_argument('-d', '--data', default=False, action='store_true', help='Scanning data node')
    parser.add_argument('-m', '--meta', default=False, action='store_true', help='Scanning meta node')
    parser.add_argument('-t', '--dumptree', default=False, action='store_true', help='Scanning Node Visualization')
    parser.add_argument('-c', '--combination', default=False, action='store_true', help='Change to UART image format')
    args = parser.parse_args()

    target_file = args.file
    if not args.combination:
        chk_file = checkformat(target_file)

        if chk_file is None:
            logging.info('Valid file in UBIFS format')
            try:
                folder = os.path.splitext(os.path.basename(target_file))[0]
                if not os.path.exists(".\\recovery\\" + folder):
                    os.makedirs(".\\recovery\\" + folder)
            except OSError:
                pass
        else:
            logging.info('Invalid file in UBIFS format')

    with open(target_file, "rb") as f:
        if args.combination:
            fn = target_file
            change_getdata = ChangeImageFormat()
            with open(fn, 'rb') as fulldump:
                logging.info('Change Image Structure')
                start_offset = 0x2100000  ## 파일시스템 영역만
                # start_offset = 0x2100000
                block_size = 0x840
                cnt = 0
                while 1:
                    if fulldump.tell() >= 0x42000000:
                        break
                    fulldump.seek(start_offset + (block_size * cnt))
                    print(hex(fulldump.tell()))
                    data = fulldump.read(block_size)
                    change_getdata.dump_to_uart(data)
                    cnt += 1

                    with open(fn.split('.bin')[0] + '_to_uart.bin', 'ba') as del_spare:
                        del_spare.write(change_getdata.ubi_data)
            try:
                nfn = fn.split('.bin')[0] + '_to_uart.bin'
            except Exception as e:
                print("ERROR", e)
                if args.debug:
                    raise
        elif args.data:
            data_analyze()
        elif args.meta:
            meta_analyze()
        elif args.dumptree:
            logging.info('Create Dump Tree in UBIFS')
            with open("recovery"+os.sep+folder+os.sep+"dumptree.txt", 'w') as outfile, contextlib.redirect_stdout(outfile):
                processblocks(f, args)

    logging.info('Complete!!!!')
