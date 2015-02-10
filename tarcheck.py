#!/usr/bin/env python2

import argparse
import os
import json

class colors:
    RED     = '\033[31m'
    BLUE    = '\033[34m'
    GREEN   = '\033[32m'
    YELLOW  = '\033[33m'
    DEFAULT = '\033[0m'


def printc(message, c):
    print c + message + colors.DEFAULT


class Header:
    def __init__(self, name, mode, ouid, guid, size, timestamp, checksum, type, owner, group,
                 major_num, minor_num, prefix):
        self.name = name
        self.mode = mode
        self.ouid = ouid
        self.guid = guid
        self.size = size
        self.timestamp = timestamp
        self.checksum = checksum
        self.type = type
        self.owner = owner
        self.group = group
        self.major_num = major_num
        self.minor_num = minor_num
        self.prefix = prefix

    def __str__(self):
        return json.dumps(self.__dict__, indent=1)


def from_c_str(s):
    index = s.find('\x00')
    return s[:index]


def calc_checksum(header_block, checksum):
    s = 32 * 8 # 8 spaces
    for b in header_block:
        s += ord(b)
    for b in checksum:
        s -= ord(b)
    return s


def bytes_to_blocks(num_bytes):
    res = num_bytes / 512
    if num_bytes % 512 == 0:
        return res
    else:
        return res + 1


def error(s):
    printc("Error: " + s, colors.RED)
    exit(1)


def warning(s):
    printc("Warning: " +  s, colors.YELLOW)


def parse_header(f, offset):
    if f[257:265] not in ['ustar  \x00', 'ustar\x0000']:
        error('Currently only supports the UStar format')
        exit(1)

    name = from_c_str(f[:100])
    mode = int(from_c_str(f[100:108]))
    ouid = int(from_c_str(f[108:116]))
    guid = int(from_c_str(f[116:124]))
    size = int(from_c_str(f[124:136]), 8)
    timestamp = int(from_c_str(f[136:148]), 8)
    checksum = int(from_c_str(f[148:156]), 8)
    type = from_c_str(f[156])

    owner = from_c_str(f[265:297])
    group = from_c_str(f[297:329])
    major_num = from_c_str(f[329:337])
    minor_num = from_c_str(f[337:345])
    prefix = from_c_str(f[345:500])

    if f[500:512] != '\x00' * 12:
        warning('Padding after header at offset %d (%s) should only contain NULL bytes. Got %s'
                % (offset + 500, hex(offset + 500), repr(f[500:512])))

    header = Header(name, mode, ouid, guid, size, timestamp, checksum, type, owner, group,
                    major_num, minor_num, prefix)
    actual_checksum = calc_checksum(f, f[148:156])
    if actual_checksum != checksum:
        warning('Wrong checksum at offset %d (%s). Calculated %d (0o%s), expected %d (0o%s)'
                % (offset + 148, hex(offset + 148), actual_checksum, oct(actual_checksum),
                   checksum, oct(checksum)))

    return header


def main():
    parser = argparse.ArgumentParser(description='Check a tar file for errors')
    parser.add_argument('tarfile', help='File to check')

    args = parser.parse_args()
    if not os.path.exists(args.tarfile):
        print 'Tar file does not exist'
        return

    tarfile = ''
    with open(args.tarfile) as f:
        tarfile = f.read()

    block_start = 0
    while True:
        header_block = tarfile[block_start:block_start + 512]
        if header_block == '\x00' * 512:
            block_start += 512
            header_block = tarfile[block_start:block_start + 512]
            if header_block != '\x00' * 512:
                exit("Found one zero block, not two")
            else:
                break

        header = parse_header(header_block, block_start)
        print header

        # Skip to next header
        num_blocks = bytes_to_blocks(header.size)
        block_start += 512 * (num_blocks + 1)


if __name__ == '__main__':
    main()
