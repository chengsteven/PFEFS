#!/usr/bin/env python
"""
This FS is written for EN.650.718: Advanced Operating Systems at Johns Hopkins University.

steven_encfs is supposed to be a step up from normal encrypted file systems. Right now,
normal encfs provides data protection by encrypting all the data that is written to disk
and decrypts data that is read from disk. This hides any data on the file system if the
physical disk were ever compromised i.e. by theft. However, this does not really help
in the cases of remote logins or if you are already logged in. This is also provides
nothing in the face of software vulnerabilities and data leaks. In addition, previous
implementations of encfs open the encrypted file systems once they have been mounted,
meaning once a FS has been mounted and verified via a password, any application can
then access that FS since the OS is already decrypting that data.


steven_encfs tries to address these issues by providing a FS that is similar to full
disk encryption. It encrypts all data written and decrypts all data read without knowledge
by the user. However, we add that separate processes cannot read from a steven_encfs
if they have not been given permission to. We want to protect the data from being
read in a meaningful way in a steven_encfs by unprivileged processes.

1_steven_encfs.py is a FS that reads and writes in block sizes. The blocks
written and read are encrypted/decrypted respectively.

author: @chengsteven
"""

# TODO LIST:
# - input password
# - process separation
# - cache
# - performance reviews on normal structure
# - restructure with data files and metadata files
# - performance reviews on restructured
# -

from __future__ import print_function, absolute_import, division

import logging
import os

import json

import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import errno
from errno import EACCES
from os.path import realpath
from threading import Lock

from fuse import FUSE, FuseOSError, Operations, LoggingMixIn


class steven_encfs(LoggingMixIn, Operations):
    def __init__(self, root):
        self.root = realpath(root)
        self.rwlock = Lock()
        self.block_size = 32 #bytes
        self.log = logging.getLogger('fuse.log-mixin')
        self.key = b"0123456789012345"
        self.cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()
#        self.st_size_dict = dict()
        self.st_size_dict = None
        self.st_size_dict_fh = None
        self.st_size_dict_path = self.root + "/st_size_dict"

    def __call__(self, op, path, *args):
        return super(steven_encfs, self).__call__(op, self.root + path, *args)

    def init(self, path):
        self.log.debug("------------ init -------------")
        self.st_size_dict_fh = os.open(self.st_size_dict_path, os.O_CREAT | os.O_RDWR)
        st = os.lstat(self.st_size_dict_path)
#        import pdb; pdb.set_trace()
        if (st.st_size):
            self.st_size_dict = json.loads(os.read(self.st_size_dict_fh, st.st_size).decode('utf-8')) # load all the st_size data
        else: self.st_size_dict = dict()

    def destroy(self, path):
        os.lseek(self.st_size_dict_fh, 0, 0)
        os.write(self.st_size_dict_fh, json.dumps(self.st_size_dict).encode('utf-8'))
        os.close(self.st_size_dict_fh)
        pass

    def access(self, path, mode):
        if not os.access(path, mode):
            raise FuseOSError(EACCES)

    chmod = os.chmod
    chown = os.chown

    def create(self, path, mode):
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)

    def flush(self, path, fh):
        return os.fsync(fh)

    def fsync(self, path, datasync, fh):
        if datasync != 0:
            return os.fdatasync(fh)
        else:
            return os.fsync(fh)

    def getattr(self, path, fh=None):
        st = os.lstat(path)
        ret_st = dict((key, getattr(st, key)) for key in (
            'st_atime', 'st_ctime', 'st_gid', 'st_mode', 'st_mtime',
            'st_nlink', 'st_uid'))
        if (path not in self.st_size_dict): self.st_size_dict[path] = 0
        ret_st['st_size'] = self.st_size_dict[path]
        return ret_st

    getxattr = None

    def link(self, target, source):
        return os.link(self.root + source, target)

    listxattr = None
    mkdir = os.mkdir
    mknod = os.mknod
    open = os.open

    def read_block(self, path, start_block, num_blocks, fh):
        self.log.debug("------------------ read_block ------------------")
        with self.rwlock:
            os.lseek(fh, start_block*self.block_size, 0)
            return os.read(fh, num_blocks*self.block_size)

    def read(self, path, size, offset, fh):
        self.log.debug("------------------ read ------------------")
        start_block = offset // self.block_size
        num_blocks = size // self.block_size
        if (size % self.block_size): num_blocks += 1
        rb_data = self.read_block(path, start_block, num_blocks, fh)

        # decryption here
        self.log.debug("----------- read ct: " + str(rb_data) + " -----------")
        pt = self.decryptor.update(rb_data)
        self.log.debug("----------- read pt: " + str(pt) + " -----------")

        start = offset % self.block_size
        return pt[start : (start + size)]

    def readdir(self, path, fh):
        fn = os.listdir(path)
        if ('st_size_dict' in fn): fn.remove('st_size_dict')
        return ['.', '..'] + fn

    readlink = os.readlink

    def release(self, path, fh):
        return os.close(fh)

    def rename(self, old, new):
        return os.rename(old, self.root + new)

    rmdir = os.rmdir

    def statfs(self, path):
        stv = os.statvfs(path)
        return dict((key, getattr(stv, key)) for key in (
            'f_bavail', 'f_bfree', 'f_blocks', 'f_bsize', 'f_favail',
            'f_ffree', 'f_files', 'f_flag', 'f_frsize', 'f_namemax'))

    def symlink(self, target, source):
        return os.symlink(source, target)

    def truncate(self, path, length, fh=None):
        with open(path, 'r+') as f:
            f.truncate(length)

    unlink = os.unlink
    utimens = os.utime

    def write_block(self, path, block_data, start_block, fh):
        self.log.debug("------------------ write_block ------------------")
        with self.rwlock:
            os.lseek(fh, start_block*self.block_size, 0)
            return os.write(fh, block_data)

    def write(self, path, data, offset, fh):
        self.log.debug("------------------ write ------------------")
        data_len = len(data)
        if (path not in self.st_size_dict): self.st_size_dict[path] = 0
        self.st_size_dict[path] = max(self.st_size_dict[path], offset + data_len)
        start_block = offset // self.block_size
        num_blocks = data_len // self.block_size
        if (data_len % self.block_size): num_blocks += 1
        if num_blocks == 0: return 0

        new_fh = os.open(path, os.O_RDONLY)
        rb_data = self.read_block(path, start_block, num_blocks, new_fh)
        os.close(new_fh)

        # new data
        if len(rb_data) == 0: rb_data = b"\0" * num_blocks * self.block_size
        start = offset % self.block_size
        rb_data = rb_data[:start] + data + rb_data[(start) + data_len:]


        self.log.debug("----------- write pt: " + str(rb_data) + " -----------")
        # encryption here
        ct = self.encryptor.update(rb_data)

        self.log.debug("----------- write ct: " + str(ct) + " -----------")

        bytes_written = self.write_block(path, ct, start_block, fh)
        if (bytes_written % self.block_size != 0): self.log.debug("------------------ write error ------------------")
        return data_len


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('encdir')
    parser.add_argument('mount')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)
    fuse = FUSE(
        steven_encfs(args.encdir), args.mount, foreground=True, allow_other=True)

