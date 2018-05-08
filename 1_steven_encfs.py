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
# - performance reviews on normal structure
# - restructure with data files and metadata files
# - performance reviews on restructured

from __future__ import print_function, absolute_import, division

import logging
import os
import json
import hashlib
import getpass
import cryptography
import ast
import base64
import psutil

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import errno
from errno import EACCES
from os.path import realpath
from threading import Lock

from time import time

from stat import S_IFREG

from fuse import FUSE, FuseOSError, Operations, LoggingMixIn, fuse_get_context

def check_process(func):
    def wrapper(*args):
        self = args[0]
        uid, gid, pid = fuse_get_context()
        init_process = psutil.Process(pid)
        current_process = init_process
        allowed = False
        last_pid = None
        if current_process.ppid() == 0: allowed = True
        while current_process.pid != last_pid and allowed == False:
            last_pid = current_process.pid
            if current_process.pid in self.proc_wl:
                allowed = True
                break
            current_process = psutil.Process(current_process.ppid())
        if allowed: return func(*args)
        else:
            self.log.debug("PROCESS BLOCKED: %s", init_process)
            raise FuseOSError(errno.EACCES)
        return func(*args)
    return wrapper


class steven_encfs(LoggingMixIn, Operations):
    def __init__(self, root, pw_hash, init_pid):
        self.root = realpath(root)
        self.rwlock = Lock()
        self.block_size = 32 #bytes
        self.log = logging.getLogger('fuse.log-mixin')
        self.key = pw_hash
        self.cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()
        self.proc_wl_path = self.root + "/proc_wl" # process white list
        self.proc_wl = [os.getpid(), init_pid]
        self.st_size_dict_path = self.root + "/st_size_dict"
        self.st_size_dict = dict()
        self.obfs_fn_path = self.root + "/obfs_fn"
        self.obfs_fn = dict() # mapping of the hashed fn to the real fn

    @check_process
    def __call__(self, op, path, *args):
        return super(steven_encfs, self).__call__(op, self.root + path, *args)

    def init(self, conn):
        self.log.debug("------------ init -------------")
        fd = os.open(self.st_size_dict_path, os.O_CREAT | os.O_RDWR)
        st = os.lstat(self.st_size_dict_path)
        fd2 = os.open(self.obfs_fn_path, os.O_CREAT | os.O_RDWR)
        st2 = os.lstat(self.obfs_fn_path)
        if (st.st_size):
            raw_read = self.read(self.st_size_dict_path, st.st_size, 0, fd)
            self.st_size_dict = json.loads(raw_read[:raw_read.index(b"}") + 1].decode('utf-8')) # load all the st_size data
        if (st2.st_size):
            raw_read2 = self.read(self.obfs_fn_path, st2.st_size, 0, fd2)
            self.obfs_fn = json.loads(raw_read2[:raw_read2.index(b"}") + 1].decode('utf-8'))
        os.close(fd)
        os.close(fd2)
        os.remove(self.st_size_dict_path)
        os.remove(self.obfs_fn_path)

    def destroy(self, private_data):
        fd = os.open(self.st_size_dict_path, os.O_CREAT | os.O_RDWR)
        fd2 = os.open(self.obfs_fn_path, os.O_CREAT | os.O_RDWR)
        os.lseek(fd, 0, 0)
        os.lseek(fd2, 0, 0)
        self.write(self.st_size_dict_path, json.dumps(self.st_size_dict).encode('utf-8'), 0, fd, False)
        self.write(self.obfs_fn_path, json.dumps(self.obfs_fn).encode('utf-8'), 0, fd2, False)
        os.close(fd)
        os.close(fd2)

    def path_obfuscate(self, path):
        if path == self.root + "/":
            return path
        rel_path = path.replace(self.root, '')
        rel_path = [p for p in rel_path.split('/') if len(p) > 0]
        for i in range(len(rel_path)):
            p = rel_path[i]
            obfsed = base64.b16encode(hashlib.sha256(p.encode()).digest()).decode()
            self.obfs_fn[obfsed] = p
            rel_path[i] = obfsed
        obfs_path = self.root
        for p in rel_path:
            obfs_path += "/" + p
        return obfs_path

    def path_deobfuscate(self, path):
        if path == self.root + "/":
            return path
        return self.obfs_fn[path]

    def access(self, path, mode):
        obfs_path = self.path_obfuscate(path)
        if path == self.proc_wl_path: return None
        if not os.access(obfs_path, mode):
            raise FuseOSError(EACCES)

    def chmod(self, path, mode):
        obfs_path = self.path_obfuscate(path)
        if path == self.proc_wl_path: raise FuseOSError(EACCES)
        os.chmod(obfs_path, mode)

    def chown(self, path, mode):
        obfs_path = self.path_obfuscate(path)
        if path == self.proc_wl_path: raise FuseOSError(EACCES)
        os.chown(obfs_path, mode)

    def create(self, path, mode):
        obfs_path = self.path_obfuscate(path)
        return os.open(obfs_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)

    def flush(self, path, fh):
        return 0

    def fsync(self, path, datasync, fh):
        return 0

    def getattr(self, path, fh=None):
        obfs_path = self.path_obfuscate(path)
        if path == self.proc_wl_path:
            return {'st_atime':time(), 'st_ctime':time(), 'st_mode':33188, 'st_mtime':time(), 'st_nlink':1, 'st_size':len(str(self.proc_wl))}
        st = os.lstat(obfs_path)
        ret_st = dict((key, getattr(st, key)) for key in (
            'st_atime', 'st_ctime', 'st_gid', 'st_mode', 'st_mtime',
            'st_nlink', 'st_uid'))
        if (obfs_path not in self.st_size_dict): self.st_size_dict[obfs_path] = 0
        ret_st['st_size'] = self.st_size_dict[obfs_path]
        return ret_st

    getxattr = None

    def link(self, target, source):
        return os.link(self.root + source, target)

    listxattr = None

    def mkdir(self, path, mode):
        obfs_path = self.path_obfuscate(path)
        os.mkdir(obfs_path, mode)

    def mknod(self, path, mode):
        obfs_path = self.path_obfuscate(path)
        os.mknod(obfs_path, mode)

    def open(self, path, flags):
        obfs_path = self.path_obfuscate(path)
        if obfs_path == self.proc_wl_path: return 0
        else:
            return os.open(obfs_path, flags)

    def read_block(self, path, start_block, num_blocks, fh):
        self.log.debug("------------------ read_block ------------------")
        obfs_path = self.path_obfuscate(path)
        with self.rwlock:
            os.lseek(fh, start_block*self.block_size, 0)
            return os.read(fh, num_blocks*self.block_size)

    def read(self, path, size, offset, fh):
        obfs_path = self.path_obfuscate(path)
        if obfs_path == self.proc_wl_path: return str(self.proc_wl).encode()
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
        obfs_path = self.path_obfuscate(path)
        fn = [self.path_deobfuscate(f) for f in os.listdir(obfs_path)]
        self.log.debug("-------------------------- readdir %s %s -----------------------", obfs_path, self.root + "/")
        if (path == (self.root + "/")): fn.append("proc_wl")
        return ['.', '..'] + fn

    def readlink(self, path):
        obfs_path = self.path_obfuscate(path)
        return os.readlink(obfs_path)

    def release(self, path, fh):
        obfs_path = self.path_obfuscate(path)
        if path == self.proc_wl_path: return 0
        return os.close(fh)

    def rename(self, old, new):
        return os.rename(old, self.root + new)

    def rmdir(self, path):
        obfs_path = self.path_obfuscate(path)
        del self.st_size_dict[obfs_path]
        return os.rmdir(obfs_path)

    def statfs(self, path):
        obfs_path = self.path_obfuscate(path)
        stv = os.statvfs(obfs_path)
        return dict((key, getattr(stv, key)) for key in (
            'f_bavail', 'f_bfree', 'f_blocks', 'f_bsize', 'f_favail',
            'f_ffree', 'f_files', 'f_flag', 'f_frsize', 'f_namemax'))

    def symlink(self, target, source):
        return os.symlink(source, target)

    def truncate(self, path, length, fh=None):
        obfs_path = self.path_obfuscate(path)
        if path == self.proc_wl_path: return None
        self.st_size_dict[obfs_path] = length
        truncated_length = length // self.block_size
        if length % self.block_size != 0: truncated_length += 1
        os.truncate(obfs_path, truncated_length)

    def unlink(self, path):
        obfs_path = self.path_obfuscate(path)
        st = self.getattr(path)
        if (st['st_nlink'] == 1): del self.st_size_dict[obfs_path]
        os.unlink(obfs_path)

    utimens = os.utime

    def write_block(self, path, block_data, start_block, fh):
        obfs_path = self.path_obfuscate(path)
        self.log.debug("------------------ write_block ------------------")
        with self.rwlock:
            os.lseek(fh, start_block*self.block_size, 0)
            return os.write(fh, block_data)

    def write(self, path, data, offset, fh, obfs=True):
        if obfs:
            obfs_path = self.path_obfuscate(path)
        else:
            obfs_path = path
        self.log.debug("------------------ write ------------------")
        data_len = len(data)
        if path == self.proc_wl_path:
            wl_str = str(self.proc_wl)
            wl_str = wl_str[:offset] + data.decode() + wl_str[(offset + data_len) : ]
            wl_str = wl_str[wl_str.index("["):wl_str.index("]") + 1]
            self.proc_wl = ast.literal_eval(wl_str)
            return data_len
        if (obfs_path not in self.st_size_dict): self.st_size_dict[obfs_path] = 0
        self.st_size_dict[obfs_path] = max(self.st_size_dict[obfs_path], offset + data_len)
        start_block = offset // self.block_size
        num_blocks = data_len // self.block_size
        if (data_len % self.block_size): num_blocks += 1
        if num_blocks == 0: return 0

        new_fh = os.open(obfs_path, os.O_RDONLY)
        rb_data = self.read_block(path, start_block, num_blocks, new_fh)
        self.log.debug("readblock data: %s\n", rb_data)
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
    parser = argparse.ArgumentParser(description="Steven's EncFS")
    parser.add_argument('encdir', help="the root directory containing the encrypted file system.")
    parser.add_argument('mount', help="the root directory of where your new mounted file system.")
    parser.add_argument('init_pid', help="the pid of the first process who will be given access. preferably a shell pid")

    pw_hash = hashlib.sha256(getpass.getpass("Please input a password to decrypt to FS: ").encode()).digest()

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)
    fuse = FUSE(
        steven_encfs(args.encdir, pw_hash, int(args.init_pid)), args.mount, foreground=True, allow_other=True)
