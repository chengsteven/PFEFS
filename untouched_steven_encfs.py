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

untouched_steven_encfs.py is a simple passthrough FS. This is kept for benchmark purposes.

author: @chengsteven
"""
#!/usr/bin/env python
from __future__ import print_function, absolute_import, division

import logging
import os

from errno import EACCES
from os.path import realpath
from threading import Lock

from fuse import FUSE, FuseOSError, Operations, LoggingMixIn


class steven_encfs(LoggingMixIn, Operations):
    def __init__(self, root):
        self.root = realpath(root)
        self.rwlock = Lock()

    def __call__(self, op, path, *args):
        return super(steven_encfs, self).__call__(op, self.root + path, *args)

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
        return dict((key, getattr(st, key)) for key in (
            'st_atime', 'st_ctime', 'st_gid', 'st_mode', 'st_mtime',
            'st_nlink', 'st_size', 'st_uid'))

    getxattr = None

    def link(self, target, source):
        return os.link(self.root + source, target)

    listxattr = None
    mkdir = os.mkdir
    mknod = os.mknod
    open = os.open

    def read(self, path, size, offset, fh):
        with self.rwlock:
            os.lseek(fh, offset, 0)
            return os.read(fh, size)

    def readdir(self, path, fh):
        return ['.', '..'] + os.listdir(path)

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

    def write(self, path, data, offset, fh):
        with self.rwlock:
            os.lseek(fh, offset, 0)
            return os.write(fh, data)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('encdir')
    parser.add_argument('mount')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)
    fuse = FUSE(
        steven_encfs(args.encdir), args.mount, foreground=True, allow_other=True)
