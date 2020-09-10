
# These module alos are used by protection code, so that protection
# code needn't import anything
import os
import platform
import sys
import struct

# Because ctypes is new from Python 2.5, so pytransform doesn't work
# before Python 2.5
#
from ctypes import cdll, c_char, c_char_p, c_int, c_void_p, \
    pythonapi, py_object, PYFUNCTYPE, CFUNCTYPE
from fnmatch import fnmatch

#
# Support Platforms
#
plat_path = 'platforms'

plat_table = (
    ('windows', ('windows', 'cygwin-*')),
    ('darwin', ('darwin', 'ios')),
    ('linux', ('linux*',)),
    ('freebsd', ('freebsd*', 'openbsd*')),
    ('poky', ('poky',)),
)

arch_table = (
    ('x86', ('i?86', )),
    ('x86_64', ('x64', 'x86_64', 'amd64', 'intel')),
    ('arm', ('armv5',)),
    ('armv6', ('armv6l',)),
    ('armv7', ('armv7l',)),
    ('ppc64', ('ppc64le',)),
    ('mips32', ('mips',)),
    ('aarch32', ('aarch32',)),
    ('aarch64', ('aarch64', 'arm64'))
)

#
# Hardware type
#
HT_HARDDISK, HT_IFMAC, HT_IPV4, HT_IPV6, HT_DOMAIN = range(5)

#
# Global
#
_pytransform = None


class PytransformError(Exception):
    pass


def dllmethod(func):
    def wrap(*args, **kwargs):
        return func(*args, **kwargs)
    return wrap


@dllmethod
def version_info():
    prototype = PYFUNCTYPE(py_object)
    dlfunc = prototype(('version_info', _pytransform))
    return dlfunc()


@dllmethod
def init_pytransform():
    major, minor = sys.version_info[0:2]
    # Python2.5 no sys.maxsize but sys.maxint
    # bitness = 64 if sys.maxsize > 2**32 else 32
    prototype = PYFUNCTYPE(c_int, c_int, c_int, c_void_p)
    init_module = prototype(('init_module', _pytransform))
    ret = init_module(major, minor, pythonapi._handle)
    if (ret & 0xF000) == 0x1000:
        raise PytransformError('Initialize python wrapper failed (%d)'