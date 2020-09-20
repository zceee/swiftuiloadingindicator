
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
                               % (ret & 0xFFF))
    return ret


@dllmethod
def init_runtime():
    prototype = PYFUNCTYPE(c_int, c_int, c_int, c_int, c_int)
    _init_runtime = prototype(('init_runtime', _pytransform))
    return _init_runtime(0, 0, 0, 0)


@dllmethod
def encrypt_code_object(pubkey, co, flags, suffix=''):
    _pytransform.set_option(6, suffix.encode())
    prototype = PYFUNCTYPE(py_object, py_object, py_object, c_int)
    dlfunc = prototype(('encrypt_code_object', _pytransform))
    return dlfunc(pubkey, co, flags)


@dllmethod
def generate_license_file(filename, priname, rcode, start=-1, count=1):
    prototype = PYFUNCTYPE(c_int, c_char_p, c_char_p, c_char_p, c_int, c_int)
    dlfunc = prototype(('generate_project_license_files', _pytransform))
    return dlfunc(filename.encode(), priname.encode(), rcode.encode(),
                  start, count) if sys.version_info[0] == 3 \
        else dlfunc(filename, priname, rcode, start, count)


@dllmethod
def generate_license_key(prikey, keysize, rcode):
    prototype = PYFUNCTYPE(py_object, c_char_p, c_int, c_char_p)
    dlfunc = prototype(('generate_license_key', _pytransform))
    return dlfunc(prikey, keysize, rcode) if sys.version_info[0] == 2 \
        else dlfunc(prikey, keysize, rcode.encode())


@dllmethod
def get_registration_code():
    prototype = PYFUNCTYPE(py_object)
    dlfunc = prototype(('get_registration_code', _pytransform))
    return dlfunc()


@dllmethod
def get_expired_days():
    prototype = PYFUNCTYPE(py_object)
    dlfunc = prototype(('get_expired_days', _pytransform))
    return dlfunc()


@dllmethod
def clean_obj(obj, kind):
    prototype = PYFUNCTYPE(c_int, py_object, c_int)
    dlfunc = prototype(('clean_obj', _pytransform))
    return dlfunc(obj, kind)


def clean_str(*args):
    tdict = {
        'str': 0,
        'bytearray': 1,
        'unicode': 2
    }
    for obj in args:
        k = tdict.get(type(obj).__name__)
        if k is None:
            raise RuntimeError('Can not clean object: %s' % obj)
        clean_obj(obj, k)