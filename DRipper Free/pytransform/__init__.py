
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