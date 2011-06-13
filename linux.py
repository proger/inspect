import os
import ctypes
import struct

from pyelf import dwarf
from obj import Object

libc = ctypes.CDLL('/lib/libc.so.6')
lseek = libc.lseek64

u64 = ctypes.c_uint64
ptr = ctypes.c_ulong
ptrsize = ctypes.sizeof(ptr)

class KVM(object):
    def __init__(self):
        # XXX: need CAP_SYS_RAWIO (or euid == 0)
        self.kmem = os.open('/dev/kmem', 0, 0)

        with open('/proc/kallsyms') as ksyms:
            data = ((sym, long(addr, 16))
                    for addr, ty, sym in (l.split()[:3] for l in ksyms.readlines())
                    if ty == 'D')
            self.kallsyms = dict(data)

    def read(self, addr, size):
        off = u64(addr)
        lseek(self.kmem, off, os.SEEK_SET)
        return os.read(self.kmem, size)

    def read_ptr(self, addr):
        return struct.unpack('@L', self.read(addr, ptrsize))[0]

    def per_cpu_offset(self, cpuno=0):
        return self.read_ptr(self.kallsyms['__per_cpu_offset'] + cpuno * ptrsize)

    def per_cpu(self, sym, cpuno=0):
        addr = self.kallsyms[sym]
        off = self.per_cpu_offset(cpuno)
        return self.read_ptr(off + addr)

kmem = KVM()

def container_of(ptr, struct, member):
    type, offset = struct.member(member)
    addr = ptr - offset
    return Object(struct, addr, kmem)
