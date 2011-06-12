import os
import ctypes
import struct

libc = ctypes.CDLL('/lib/libc.so.6')

lseek = libc.lseek64
u64 = ctypes.c_uint64
ptr = ctypes.c_ulong
ptrsize = ctypes.sizeof(ptr)

NR_CPUS = 64    # kernel config

# XXX: need CAP_SYS_RAWIO (or euid == 0)
kmem = os.open('/dev/kmem', 0, 0)

def kmem_read(addr, size):
    off = u64(addr)
    lseek(kmem, off, os.SEEK_SET)
    return os.read(kmem, size)

def kmem_read_ptr(addr):
    return struct.unpack('@L', kmem_read(addr, ptrsize))[0]

kallsyms = {}
with open('/proc/kallsyms') as ksyms:
    data = ((sym, long(addr, 16))
            for addr, ty, sym in (l.split()[:3] for l in ksyms.readlines())
            if ty == 'D')
    kallsyms = dict(data)

per_cpu_offset = lambda cpuno=0: kmem_read_ptr(kallsyms['__per_cpu_offset'] + cpuno * ptrsize)

def per_cpu(sym, cpuno=0):
    addr = kallsyms[sym]
    off = per_cpu_offset(cpuno)

    return kmem_read_ptr(off + addr)
