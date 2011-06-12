import os
import ctypes
import struct
from commands import getoutput as go

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

def per_cpu_offset(cpuno=0):
    # ffffffff81cb8760 D __per_cpu_offset
    addr = kallsyms['__per_cpu_offset']
    return kmem_read_ptr(addr + cpuno * ptrsize)

def per_cpu(sym, cpuno=0):
    addr = kallsyms[sym]
    off = per_cpu_offset(cpuno)

    return kmem_read_ptr(off + addr)

def read_udpmem():
    #  ffffffff81cc07a0 D sysctl_udp_mem    long[3]

    data = struct.unpack('@lll',
            kmem_read(kallsyms['sysctl_udp_mem'], 8 * 3))

    # sysctl net.ipv4.udp_mem
    assert map(int, go('sysctl net.ipv4.udp_mem').split('=')[1].split()) == list(data)
    return data
