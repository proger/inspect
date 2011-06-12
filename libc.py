import os
import ctypes
import struct
from commands import getoutput as go

libc = ctypes.CDLL('/lib/libc.so.6')

lseek = libc.lseek64
u64 = ctypes.c_uint64

# XXX: need CAP_SYS_RAWIO
kmem = os.open('/dev/kmem', 0, 0)

# TODO: percpu()

def kmem_read(fd, addr, size):
    off = u64(addr)

    lseek(fd, off, os.SEEK_SET)
    return os.read(fd, size)

def read_udpmem():
    #  ffffffff81cc07a0 D sysctl_udp_mem    long[3]

    data = struct.unpack('@lll',
            kmem_read(kmem, 0xffffffff81cc07a0L, 8 * 3))

    # sysctl net.ipv4.udp_mem
    assert map(int, go('sysctl net.ipv4.udp_mem').split('=')[1].split()) == list(data)
    return data
