import os
import ctypes

libc = ctypes.CDLL('/lib/libc.so.6')

lseek = libc.lseek64
u64 = ctypes.c_uint64

kmem = os.open('/dev/kmem', 0, 0)

#  ffffffff81cc07a0 D sysctl_udp_mem    long[3]
off = u64(0xffffffff81cc07a0)
