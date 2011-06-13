import linux
from commands import getoutput as go
import struct

kvm = linux.KVM()
kmem_read = kvm.read
per_cpu = kvm.per_cpu
kallsyms = kvm.kallsyms

def read_udpmem():
    #  ffffffff81cc07a0 D sysctl_udp_mem    long[3]

    data = struct.unpack('@lll',
            kmem_read(kallsyms['sysctl_udp_mem'], 8 * 3))

    # sysctl net.ipv4.udp_mem
    assert map(int, go('sysctl net.ipv4.udp_mem').split('=')[1].split()) == list(data)
    return data

def read_current_task():
    assert per_cpu('current_task', 0) != per_cpu('current_task', 1)

if __name__ == '__main__':
    print read_udpmem()
    read_current_task()
