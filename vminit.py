import sys
import os
import struct
from functools import partial

sys.path.insert(0, './pyelf/obj')

import cydwarf
from pyelf import dwarf

import linux
import obj


dw = cydwarf.Dwarf(os.open('/home/proger/dev/linux/obj/vmlinux', 0))

task = dwarf.locatebyname(dw, 'task_struct')
curp = linux.kmem.per_cpu('current_task', 0)
current0 = obj.Object(task, curp, linux.kmem, name='current0')

Task = partial(obj.Object, type=task, handler=linux.kmem)

def tasks():

    all_tasks = []

    def walk_task(task):
        getptr = lambda buf: struct.unpack('@L', buf)[0]
        follow_task = lambda buf: Task(ptr=getptr(buf))

        prev = task.members_dict['tasks'].members[0].value
        next = task.members_dict['tasks'].members[1].value

        print task, prev, '<>', next

        all_tasks.extend(map(walk_task, map(follow_task, filter(None, [prev, next]))))

        return task

    walk_task(current0)

    return all_tasks
