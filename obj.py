from pyelf import dwarf

class Object(object):
    def __init__(self, type, ptr, handler, parent=None, name=''):
        self.type = type
        self.ptr = ptr
        self.handler = handler
        self.parent = parent
        self.name = name
        #if parent:
        #    self.name = self.parent.name + '.' + name
        #else:
        #    self.name = name or self.type.die.name

        self._members = self.members
        self.members_dict = dict((o.name, o) for o in self._members) if self._members else None

    def __repr__(self):
        addr = hex(self.ptr) if not self.parent else '+' + hex(self.ptr - self.parent.ptr)
        return '<{0} {1} {2}>'.format(self.type.name, self.name, addr)

    @property
    def value(self):
        try:
            return self.handler.read(self.ptr, self.type.size)
        except BaseException, e:
            return None

    @property
    def members(self):
        if hasattr(self, '_members'):
            return self._members

        if self.type.__class__ != dwarf.Struct:
            return None

        return [
            Object(type, self.ptr + offset, self.handler, self, name)
            for offset, type, name in self.type.members
        ]
