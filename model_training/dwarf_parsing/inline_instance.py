from dwarf_parsing.bino.dwarf_parser import Dwarf
from dwarf_parsing.bino.name_mangling import demangle

class inlineInstance:
    def __init__(self, demangled_name, ranges=[]):
        self.demangled_name = demangled_name
        self.ranges = ranges.copy()

    def __repr__(self):
        name_repr = "Name: {}".format(self.demangled_name)
        ranges_repr = "Ranges: "
        for ran in self.ranges:
            ranges_repr += "{} -> {}, ".format(hex(ran[0]), hex(ran[1]))

        return "{}\n{}\n".format(name_repr, ranges_repr)


def get_inlined_instances(elf_path, methods_of_interest):
    dobject = Dwarf(elf_path)
    inlined_instances_list = []

    for mangled_name, ranges in dobject.get_inlined_subroutines_info():
        namespace, method = demangle(mangled_name)
        demangled_name = namespace + "::" + method

        if demangled_name in methods_of_interest:
            new_instance = inlineInstance(demangled_name)
            for elem in ranges:
                if elem[1] == elem[0]:
                    continue
                new_instance.ranges.append([elem[0], elem[1]])

            inlined_instances_list.append(new_instance) 
        else:
            pass

    return inlined_instances_list
