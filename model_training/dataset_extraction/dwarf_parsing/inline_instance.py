from dwarf_parsing.bino.dwarf_parser import Dwarf
from dwarf_parsing.bino.name_mangling import demangle

def get_inlined_instances(elf_path, methods_of_interest):
    dobject = Dwarf(elf_path)
    inlined_instances_list = []

    for mangled_name, ranges in dobject.get_inlined_subroutines_info():
        namespace, method = demangle(mangled_name)
        demangled_name = namespace + "::" + method

        if demangled_name in methods_of_interest:
            new_instance = {'method': demangled_name,
                    'ranges': []}
            for elem in ranges:
                # Inlined instructions may become dead code and be removed
                # Resulting 0-byte Dwarf rangers are ignored
                if elem[1] - elem[0] > 0:
                    new_instance['ranges'].append([elem[0], elem[1]])

            # Instances with 0-byte ranges only are ignored
            if new_instance['ranges']:
                inlined_instances_list.append(new_instance)
        else:
            pass

    return inlined_instances_list
