###############
### IMPORTS ###
###############
import pdb
import angr
import os
import traceback
from modules.dwarf_parser import Dwarf
from modules.persistence import save_state, load_state
from pwn import *
from modules.name_mangling import demangle


########################
### GLOBAL VARIABLES ###
########################

BINARIES_DIR = 'binary_dataset/'
SNIPPETS_DIR = 'snippet_dataset/'
DEFAULT_OPT = ["-O2"]
#OPT_LEVELS = ["-O2", "-O3", "-Os", "-Ofast"]
METHODS = {
    "std::deque::operator[]",
    "std::deque::pop_front",
    "std::deque::push_back",
    "std::map::find",
    "std::map::lower_bound",
    "std::map::operator[]",
    "std::map::upper_bound"
    "std::vector::clear",
    "std::vector::erase",
    "std::vector::push_back",
    "std::vector::reserve",
    "std::vector::resize"
}

###############
### CLASSES ###
###############

class inlinedInfo:
    def __init__(self, demangled_name, ranges=[], blocks=[]):
        self.demangled_name = demangled_name
        self.ranges = ranges.copy()
        self.blocks = blocks.copy()

    def __repr__(self):
        name_repr = "Name: {}".format(self.demangled_name)
        ranges_repr = "Ranges: "
        for ran in self.ranges:
            ranges_repr += "{} -> {}, ".format(hex(ran[0]), hex(ran[1]))

        block_repr = "Blocks: "
        for block in self.blocks:
            block_repr += "{} -> {}, ".format(hex(block[0]), hex(block[1]))

        return "{}\n{}\n{}\n".format(name_repr, ranges_repr, block_repr)



#################
### FUNCTIONS ###
#################

def get_inlined_instances(elf_path):
    dobject = Dwarf(elf_path)
    inlined_instances_list = []
    for mangled_name, ranges in dobject.get_inlined_subroutines_info():
        namespace, method = demangle(mangled_name)
        demangled_name = namespace + "::" + method
        if demangled_name in METHODS:
            new_instance = inlinedInfo(demangled_name)
            for elem in ranges:
                new_instance.ranges.append([elem[0], elem[1]])
            inlined_instances_list.append(new_instance) 
        else:
            pass
    return inlined_instances_list



# Navigates the cfg starting from the entry node in a tree search
# For each block, it checks all instances and their ranges
# In case of overlap, it adds the block to the instance list
def find_blocks(elf_path, inlined_info_list):
    angr_proj = angr.Project(elf_path, load_options={'auto_load_libs': False})
    base_addr = angr_proj.loader.main_object.min_addr
    cfg = angr_proj.analyses.CFGFast()
    entry_node = cfg.get_any_node(angr_proj.entry)

    blocks_queue = [entry_node]
    visited_blocks = set(blocks_queue) # Sets allow for O(1) lookup

    #Navigate CFG through a graph search
    while len(blocks_queue) > 0:
        block = blocks_queue.pop(0)
        block_start = block.addr - base_addr
        block_end = block_start + block.size

        for instance in inlined_info_list:
            for rang in instance.ranges:
                if (block_start < rang[1] and block_end > rang[0]):
                    instance.blocks.append([block_start, block_end])
                    break

        for succ in block.successors:
            if succ not in visited_blocks:
                visited_blocks.add(succ)
                blocks_queue.append(succ)


#Name used as ID is name of the binary + name of the method + covered range
def compose_name(elf_name, inlined_instance):
    elf_id = elf_name
    method_id = inlined_instance.demangled_name.replace('\'', '')
    range_id = str([hex(inlined_instance.blocks[0][0]), hex(inlined_instance.blocks[-1][1])])  
    snippet_name = "{}-{}-{}.txt".format(elf_id, method_id, range_id)
    return snippet_name



def compose_snippet(elf, range_list):
    code = ''
    for rang in range_list:
        bytestring = elf.read(rang[0], rang[1]-rang[0])
        code += disasm(bytestring) + '\n'
    return code



def extract_asm(snippets_dir, elf_path, inlined_instances_list):
    elf = ELF(elf_path)
    elf_name = os.path.basename(elf_path)
    input_dir = os.path.join(snip_dir, "input")
    if not os.path.exists(input_dir): 
        os.mkdir(input_dir)
    target_dir = os.path.join(snip_dir, "target")
    if not os.path.exists(target_dir): 
        os.mkdir(target_dir)
    print("INPUT:" + input_dir + "\nTARGET:" + target_dir)

    for instance in inlined_instances_list:
        if len(instance.blocks) > 0:
            snippet_name = compose_name(elf_name, instance)
            input_snippet = compose_snippet(elf, instance.blocks)
            target_snippet = compose_snippet(elf, instance.ranges)
            #XXX
            if len(input_snippet) >= len(target_snippet):
                with open(os.path.join(input_dir, snippet_name), "w") as input_file:
                    input_file.write(input_snippet)
                with open(os.path.join(target_dir, snippet_name), "w") as target_file:
                    target_file.write(target_snippet)



def extract_snippets(elf_path, snip_dir):
    # 1) DWARF info is parsed into InlinedInfo objects
    print("Parsing DWARF to get instances:\n")
    inlined_instances_list = get_inlined_instances(elf_path)

    # 2) InlinedInfo ranges are used to identify blocks containing the inlined instance instructions
    print("Navigating CFG to identify relevant blocks:\n")
    find_blocks(elf_path, inlined_instances_list)
    print (inlined_instances_list)

    # 3) Asm snippets of identified blocks and ranges are extracted to files
    print("WRITING SNIPPETS")
    extract_asm(snip_dir, elf_path, inlined_instances_list) 



def handle_exception(proj_name, opt_level, proj_list, opt_levels, problem_binary=''):
    print(proj_name + " - " + opt_level)
    if problem_binary:
        print("Problematic binary is " + problem_binary)
    traceback.print_exc()
    leftover_proj = proj_list[proj_list.index(proj_name):]
    leftover_opt = opt_levels[opt_levels.index(opt_level)+1:]
    save_state(leftover_proj, leftover_opt)



if __name__ =="__main__":
    context.arch = "amd64"
    #Future implementation should possibly cycle over both g++ and Clang
    
    proj_list, opt_levels = load_state() 
    if len(proj_list) == 0:
        proj_list = os.listdir(BINARIES_DIR)
    if len(opt_levels) == 0:
        opt_levels = DEFAULT_OPT

    for proj_name in proj_list:
        print("Parsing project: " + proj_name)
        proj_dir = BINARIES_DIR + proj_name
        proj_snip_dir = SNIPPETS_DIR + proj_name
        if not os.path.exists(proj_snip_dir): 
            os.mkdir(proj_snip_dir)

        for opt_level in opt_levels:
                print("With optimization: " + opt_level)
                bin_dir = os.path.join(proj_dir, opt_level)
                snip_dir = os.path.join(proj_snip_dir, opt_level)
                if not os.path.exists(snip_dir): 
                    os.mkdir(snip_dir)

                for bin_name in os.listdir(bin_dir):
                        try:
                            elf_path = os.path.join(bin_dir, bin_name)
                            print("FOR BINARY AT: " + elf_path)
                            extract_snippets(elf_path, snip_dir)
                        except KeyboardInterrupt:
                            handle_exception(proj_name, opt_level, proj_list, opt_levels)
                            exit()
                        except:
                            handle_exception(proj_name, opt_level, proj_list, opt_levels, bin_name)
        opt_levels = DEFAULT_OPT

