###############
### IMPORTS ###
###############
import angr
import os
from dwarf_parser import *
from pwn import *
from unmangler import check_name, METHODS


########################
### GLOBAL VARIABLES ###
########################

BINARIES_DIR = 'binary_dataset/'
SNIPPETS_DIR = 'snippet_dataset/'
OPT_LEVELS = ["-O2"]

###############
### CLASSES ###
###############

class inlinedInfo:
    def __init__(self, mangled_name, ranges=[], blocks=[]):
        self.mangled_name = mangled_name
        self.ranges = ranges.copy()
        self.blocks = blocks.copy()

    def __repr__(self):
        name_repr = "Name: {}".format(self.mangled_name)
        ranges_repr = "Ranges: "
        for ran in self.ranges:
            ranges_repr += "{} -> {}, ".format(hex(ran[0]), hex(ran[1]))

        block_repr = "Blocks: "
        for block in self.blocks:
            block_repr += "{} -> {}, ".format(hex(block[0]), hex(block[1]))

        return "{}\n{}\n{}".format(name_repr, ranges_repr, block_repr)



#################
### FUNCTIONS ###
#################

def extract_instances(elf_path, base_addr):
    print("EXTRACTING INSTANCES:\n")
    dobject = Dwarf(elf_path)
    inlined_instances_list = []
    for mangled_name, ranges in dobject.get_inlined_subroutines_info():
        if check_name(mangled_name, METHODS):
            new_instance = inlinedInfo(mangled_name)

            range_start = ranges[0][0] + base_addr
            new_instance.ranges.append([ranges[0][0] + base_addr, ranges[0][1] + base_addr])
            for elem in ranges[1:]:
                new_instance.ranges.append([elem[0] + range_start, elem[1] + range_start])
            inlined_instances_list.append(new_instance) 
        else:
            pass
    return inlined_instances_list


# Navigates the cfg starting from the entry node in a tree search
# For each block, it checks all instances and their ranges
# In case of overlap, it adds the block to the instance list
#NOTE: currently, there's a bug of some sort due to which some blocks aren't parsed. 
def extract_blocks(cfg, entry_node, inlined_info_list):
    print("EXTRACTING BLOCKS:\n")
    visited_blocks = set() # Sets allow for O(1) lookup
    blocks_queue = [entry_node]

    # NOTE: search currently O(N*R) - better complexity might be crucial
    # Iterate over all blocks:
    while len(blocks_queue) > 0:
        block = blocks_queue.pop(0)
        block_start = block.addr
        block_end = block_start + block.size
        print("Block {} goes from {} to {}".format(block.name, hex(block_start), hex(block_end)))

        # Iterate over all instances and over all of each instances range
        for instance in inlined_info_list:
            for rang in instance.ranges:
                # If there is any overlapping between any range and the block, append the latter
                if (block_start < rang[1] and block_end > rang[0]):
                    instance.blocks.append([block_start, block_end])
                    break

        # Update the queue and the visited set for proper
        visited_blocks.add(block)
        print("Successors:")
        for succ in block.successors:
            # Avoid cycles in graph - alternative implementation would be to remove all edges
            print("{} ({}), ".format(succ.name, hex(succ.addr)))
            if succ not in visited_blocks:
                blocks_queue.append(succ)



def build_name(elf_name, inlined_instance):
    elf_id = elf_name
    method_id = inlined_instance.mangled_name.replace('\'', '')
    range_id = str([hex(inlined_instance.blocks[0][0]), hex(inlined_instance.blocks[-1][1])])  
    snippet_name = "{}-{}-{}.txt".format(elf_id, method_id, range_id)
    return snippet_name



def extract_asm(snippets_dir, elf_path, inlined_instances_list):
    print("WRITING SNIPPETS")
    elf = ELF(elf_path)
    elf_name = os.path.basename(elf_path)
    input_dir = os.path.join(snip_dir, "input")
    target_dir = os.path.join(snip_dir, "target")
    print("INPUT:" + input_dir + "\nTARGET:" + target_dir)
    if not os.path.exists(input_dir): 
        os.mkdir(input_dir)
    if not os.path.exists(target_dir): 
        os.mkdir(target_dir)

    for instance in inlined_instances_list:
        if len(instance.blocks) > 0: #XXX: but why should this ever happen?
            # Snippet identifier is elf_name + mangled_name + full range block
            snippet_name = build_name(elf_name, instance)

            input_snippet = open(os.path.join(input_dir, snippet_name), "w")
            code = ''
            for block in instance.blocks:
                bytestring = elf.read(block[0] - 0x400000 , block[1]-block[0])
                code += disasm(bytestring) + '\n'
            input_snippet.write(code)
            input_snippet.close()

            target_snippet = open(os.path.join(target_dir, snippet_name), "w")
            code = ''
            for rang in instance.ranges:
                #NOTE: there is a problem with single byte ranges
                bytestring = elf.read(rang[0] - 0x400000 , rang[1]-rang[0]+1)
                code += disasm(bytestring) + '\n'
            target_snippet.write(code)
            target_snippet.close()



if __name__ =="__main__":
    context.arch = "amd64"
    #Future implementation should possibly cycle over both g++ and Clang
    for proj_name in os.listdir(BINARIES_DIR):
        print("Parsing project: " + proj_name)
        proj_dir = BINARIES_DIR + proj_name
        proj_snip_dir = SNIPPETS_DIR + proj_name
        if not os.path.exists(proj_snip_dir): 
            os.mkdir(proj_snip_dir)

        for opt_level in OPT_LEVELS:
            print("With optimization: " + opt_level)
            bin_dir = os.path.join(proj_dir, opt_level)
            snip_dir = os.path.join(proj_snip_dir, opt_level)
 
            if not os.path.exists(snip_dir): 
                os.mkdir(snip_dir)

            for bin_name in os.listdir(bin_dir):
                elf_path = os.path.join(bin_dir, bin_name)
                print("FOR BINARY AT: " + elf_path)

                angr_proj = angr.Project(elf_path, load_options={'auto_load_libs': False})
                base_addr = angr_proj.loader.main_object.min_addr
                #dwarf info is parsed into InlinedInfo objects
                #NOTE: it is quite ugly to pass around a bunch of paths and objects instead of a single one
                #Angr already keeps an ELF in memory should think of universal solution
                inlined_instances_list = extract_instances(elf_path, base_addr)
                print(inlined_instances_list)

                #InlinedInfo ranges are used to identify blocks containing the inlined instance instructions
                #NOTE: could simply pass the angr_project entirely within here
                cfg = angr_proj.analyses.CFGFast()
                entry_node = cfg.get_any_node(angr_proj.entry)
                extract_blocks(cfg, entry_node, inlined_instances_list)

                #DEBUG
                #print("Some leftovers!")
                #for elem in inlined_instances_list:
                #    if len(elem.blocks) < 1:
                #        print(elem)

                #extract asm snippets of identified blocks
                extract_asm(snip_dir, elf_path, inlined_instances_list) 
