import angr
import os
from dwarf_parser import *
from pwn import *

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


def extractInstances(elf_path, base_addr):
    dobject = Dwarf(elf_path)
    inlined_instances_list = []
    for mangled_name, ranges in dobject.get_inlined_subroutines_info():
        new_instance = inlinedInfo(mangled_name)
        range_start = ranges[0][0] + base_addr
        new_instance.ranges.append([ranges[0][0] + base_addr, ranges[0][1] + base_addr])
        for elem in ranges[1:]:
            new_instance.ranges.append([elem[0] + range_start, elem[1] + range_start])
        inlined_instances_list.append(new_instance) 

    return inlined_instances_list


# Navigates the cfg starting from the entry node in a tree search
# For each block, it checks all instances and their ranges
# In case of overlap, it adds the block to the instance list
#NOTE: currently, there's a bug of some sort due to which some blocks aren't parsed. 
def extractBlocks(cfg, entry_node, inlined_info_list):
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



def extractAsm(snippets_dir, elf_path, inlined_instances_list):
    elf = ELF(elf_path)
    for instance in inlined_instances_list:
        if len(instance.blocks) > 0: #XXX: but why should this ever happen?
            # Snippet identifier is name + full range block
            range_ID = str([hex(instance.blocks[0][0]), hex(instance.blocks[-1][1])]) # This is used to uniquely identify each snippet - might have collisions 
            snippet_name = "{}-{}.txt".format(instance.mangled_name, range_ID).replace('\'', '')

            input_snippet = open(snippets_dir + "input/" + snippet_name, "w")
            code = ''
            for block in instance.blocks:
                bytestring = elf.read(block[0] - 0x400000 , block[1]-block[0])
                code += disasm(bytestring) + '\n'
                input_snippet.write(code)
            input_snippet.close()

            target_snippet = open(snippets_dir + "target/" + snippet_name, "w")
            code = ''
            for rang in instance.ranges:
                #NOTE: there is a problem with single instance ranges
                bytestring = elf.read(rang[0] - 0x400000 , rang[1]-rang[0]+1)
                code += disasm(bytestring) + '\n'
            target_snippet.write(code)
            target_snippet.close()



if __name__ =="__main__":
    context.arch = "amd64"
    #Future implementation should possibly cycle over both g++ and Clang
    optimizations = ["O2"]
    #optimizations = ["O2", "O3", "Ofast", "Os"]
    proj_dir = "projects/"
    for bin_name in os.listdir(proj_dir):
        print("Parsing project: " + bin_name)
        proj_path = proj_dir + bin_name
        for opt_level in optimizations:
            print("With optimization: " + opt_level)
            elf_path = proj_path + "/{}_{}.o".format(bin_name, opt_level)
            snippets_dir = proj_path + "/snippets/{}/".format(opt_level)
            try:
                os.mkdir(snippets_dir)
            except FileExistsError:
                pass

            try:
                os.mkdir(snippets_dir + "input")
                os.mkdir(snippets_dir + "target")
            except FileExistsError:
                pass

            angr_proj = angr.Project(elf_path, load_options={'auto_load_libs': False})
            base_addr = angr_proj.loader.main_object.min_addr
            #dwarf info is parsed into InlinedInfo objects
            #NOTE: it is quite ugly to pass around a bunch of paths and objects instead of a single one - should think of universal solution
            inlined_instances_list = extractInstances(elf_path, base_addr)

            #InlinedInfo ranges are used to identify blocks containing the inlined instance instructions
            cfg = angr_proj.analyses.CFGFast()
            entry_node = cfg.get_any_node(angr_proj.entry)
            extractBlocks(cfg, entry_node, inlined_instances_list)

            #DEBUG
            #print("Some leftovers!")
            #for elem in inlined_instances_list:
            #    if len(elem.blocks) < 1:
            #        print(elem)

           # extract asm snippets of identified blocks
            extractAsm(snippets_dir, elf_path, inlined_instances_list) 
            
            for e in inlined_instances_list:
                print(e)
