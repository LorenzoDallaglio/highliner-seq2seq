import angr
from dwarf_parser import *
from pwn import *

class inlinedInfo:
    def __init__(self, mangled_name, ranges=[], blocks=[]):
        self.mangled_name = mangled_name
        self.ranges = ranges
        self.blocks = blocks

    def __repr__(self):
        name_repr = "Name: {}".format(mangled_name)
        ranges_repr = "Ranges: "
        for ran in ranges:
            ranges_repr += "{} -> {}, ".format(hex(ran[0]), hex(ran[1]))

        block_repr = "Blocks: "
        for block in blocks:
            block_repr += "{} -> {}, ".format(hex(block[0]), hex(block[1]))

        return "{}\n{}\n{}\n".format(name_repr, ranges_repr, block_repr)

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
        print(new_instance)

    return inlined_instances_list

# NOTE: Current implementation creates CFGFast from scratch each iterations 
#   However, this may result in significant overhead vs just saving and reloading CFG.graph
#   May be changed in the future
#	def loadCfg(binname, proj):
#	    cfgpath = "projects/{}/{}.gexf".format(binname, binname)
#	    try:
#	        cfg = nx.read_gexf(cfgpath) 
#	    except:
#	        cfg = proj.analyses.CFGFast().graph
#	        nx.write_gexf(cfg, cfgpath)
#	    return cfg

def extractBlocks(cfg, entry_node, inlined_info_list):
    visited_blocks = set() # Sets allow for O(1) lookup
    blocks_queue = [entry_node]

    # NOTE: search currently O(N*R) - better complexity might be crucial
    while len(blocks_queue) > 0:
        block = blocks_queue.pop()
        block_start = block.addr
        block_end = block_start + block.size

        for instance in inlined_info_list:
            if len(instance.ranges) < 1:
                continue
            range_start = instance.ranges[0][0]
            # NOTE: underlying assumption that an inlined block with a jump within is NOT considered contiguous 
            if (block_start < range_start and range_start < block_end):
                instance.blocks.append([block_start, block_end])
                while (block_start < range_start and range_start < block_end):
                    instance.ranges.pop()
                    range_start = instance.ranges[0][0]

        visited_blocks.add(block)
        for succ in block.successors:
            # Avoid cycles in graph - alternative implementation would be to remove all edges
            if succ not in visited_blocks:
                # NOTE: undelying assumption that successors are ordered by increasing starting position -> SURELY FALSE
                blocks_queue.append(succ)


def extractAsm(path, elf_path, binname, inlined_instances_list):
    #NOTE: currently it's only on single optimization
    snippets_path = path + "/snippets/O2/"
    #NOTE: surely there is an already opened ELF object somewhere in memory
    elf = ELF(elf_path)
    for instance in inlined_instances_list:
        #NOTE: such a complex naming convention will not be necessary with complete script
        #   Each snippet's name as well as opt level will be provided its own subfolder
        range_ID = str([hex(instance.blocks[0][0]), hex(instance.blocks[-1][1])]) # This is used to uniquely identify each snippet - might have collisions 
        snippet_name = "{}-{}".format(instance.mangled_name, range_ID)
        snippets_path += snippet_name
        snippet = open(snippets_path, "w")
        ## Use pwn.elf.read and disasm to extract snippets
        for block in instance.blocks:
            bytestring = elf.read(block[0], block[1]-block[0])
            code = disasm(bytestring)
            snippet.write(code)
        snippet.close()


if __name__ =="__main__":
    #NOTE: currently it's only on single binary on single optimization
    #Future implementation should use a double cycle over all projects, all Os, possibly both C++ and Clang
    binname = "test"
    path = "projects/{}".format(binname)
    opt_level = "O2"
    elf_path = "projects/{}/{}_{}.o".format(binname, binname, opt_level)
    proj = angr.Project(elf_path, load_options={'auto_load_libs': False})
    base_addr = proj.loader.main_object.min_addr
    #dwarf info is parsed into InlinedInfo objects
    #NOTE: it is quite ugly to pass around a bunch of paths and objects instead of a single one - should think of universal solution
    inlined_instances_list = extractInstances(elf_path, base_addr)

    #InlinedInfo ranges are used to identify blocks containing the inlined instance instructions
    cfg = proj.analyses.CFGFast()
    entry_node = cfg.get_any_node(proj.entry)
    extractBlocks(cfg, entry_node, inlined_instances_list)

    #extract asm snippets of identified blocks
    #NOTE: Angr must surely create an Elf object of the file already
    extractAsm(path, elf_path, binname, inlined_instances_list) 

    

