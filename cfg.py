import angr
from dwarf_parser import *
from elftools.elf.elffile import ELFFile
from os.path import join

class inlinedInfo:
    def __init__(self, mangled_name, ranges=[], blocks=[]):
        self.mangled_name = mangled_name
        self.ranges = ranges
        self.blocks = blocks

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
    # XXX MISSING ADDED BASE ADDRESS
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


if __name__=="__main__":
    #NOTE: currently it's only on single binary
    binname = "test"
    #NOTE: currently it's on single optimization
    elfpath = "projects/{}/{}_O2.o".format(binname, binname)
    proj = angr.Project(elfpath, load_options={'auto_load_libs': False})

    base_addr = proj.loader.main_object.min_addr
    dobject = Dwarf(elfpath)
    inlined_instances_list = []
    for mangled_name, ranges in dobject.get_inlined_subroutines_info():
        new_instance = inlinedInfo(mangled_name)
        range_start = ranges[0][0] + base_addr
        new_instance.ranges.append([ranges[0][0] + base_addr, ranges[0][1] + base_addr])
        for elem in ranges[1:]:
            new_instance.ranges.append([elem[0] + range_start, elem[1] + range_start])

    cfg = proj.analyses.CFGFast()
    entry_node = cfg.get_any_node(proj.entry)
    extractBlocks(cfg, entry_node, inlined_instances_list)

    

    

