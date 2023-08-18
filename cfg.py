import angr
import networkx as nx

class customCfgNode:
    def __init__ (self, start_addr, size):
        self.start_addr = start_addr
        self.size = size

class inlinedInfo:
    def __init__(self, mangled_name, ranges):
        self.mangled_name = mangled_name
        self.ranges = ranges

def loadCfg(binname, proj):
    cfgpath = "projects/{}/{}.gexf".format(binname, binname)
    # Saving the graph and loading it back in future occurrences should save signficant time
    try:
        cfg = nx.read_gexf(cfgpath) 
    except:
        cfg = buildCustomCfg(proj)
        #XXX Currently unable to save calculated CFG in a proper way - slow
        #nx.write_gexf(cfg, cfgpath)
    return cfg

# XXX: search currently O(N*R)
# Returns a list of lists of block addresses
def extractBlocks(cfg, inlined_list):
    snippet_address_list = []
    for inlined_instance in inlined_list:
        search_graph = nx.DiGraph()
        #TODO: check which is the structure of the CFG
        search_graph.add_nodes_from(cfg)
        #differentiate between contiguous case and non contiguous case
        if (len(inlined_list.ranges) == 1):
            snippet_address_list += extractContiguousBlocks(cfg, inlined_list)
        elif (len(inlined_list.ranges) > 1): 
            snippet_address_list += extractRangeBlocks(cfg, inlined_list)

        
#Pseudocode for the future:
#For each range, find the starting node
#Apply this algorithm:
#   for each range:
#       if range is contained in the block, add the block and pop the range
#       if not, check successor blocks, eliminating blocks who start after the end of the considered interval
#   pass the list of blocks to the asm extractor
#

if __name__=="__main__":
    #XXX: currently it's only on single binary
    binname = "test"
    #XXX: currently it's on single optimization
    elfpath = "projects/{}/{}_O2.o".format(binname, binname)
    proj = angr.Project(elfpath, load_options={'auto_load_libs': False})

   # cfg = loadCfg(binname, proj)
    cfg = proj.analyses.CFGFast()
    cfgpath = "projects/{}/{}.txt".format(binname, binname)
    nx.write_multiline_adjlist(cfg, cfgpath)

    print("Cfg loaded!")
    node = cfg.get_any_node(proj.entry)
    print(dir(node))
    print(hex(node.addr)) #address of where the code starts
    print(node.size) #node size
    
    

