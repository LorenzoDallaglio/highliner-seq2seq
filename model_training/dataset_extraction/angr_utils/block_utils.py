import angr 

def get_instructions(block, show_addr=False):
    instructions = []
    #note: check instructions
    for inst in block.disassembly.insns:
        inst_string = "{:x}\t".format(inst.address) if show_addr else ''
        inst_string += "{} {}".format(inst.mnemonic, inst.op_str)
        instructions.append(inst_string)
    return instructions


def compute_inlined_flags(block, ranges, base_addr):
    inline_flags = []
    for address in block.instruction_addrs:
        inlined=False
        address -= base_addr
        for rang in ranges:
            if address >= rang[0] and address < rang[1]:
                inlined=True    
                break
        inline_flags.append(inlined)
    return inline_flags


# Basic, borderline redundant decorator of angr
class blockNavigator:
    def __init__(self, elf_path):
        self.proj = angr.Project(elf_path, main_opts={'arch': "amd64"}, load_options={'auto_load_libs': False})
        self.base_addr = self.proj.loader.main_object.min_addr
        cfg = self.proj.analyses.CFGFast(normalize=True)
        self.function_manager = cfg.kb.functions
        self.function_list = []


    # Necessary due to the improper usage of networkX library from angr
    def _get_cfg_nodes(self, cfg, blocks):
        block_addresses = {block.addr: block for block in blocks}
        node_index = {block: None for block in blocks}

        for node in list(cfg.nodes):
            if node.addr in block_addresses.keys():
                block = block_addresses[node.addr]
                node_index[block] = node

        return node_index



    def _compute_node_type(self, cfg, blocks):
        if len(blocks) > 1:
            node_index = self._get_cfg_nodes(cfg, blocks)
            relations = []

            # Consider all other nodes' predecessors and successors
            preds, succs = set(), set()
            for node in node_index.values():
                node_preds = set(cfg.predecessors(node))
                node_succs = set(cfg.successors(node))
                preds = preds.union(node_preds)
                succs = succs.union(node_succs)

            for node in node_index.values():
                node_preds = set(cfg.predecessors(node))
                node_succs = set(cfg.successors(node))
                other_preds = preds.difference(node_preds)
                other_succs = succs.difference(node_succs)
                # Initial nodes aren't successors of any other node
                if node not in other_succs:
                    # Isolated nodes aren't relevant: mark them as individual
                    if node not in other_preds:
                        node_type = 'Individual'
                    else:
                        node_type = 'Initial'
                # Final nodes aren't precessor of any other node
                elif node not in other_preds:
                    node_type = 'Final'
                # All others are intermediate
                else:
                    node_type = 'Intermediate'

                relations.append(node_type)

            return relations

        # Single nodes are individuals
        elif len(blocks) > 0:
            return ['Individual']


    def make_function_list(self):
        angr_functions = []
        for angr_function in self.function_manager.values():
            # If the function is a plt function we don't care
            if angr_function.is_plt:
                continue
            # No blocks? Don't care  
            if angr_function.size == 0:
                continue
            angr_functions.append(angr_function)

        # Sort function list for better iteration
        self.function_list = sorted(angr_functions, key = lambda fun: fun.addr)


    #NOTE: suboptimal to iterate on the function once and then iterate again, but intuitive
    def find_context_function(self, address):
        ceiling_fun = self.function_manager.ceiling_func(address)
        ceiling_index = self.function_list.index(ceiling_fun)
        for candidate in reversed(self.function_list[:ceiling_index]):
            for block in candidate.blocks:
                block_start = block.addr
                block_end = block_start + block.size

                if (block_start <= address and address < block_end):
                    #possible solution: previously sort blocks, then return leftover iterators
                    #block_index = candidate.blocks.index(block)
                    #return candidate.index[block:]
                    return candidate


    def find_overlapping_blocks(self, ranges):
        #DWARF ranges are sorted in increasing order - tested
        starting_addr = ranges[0][0]
        context_fun = self.find_context_function(starting_addr + self.base_addr)
        # Sometimes inlined blocks belong to no function: return no overlapping blocks
        if not context_fun:
            return []

        block_list = sorted(context_fun.blocks, key = lambda block: block.addr)
        overlapping_blocks = []
        #NOTE: knowing both blocks and ranges are sorted, a more optimal approach whould iterate on each once
        for block in block_list:
            for rang in ranges:
                block_start = block.addr - self.base_addr
                block_end = block_start + block.size
                if (block_start < rang[1] and block_end > rang[0]):
                    overlapping_blocks.append(block)
                    break

        node_types = self._compute_node_type(context_fun.transition_graph, overlapping_blocks)
        return list(zip(overlapping_blocks, node_types))

