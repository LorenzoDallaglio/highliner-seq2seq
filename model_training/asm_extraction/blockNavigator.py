import angr 

#Basic, borderline redundant decorator of angr
class blockNavigator:
    def __init__(self, elf_path):
        self.proj = angr.Project(elf_path, main_opts={'arch': "amd64"}, load_options={'auto_load_libs': False})
        self.base_addr = self.proj.loader.main_object.min_addr
        cfg = self.proj.analyses.CFGFast(normalize=True)
        self.function_manager = cfg.kb.functions
        self.function_list = []

#NOTE: How fast is using the function manager? perhaps not using the ceiling function is faster?
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
        starting_addr = ranges[0][0] #DWARF ranges are sorted in increasing order - tested
        context_fun = self.find_context_function(starting_addr + self.base_addr)
        block_list = sorted(context_fun.blocks, key = lambda block: block.addr)
        overlapping_blocks = []
#NOTE: knowing both blocks and ranges are sorted, a more optimal approach whould iterate on each once
        for block in block_list:
            for rang in ranges:
                block_start = block.addr - self.base_addr
                block_end = block_start + block.size
                if (block_start < rang[1]  and block_end > rang[0]):
                    overlapping_blocks.append(block)
                    break
        return overlapping_blocks

