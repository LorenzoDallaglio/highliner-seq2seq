###############
### IMPORTS ###
###############
import pdb
import angr
import os
import traceback
from modules.dwarf_parser import Dwarf
from modules.persistence import save_state, load_state
from modules.name_mangling import demangle
from modules.tokenizer import tokenize
from modules.config import BINARIES_DIR, SNIPPETS_DIR, OPT_LEVELS, INLINE_TOKEN, METHODS

###############
### CLASSES ###
###############

#Simulating argv
RESUME_EXEC = False
SAVE_FILES = True
SAVE_PICKLE = True

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
            block_repr += "{} -> {}, ".format(hex(block.addr), hex(block.addr + block.size))

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
                if elem[1] == elem[0]:
                    continue
                new_instance.ranges.append([elem[0], elem[1]])
            inlined_instances_list.append(new_instance) 
        else:
            pass
    return inlined_instances_list



def get_angr_function_list(cfg):
    angr_functions = []
    for angr_function in cfg.kb.functions.values():
        # If the function is a plt function we don't care
        if angr_function.is_plt:
            continue
        # No blocks? Don't care  
        if angr_function.size == 0:
            continue
        angr_functions.append(angr_function)
    return sorted(angr_functions, key = lambda fun: fun.addr)


#NOTE: suboptimal to iterate on the function once and then iterate again, but intuitive
def find_context_function(instance_starting_addr, candidate_function_list):
    for candidate in reversed(candidate_function_list):
        for block in candidate.blocks:
            block_start = block.addr
            block_end = block_start + block.size
            if (block_start <= instance_starting_addr and instance_starting_addr < block_end):
                return candidate



def find_blocks(elf_path, inlined_info_list):
    angr_proj = angr.Project(elf_path, main_opts={'arch': "amd64"}, load_options={'auto_load_libs': False})
    base_addr = angr_proj.loader.main_object.min_addr
    cfg = angr_proj.analyses.CFGFast(normalize=True)
    fun_manager = cfg.kb.functions
    function_list = get_angr_function_list(cfg)

    for instance in inlined_info_list:
        for rang in instance.ranges: #Rebase Dwarf addresses
            rang[0] += base_addr
            rang[1] += base_addr

        starting_addr = instance.ranges[0][0] #DWARF ranges are sorted in increasing order - tested
        ceiling_fun = fun_manager.ceiling_func(starting_addr)
        ceiling_index = function_list.index(ceiling_fun)
        context_fun = find_context_function(starting_addr, function_list[:ceiling_index])
            
        block_list = sorted(context_fun.blocks, key = lambda block: block.addr)
        for block in block_list:
            for rang in instance.ranges:
                block_start = block.addr
                block_end = block_start + block.size
                if (block_start < rang[1] and block_end > rang[0]):
                    instance.blocks.append(block)
                    break



#Name used as ID is name of the binary + name of the method + covered range
def compose_file_name(elf_name, inlined_instance):
    elf_id = elf_name
    method_id = inlined_instance.demangled_name.replace('\'', '')
    start = inlined_instance.blocks[0].addr
    end = inlined_instance.blocks[-1].addr + inlined_instance.blocks[-1].size
    range_id = str([hex(start), hex(end)])  
    snippet_name = "{}-{}-{}.txt".format(elf_id, method_id, range_id)
    return snippet_name



#Note: suboptimal, should do the operation when checking if a block belongs or not to an instance
def compose_snippet(instance, address=False):
    code = ''
    for block in instance.blocks:
        for inst in block.disassembly.insns:
            if address:
                code += "{}:".format(hex(inst.address))
            code += "{} {}".format(inst.mnemonic, inst.op_str)
            for rang in instance.ranges:
                if inst.address >= rang[0] and inst.address < rang[1]:
                    code += INLINE_TOKEN
                    break
            code += "\n"
    return code



def extract_asm_to_files(snippets_dir, elf_path, inlined_instances_list):
    elf_name = os.path.basename(elf_path)
    for instance in inlined_instances_list:
        if len(instance.blocks) > 0:
            snippet_name = compose_file_name(elf_name, instance)
            snippet = compose_snippet(instance, address=True)
            with open(os.path.join(snippets_dir, snippet_name), "w") as input_file:
                input_file.write(str(instance))
                input_file.write("="*50 + '\n')
                input_file.write(snippet)


def extract_snippets(elf_path, snip_dir):
    # 1) DWARF info is parsed into InlinedInfo objects
    print("Parsing DWARF to get instances:\n")
    inlined_instances_list = get_inlined_instances(elf_path)

    # 2) InlinedInfo ranges are used to identify blocks containing the inlined instance instructions
    print("Navigating CFG to identify relevant blocks:\n")
    find_blocks(elf_path, inlined_instances_list)
    print (inlined_instances_list)

    
    # 3) Asm snippets of identified blocks and ranges are extracted to files
    if SAVE_FILES:
        print("Writing appropriate snippets")
        extract_asm_to_files(snip_dir, elf_path, inlined_instances_list) 
    if SAVE_PICKLE:
        pass
        #extract_asm_to_pickle(inlined_instances_list)
        



def handle_exception(proj_name, opt_level, proj_list, opt_levels, problem_binary=''):
    print(proj_name + " - " + opt_level)
    if problem_binary:
        print("Problematic binary is " + problem_binary)
    traceback.print_exc()
    leftover_proj = proj_list[proj_list.index(proj_name):]
    leftover_opt = opt_levels[opt_levels.index(opt_level)+1:]
    save_state(leftover_proj, leftover_opt)



if __name__ =="__main__":
    #Future implementation should possibly cycle over both g++ and Clang
    
    if RESUME_EXEC:
        proj_list, opt_levels = load_state() 
        if len(proj_list) == 0:
            proj_list = sorted(os.listdir(BINARIES_DIR))
        if len(opt_levels) == 0:
            opt_levels = OPT_LEVELS
    else:
        proj_list = sorted(os.listdir(BINARIES_DIR))
        opt_levels = OPT_LEVELS

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
                        #except:
                        #    handle_exception(proj_name, opt_level, proj_list, opt_levels, bin_name)

