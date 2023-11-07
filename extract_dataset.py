###############
### IMPORTS ###
###############
import pdb
import angr
import os
import traceback
from dwarf_parsing.inlineInstance import *
from asm_extraction.blockNavigator import *
from modules.persistence import save_state, load_state
from modules.tokenizer import tokenize
from modules.config import BINARIES_DIR, SNIPPETS_DIR, OPT_LEVELS, INLINE_TOKEN, METHODS

#Simulating argv
RESUME_EXEC = False
SAVE_FILES = True
SAVE_PICKLE = True


#################
### FUNCTIONS ###
#################


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
    inlined_instances_list = get_inlined_instances(elf_path, METHODS)

    # 2) InlinedInfo ranges are used to identify blocks containing the inlined instance instructions
    print("Navigating CFG to identify relevant blocks:\n")
    navigator = blockNavigator(elf_path)
    for instance in inlined_instances_list:
        overlapping_blocks = navigator.find_overlapping_blocks(instance.ranges)
        print (instance, [[hex(block.addr), hex(block.addr + block.size)] for block in overlapping_blocks])
    return

    
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

