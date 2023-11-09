import pdb
import os
import traceback
from dwarf_parsing.inlineInstance import *
from asm_extraction.blockNavigator import *
from snippet_creation.Snippet import * 
from utils.persistence import save_state, load_state
from utils.config import BINARIES_DIR, SNIPPETS_DIR, OPT_LEVELS, INLINE_MARK, METHODS
from pickle import dump, load

#Simulating argv
RESUME_EXEC = False
SAVE_FILES = True
SAVE_PICKLE = True

def handle_exception(leftover_proj, leftover_opt, snippet_list, problem_binary=''):
    print(proj_name + " - " + opt_level)
    if problem_binary:
        print("Problematic binary is " + problem_binary)
    traceback.print_exc()
    save_state(leftover_proj, leftover_opt, snippet_list)



if __name__ =="__main__":
    #Future implementation should possibly cycle over both g++ and Clang
    
    if RESUME_EXEC:
        proj_list, opt_levels, snippet_list = load_state() 
    else:
        proj_list = sorted(os.listdir(BINARIES_DIR))
        opt_levels = OPT_LEVELS

    snippet_list = []
    for proj_name in proj_list:
        print("Parsing project: " + proj_name)
        proj_dir = BINARIES_DIR + proj_name
        proj_snip_dir = SNIPPETS_DIR + proj_name
        if not os.path.exists(proj_snip_dir): 
            os.mkdir(proj_snip_dir)

        proj_snippets = []
        for opt_level in opt_levels:
            print("With optimization: " + opt_level)
            bin_dir = os.path.join(proj_dir, opt_level)
            snip_dir = os.path.join(proj_snip_dir, opt_level)
            if not os.path.exists(snip_dir): 
                os.mkdir(snip_dir)
            
            for bin_name in os.listdir(bin_dir):
                elf_path = os.path.join(bin_dir, bin_name)
                print("FOR BINARY AT: " + elf_path)
                try:
                    print("Parsing DWARF to get instances:\n")
                    inlined_instances_list = get_inlined_instances(elf_path, METHODS)

                    print("Navigating CFG to identify relevant blocks:\n")
                    navigator = blockNavigator(elf_path)
                    navigator.make_function_list()
                    for instance in inlined_instances_list:
                        overlapping_blocks = navigator.find_overlapping_blocks(instance.ranges)
                        print (instance, [[hex(block.addr), hex(block.addr + block.size)] for block in overlapping_blocks])

                        snippet = Snippet(bin_name, opt_level, instance.demangled_name, addr=instance.ranges[0][0])
                        snippet.load_code(instance.ranges, navigator.base_addr, overlapping_blocks, INLINE_MARK)
                        snippet.build_sequences(INLINE_MARK)
                        if SAVE_FILES:
                            snippet.to_file(snip_dir)
                        proj_snippets.append(snippet)

                except KeyboardInterrupt:
                    leftover_proj = proj_list[proj_list.index(proj_name):]
                    leftover_opt = opt_levels[opt_levels.index(opt_level):]
                    handle_exception(leftover_proj, leftover_opt, snippet_list, problem_binary=bin_name)
                    exit()
                except:
                    leftover_proj = proj_list[proj_list.index(proj_name):]
                    leftover_opt = opt_levels[opt_levels.index(opt_level):]
                    handle_exception(leftover_proj, leftover_opt, snippet_list, problem_binary=bin_name)

        snippet_list += proj_snippets

    if SAVE_PICKLE:
        with open("data/pickled_data.pickle", "wb") as pickle_file:
            dump(snippet_list, pickle_file)
