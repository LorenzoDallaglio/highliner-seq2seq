import pdb
import os
import traceback
from dwarf_parsing.inline_instance import inlineInstance, get_inlined_instances
from asm_extraction.navigator import blockNavigator
from snippet_creation.snippet import Snippet
from snippet_creation.block_utils import get_instructions, compute_inlined_flags
from utils.persistence import save_state, load_state
from utils.config import BINARIES_DIR, SNIPPETS_DIR, OPT_LEVELS, INLINE_MARK, METHODS
from json import dump, load


def handle_exception(leftover_proj, leftover_opt, snippet_list, problem_binary=''):
    with open("logs/exec_trace.txt", 'a+') as trace_file:
        trace_file.write(proj_name + " - " + opt_level + "\n")
        if problem_binary:
            trace_file.write("Problematic binary is " + problem_binary + "\n")
        traceback.print_exc(file = trace_file)


if __name__ =="__main__":
    proj_list = sorted(os.listdir(BINARIES_DIR))
    opt_levels = OPT_LEVELS
    output = []

    for proj_index, proj_name in enumerate(proj_list):
        print("Parsing project: " + proj_name)
        proj_dir = BINARIES_DIR + proj_name

        for opt_index, opt_level in enumerate(opt_levels):
            print("With optimization: " + opt_level)
            bin_dir = os.path.join(proj_dir, opt_level)

            for bin_name in os.listdir(bin_dir):
                proj_data = {'binary': bin_name,
                        'optimization': opt_level,
                        'matches': []}

                elf_path = os.path.join(bin_dir, bin_name)
                print("FOR BINARY AT: " + elf_path)

                try:
                    print("Parsing DWARF to get instances:\n")
                    inlined_instances_list = get_inlined_instances(elf_path, METHODS)

                    print("Navigating CFG to identify relevant blocks:\n")
                    navigator = blockNavigator(elf_path)
                    navigator.make_function_list()
                    base_addr = navigator.base_addr

                    for instance in inlined_instances_list:
                        ranges = instance['ranges']
                        matching_blocks = navigator.find_overlapping_blocks(ranges)
                        print (instance, [[hex(block.addr), hex(block.addr + block.size)] for block in matching_blocks])

                        match = {'method': instance['method'],
                                'blocks' : []}

                        for block in matching_blocks:
                            block_data = {'address': block.addr - base_addr}
                            block_data['instructions'] = get_instructions(block)
                            block_data['inline_flags'] = compute_inlined_flags(block, ranges, base_addr)
                            match['blocks'].append(block_data)

                        proj_data['matches'].append(match) 

                except KeyboardInterrupt:
                    handle_exception(proj_list[proj_index:], opt_levels[opt_index:], output, problem_binary=bin_name)
                    exit()
                #except:
                #    handle_exception(proj_list[proj_index:], opt_levels[opt_index:], output, problem_binary=bin_name)

            if 'matches' in proj_data.keys():
                output.append(proj_data)

    with open("output.json", 'w') as output_file:
        dump(output, output_file, indent=2)
