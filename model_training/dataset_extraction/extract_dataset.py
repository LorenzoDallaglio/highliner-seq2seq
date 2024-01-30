import os
import traceback
from tqdm import tqdm
from dwarf_parsing.inline_instance import get_inlined_instances
from angr_utils.block_utils import blockNavigator, get_instructions, compute_inlined_flags
from config.vars import BINARIES_DIR, SNIPPETS_DIR, OPT_LEVELS, METHODS
from json import dump, load


def handle_exception(problem_project, problem_binary):
    with open("logs/exec_trace.txt", 'a+') as trace_file:
        trace_file.write(proj_name + " - " + opt_level + "\n")
        if problem_binary:
            trace_file.write("Problematic binary is " + problem_binary + "\n")
        traceback.print_exc(file = trace_file)


if __name__ =="__main__":
    proj_list = sorted(os.listdir(BINARIES_DIR))
    opt_levels = OPT_LEVELS
    output = []

    for proj_name in tqdm(proj_list, desc='Progress over projects', colour='GREEN'):
        print("Parsing project {}\n".format(proj_name))
        proj_dir = BINARIES_DIR + proj_name

        for opt_level in OPT_LEVELS:
            bin_dir = os.path.join(proj_dir, opt_level)

            for bin_name in os.listdir(bin_dir):
                print("Extracting from binary {}{}".format(bin_name, opt_level))

                proj_data = {'binary': bin_name,
                        'optimization': opt_level,
                        'matches': []}

                elf_path = os.path.join(bin_dir, bin_name)

                try:
                    inlined_instances_list = get_inlined_instances(elf_path, METHODS)

                    navigator = blockNavigator(elf_path)
                    navigator.make_function_list()
                    base_addr = navigator.base_addr

                    for instance in inlined_instances_list:
                        ranges = instance['ranges']
                        matching_blocks = navigator.find_overlapping_blocks(ranges)

                        match = {'method': instance['method'],
                                'blocks' : []}

                        for block, node_type in matching_blocks:
                            block_data = {'address': block.addr - base_addr,
                                   'node_type': node_type,
                                   'instructions': get_instructions(block),
                                   'inline_flags': compute_inlined_flags(block, ranges, base_addr)
                                    }
                            match['blocks'].append(block_data)

                        if match['blocks']:
                            proj_data['matches'].append(match)

                except KeyboardInterrupt:
                    handle_exception(proj_name, bin_name)
                    exit()
                except:
                    handle_exception(proj_name, bin_name)

                if proj_data['matches']:
                    output.append(proj_data)
                    with open("data/output.json", 'w') as output_file:
                        dump(output, output_file, indent=2)

