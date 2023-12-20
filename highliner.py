from json import load

from angr_utils.block_utils import *
from models.EncoderDecoder import *


if __name__ == "__main__":
    ##Import bino's output
    results_path = 'test_out.json'
    with open(results_path, 'r') as results:
        bino_output = load(results)

    ##Open angr's project
    binary_path = bino_output['binary_path']
    block_index = index_blocks(binary_path, rebase=True)

    highliner = EncoderDecoder(window_size = 256)

    for match in bino_output['matches']:
        matched_blocks = match['blocks']
        angr_blocks = [block_index[block['address']] for block in matched_blocks]

        inst_seq = []
        for block in angr_blocks:
            print(disasm_as_seq(block))
            inst_seq += disasm_as_seq(block)

        #prob_seq = highliner.predict(inst_seq)

       # #Can just add some keys to the existing dictionary!
       # inlined_inst_map = {}
       # for block in angr_blocks:
       #     num_inst = len(block.disassembly.insns)
       #     inlined_inst_map[block] = prob_seq[0:num_inst]
       #     prob_seq = [num_inst]

       # output[match] = inlined_inst_map

    #Formatter().format(binary_path, output)
    print('Done')
        



