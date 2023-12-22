from json import load

from angr_utils.block_utils import index_blocks, get_instructions
from models.frontend import EncoderDecoder
from output_format.format import format_match

#Input options: base or don't, hex or num, print or not, store or not
if __name__ == "__main__":
    ##Import bino's output
    results_path = 'test_out.json'
    with open(results_path, 'r') as results:
        bino_output = load(results)

    ##Open angr's project
    binary_path = bino_output['binary_path']
    block_index = index_blocks(binary_path, rebase=True)

    ##Initialize model
    highliner = EncoderDecoder(window_len = 256)

    for match in bino_output['matches']:
        ##Extract instructions of each match using angr disassembler
        matched_blocks = match['blocks']
        match_instructions = []
        for block in matched_blocks:
            angr_block = block_index[block['address']]
            block_instr = get_instructions(angr_block)
            block['instructions'] = block_instr
            match_instructions += block_instr
            
        #Predict on instructions
        inline_predictions = highliner.predict(match_instructions)

        #Zip predicted inlining probability to each instruction
        for block in matched_blocks:
            num_inst = len(block['instructions'])
            block_predictions = inline_predictions[:num_inst]
            inline_predictions = inline_predictions[num_inst:]
            block['instructions'] = list(zip(block['instructions'], block_predictions))
        break

    #Formatter().format(binary_path, output)
    print('Done')
        



