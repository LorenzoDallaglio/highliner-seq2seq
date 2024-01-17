#!/usr/bin/python3

import argparse
from json import load, dump
from angr_utils.block_utils import index_blocks, get_instructions
from models.frontend import EncoderDecoder
from output_format.format import format_match


def parse_args(): 
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output',
                        dest='output_file',
                        help='path to a file to dump the results in as json. If not specified, output will be only printed to sdtout')
    parser.add_argument('-b', '--binary',
                        dest='binary_path',
                        help='path to Bino input binary. Required only to override path specified by Bino outpu in case of different working directories. If not specified, will be retrieved by Bino output')
    parser.add_argument(dest='input_file',
                        help='output file of Bino to extend')

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    output_file = args.output_file
    binary_path = args.binary_path
    input_file = args.input_file

    # Import bino's output as input
    with open(input_file, 'r') as results:
        bino_output = load(results)

    # Open binary with angr and index blocks to retrieve inlined blocks identified by Bino
    if not binary_path:
        binary_path = bino_output['binary_path']

    print('Binary: {}'.format(binary_path))
    block_index = index_blocks(binary_path, rebase=True)
    
    # Initialize model
    highliner = EncoderDecoder(window_len = 256)

    # Iterate on inlined instances matched by Bino
    for match in bino_output['matches'][:10]:
        matched_blocks = match['blocks']
        match_instructions = []

        # Extract instructions of each matched block using angr disassembler
        for block in matched_blocks:
            angr_block = block_index[block['address']]
            block_instr = get_instructions(angr_block)
            block['instructions'] = block_instr
            match_instructions += block_instr
            
        # Predict on instructions
        inline_predictions = highliner.predict(match_instructions)

        # Zip predicted inlining probability to each instruction
        for block in matched_blocks:
            num_inst = len(block['instructions'])
            block_predictions = inline_predictions[:num_inst]
            inline_predictions = inline_predictions[num_inst:]
            block['instructions'] = list(zip(block['instructions'], block_predictions))

        print(format_match(match))

    if output_file:
        with open(output_file, 'w') as output:
            dump(bino_output, output, indent=2)
