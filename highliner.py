#!/usr/bin/python3

import argparse
import torch
from json import load, dump
from angr_utils.blocks import index_blocks, get_instructions
from angr_utils.parsing import parse_instruction_list
from models.encoder_decoder import EncoderDecoder
#BUG: necessary import here
from models.highliner.decoder import BiLSTMPredictor
from output_format.format import format_match


def parse_args(): 
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output',
                        dest='output_file',
                        help='path to a file to dump the results in as json. If not specified, output will be only printed to sdtout')
    parser.add_argument('-b', '--binary',
                        dest='binary_path',
                        help='path to Bino input binary. Required only to override path specified by Bino output in case of different working directories. If not specified, will be retrieved by Bino output')
    parser.add_argument('-nogpu',
                        action = 'store_false',
                        dest='allow_gpu',
                        help='disables GPU usage. If not specified, programm will prioritize GPU over CPU')
    parser.add_argument('-t', '--threshold',
                        dest='threshold',
                        type=float,
                        help='sets threshold between 0 and 1 to set apart positive and negative class from model output. If not specified or invalid, optimal threshold will be used')
    parser.add_argument(dest='input_file',
                        help='output file of Bino to extend')

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    output_file = args.output_file
    binary_path = args.binary_path
    allow_gpu = args.allow_gpu
    threshold = args.threshold
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
    device = torch.device("cuda:0" if torch.cuda.is_available() and allow_gpu else "cpu")
    print("Prediction performed on {}\n".format(device))
    highliner = EncoderDecoder(device)

    # Iterate on inlined instances matched by Bino
    for match in bino_output['matches']:
        matched_blocks = match['blocks']
        match_instructions = []

        # Extract instructions of each matched block using angr disassembler
        # Input should be a list of strings
        for block in matched_blocks:
            angr_block = block_index[block['address']]
            block_instr = get_instructions(angr_block)
            block['instructions'] = block_instr
            match_instructions += block_instr
            
        # Predict on instructions
        parsed_instructions = parse_instruction_list(match_instructions)
        inline_predictions = highliner.predict(match_instructions)

        # Zip predicted inlining probability to each instruction
        for block in matched_blocks:
            num_inst = len(block['instructions'])
            block_predictions = inline_predictions[:num_inst]
            inline_predictions = inline_predictions[num_inst:]
            block['instructions'] = list(zip(block['instructions'], block_predictions))

        if not threshold or threshold < 0 or threshold > 1:
            threshold = 0.67
        print(format_match(match, threshold))

    if output_file:
        with open(output_file, 'w') as output:
            dump(bino_output, output, indent=2)
