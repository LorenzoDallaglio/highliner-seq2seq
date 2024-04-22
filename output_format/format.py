def _format_instruction(instruction, threshold):
    inst, pred = instruction
    inst_str = '- {}'.format(inst)
    if pred > threshold:
        inst_str = inst_str.ljust(50)
        inst_str += ' <--- {:0.2%} INLINED\n'.format(pred)
    else:
        inst_str += '\n'
    return inst_str


def _format_block(block, threshold):
    block_str = '- 0x{:02x}: {}\n'.format(block['address'], block['type'])
    for inst in block['instructions']:
        block_str += '\t' + _format_instruction(inst, threshold) 
    return block_str


def format_match(match, threshold):
    method_name =  match['path_name'] + match['function_name']
    match_str = 'Function recognized: {}\n'.format(method_name)
    match_str += 'Similarity: {:0.6f}\n'.format(match['similarity'])

    match_str += 'Blocks_matched:\n'
    for block in match['blocks']:
        for line in _format_block(block, threshold).split('\n')[:-1]:
            match_str += '\t' + line  + '\n'
    
    return match_str



                
            
            

