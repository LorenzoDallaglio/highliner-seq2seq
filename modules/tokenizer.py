import re

def tokenize(raw_list, inline_token):
    instruction_list = []
    header_regex = r"^ *[0-9a-f]*:"
    bytes_regex = r"^ +([0-9a-f]{2} )+ +" #currently useless
    operators_regex = r"([\[\]\+\-\*:])"
    long_address_regex = r"0x[0-9a-f]{5,}"
    trailing_chars_regex = r" *(#.+)*[\n\r]"
    for raw_instruction in raw_list:
        clean_instruction = re.sub(inline_token, '', raw_instruction)
        clean_instruction = re.sub(header_regex, '', clean_instruction)
        clean_instruction = re.sub(bytes_regex, '', clean_instruction)
        clean_instruction = re.sub(r",", ' ', clean_instruction)
        clean_instruction = re.sub(r" +", ' ', clean_instruction)
        clean_instruction = re.sub(operators_regex, ' \g<1> ', clean_instruction)
        clean_instruction = re.sub(long_address_regex, '[addr]', clean_instruction)
        clean_instruction = re.sub(trailing_chars_regex, '', clean_instruction)
        instruction_list.append(clean_instruction)
    return instruction_list
