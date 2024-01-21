import re

#Note: this parser assumes instructions to be formatted as angr.Block.pprint() does
def parse_instruction(inst, symbol_map=None, string_map=None):
    # Strip instruction address:
    inst = re.sub('^0x[0-9a-f]*: ', '', inst)

    # Normalize word separators to commas, and then split around them
    inst = re.sub('\s+', ', ', inst, 1)
    parts = inst.split(', ')
    operand = []
    token_lst = []

    # Separate operands and mnemonic
    if len(parts) > 1:
        operand = parts[1:]
    token_lst.append(parts[0])

    # Normalize each operand
    for i in range(len(operand)):
        # Isolate symbols
        symbols = re.split('([0-9A-Za-z]+)', operand[i])
        symbols = [s.strip() for s in symbols if s]
        processed = []

        # Handle numbers by converting them into symbols, string and address
        for j in range(len(symbols)):

            # Design choice of Palmtree: 
            # hex numbers with more that 6 digits and less than 15 will be replaced by special tokens
            # the others are constant numbers and will not be normalized, but stay as tokens
            if symbols[j][:2] == '0x' and len(symbols[j]) > 6 and len(symbols[j]) < 15:
                if symbol_map and int(symbols[j], 16) in symbol_map:
                    processed.append("symbol")
                elif string_map and int(symbols[j], 16) in string_map:
                    processed.append("string")
                else:
                    processed.append("address")
            else:
                processed.append(symbols[j])
            processed = [p for p in processed if p]

        token_lst.extend(processed)

    # the output will be like "mov eax [ rax + 0x1 ]"
    return ' '.join(token_lst)

def parse_instruction_list(inst_list, symbol_map=None, string_map=None):
    return [parse_instruction(inst, symbol_map, string_map) for inst in inst_list]
