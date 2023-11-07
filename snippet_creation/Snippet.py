from os.path import join, basename

import re

class Snippet:
    def __init__ (self, binary, opt, method, addr = 0, instructions = []):
        self.binary = binary
        self.opt = opt
        self.method = method
        self.addr = addr
        self.instructions = instructions
        self.input_seq = []
        self.target_seq = []

    def _tokenize(self, raw_list, inline_token):
        instruction_list = []
        header_regex = r"^0x[0-9a-f]*:"
        bytes_regex = r"^ +([0-9a-f]{2} )+ +" #currently useless
        operators_regex = r"([\[\]\+\-\*:])"
        long_address_regex = r"0x[0-9a-f]{5,}"
        trailing_chars_regex = r" *(#.+)*[\n\r]"
        for raw_instruction in raw_list:
            clean_instruction = raw_instruction.replace(inline_token, '')
            clean_instruction = re.sub(header_regex, '', clean_instruction)
            clean_instruction = re.sub(bytes_regex, '', clean_instruction)
            clean_instruction = re.sub(r",", ' ', clean_instruction)
            clean_instruction = re.sub(r" +", ' ', clean_instruction)
            clean_instruction = re.sub(operators_regex, ' \g<1> ', clean_instruction)
            clean_instruction = re.sub(long_address_regex, '[addr]', clean_instruction)
            clean_instruction = re.sub(trailing_chars_regex, '', clean_instruction)
            instruction_list.append(clean_instruction)
        return instruction_list

    def load_code(self, ranges, blocks, inline_mark):
        inst_string = ''
        for block in blocks:
            for inst in block.disassembly.insns:
                inst_string += "{}:".format(hex(inst.address))
                inst_string += "{} {}".format(inst.mnemonic, inst.op_str)
                #NOTE: could be rewritten with iterators
                for rang in ranges:
                    if inst.address >= rang[0] and inst.address < rang[1]:
                        inst_string += inline_mark
                        break
                self.instructions.append(inst_string)

    def build_sequences(self, inline_mark):
        self.input_seq = self._tokenize(self.instructions, inline_mark)
        self.target_seq = [(inline_mark in inst) for inst in self.instructions]
        
    def to_file (self, snippets_dir):
        file_name = "{}###{}###{}###{}".format(self.binary, self.opt, self.method, hex(self.addr))
        with open(join(snippets_dir, file_name), 'w') as snippet_file:
            code = '\n'.join(self.instructions)
            snippet_file.write(code)
        return



    def from_file (file_path):
        file_name = basename(file_path)
        attributes = file_name.split('###')
        with open(join(snippets_dir, filename), 'r') as snippet_file:
            code = snippet_file.readlines()
        return snippet(attributes[0], attributes[1], attributes[2], attributes[3])






        

