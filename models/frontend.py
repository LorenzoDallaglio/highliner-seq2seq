from models.config import *
import models.palmtree.eval_utils as encoder_utils
import models.highliner.decoder as decoder_utils
import re

#NOTE: add parameter to choose if GPU is available or not
class EncoderDecoder:
    def __init__ (self, window_len):
        self.encoder = encoder_utils.UsableTransformer(model_path=TRANSFORMER_PATH, vocab_path=VOCAB_PATH)
        self.decoder = decoder_utils.Decoder(DECODER_PATH, window_len)

    #NOTE: currently unchanged from tokenize module
    def _preprocess_input(self, raw_list):
        instruction_list = []
        header_regex = r"^0x[0-9a-f]*:"
        bytes_regex = r"^ +([0-9a-f]{2} )+ +"
        operators_regex = r"([\[\]\+\-\*:])"
        long_address_regex = r"0x[0-9a-f]{5,}"
        trailing_chars_regex = r" *(#.+)*[\n\r]"
        for raw_instruction in raw_list:
            clean_instruction = re.sub(header_regex, '', raw_instruction)
            clean_instruction = re.sub(bytes_regex, '', clean_instruction)
            clean_instruction = re.sub(r",", ' ', clean_instruction)
            clean_instruction = re.sub(r" +", ' ', clean_instruction)
            clean_instruction = re.sub(operators_regex, ' \g<1> ', clean_instruction)
            clean_instruction = re.sub(long_address_regex, '[addr]', clean_instruction)
            clean_instruction = re.sub(trailing_chars_regex, '', clean_instruction)
            instruction_list.append(clean_instruction)
        return instruction_list

    def predict(self, inst_seq):
        inst_seq = self._preprocess_input(inst_seq)
        embedded_seq = self.encoder.encode(inst_seq)
        pred = self.decoder.decode(embedded_seq)
        return pred.tolist()


