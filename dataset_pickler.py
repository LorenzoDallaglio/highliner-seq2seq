from os import listdir
from os.path import join
from pickle import dump, load
from modules.config import OPT_LEVELS, SNIPPETS_DIR, INLINE_TOKEN, METHODS
from modules.tokenizer import tokenize

class snippet:
    def __init__ (self, name, opt, input_seq, target_seq):
        self.name = name
        self.opt = opt
        self.input_seq = input_seq[:]
        self.target_seq = target_seq[:]

def parse_files():
    snippet_list = []
    for project in listdir(SNIPPETS_DIR):
        for opt in OPT_LEVELS:
            asm_dir = join(SNIPPETS_DIR, project, opt)
            try:
                for snippet_name in listdir(asm_dir):
                    with open(join(asm_dir, snippet_name), "r") as seq_file:
                        asm = seq_file.readlines()[4:] #Current file header
                        target_seq = [(INLINE_TOKEN in inst) for inst in asm]
                        input_seq = tokenize(asm, INLINE_TOKEN)
                    snippet_list.append(snippet(snippet_name, opt, input_seq, target_seq))
            except FileNotFoundError:
                pass
    return snippet_list

if __name__ == "__main__":
    snippet_list = parse_files()
    with open("data/pickled_data.pickle", "wb") as pickle_file:
        dump(snippet_list, pickle_file)
        

