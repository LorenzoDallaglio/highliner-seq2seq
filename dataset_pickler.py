from os import listdir
from os.path import join
from build_sort import recursive_ls
from pickle import dump, load
from modules.config import OPT_LEVELS, SNIPPETS_DIR, METHODS
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
            input_dir = join(SNIPPETS_DIR, project, opt, "input")
            target_dir = join(SNIPPETS_DIR, project, opt, "target")
            try:
                for snippet_name in listdir(input_dir):
                    with open(join(input_dir, snippet_name), "r") as input_file:
                        input_seq = tokenize(input_file.readlines())
                    with open(join(target_dir, snippet_name), "r") as target_file:
                        target_seq = tokenize(target_file.readlines())
                    snippet_list.append(snippet(snippet_name, opt, input_seq, target_seq))
            except FileNotFoundError:
                pass
    return snippet_list

if __name__ == "__main__":
    snippet_list = parse_files()
    with open("data/pickled_data.pickle", "wb") as pickle_file:
        dump(snippet_list, pickle_file)
        

