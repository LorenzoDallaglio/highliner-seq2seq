import json, pickle
from snippet_creation.Snippet import Snippet

with open('output.json', 'r') as new:
    new_output = json.load(new)

with open('data/pickled_data.pickle', 'rb') as old:
    old_output = pickle.load(old)

rshell_snippets = [snippet for snippet in old_output if 'rshell' in snippet.binary]

for snippet in rshell_snippets:
    print(snippet.opt)
    print(snippet.method)
    print(snippet.blocksize)
    print(snippet.addr)
    print('\n'.join(snippet.instructions))
    target_seq = [str(flag) for flag in snippet.target_seq]
    print('\n'.join(target_seq))
    print('\n')

