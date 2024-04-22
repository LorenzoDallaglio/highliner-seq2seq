import json, pickle
from snippet_creation.Snippet import Snippet
from tqdm import tqdm

def get_instructions(match):
    inst = []
    for block in match['blocks']:
        inst.extend(block['instructions'])
    return inst

def get_match_flags(match):
    flags = []
    for block in match['blocks']:
        flags.extend(block['inline_flags'])
    return flags

def sort_snippets(snippet_list):
    binary_dict = {}
    opt_template = {'-O2': [], '-O3': [], '-Os': []}
    for snippet in snippet_list:
        if snippet.binary in binary_dict:
            binary_dict[snippet.binary][snippet.opt].append(snippet)
        else:
            binary_dict[snippet.binary] = opt_template.copy()
            binary_dict[snippet.binary][snippet.opt].append(snippet)

    return binary_dict

def is_equivalent(snippet, match):
    same_size = (snippet.blocksize == len(match['blocks']))
    same_inline = (snippet.target_seq == get_match_flags(match))
    return same_size and same_inline

with open('dataset_extraction/data/output.json', 'r') as new:
    new_output = json.load(new)

with open('dataset_extraction/data/pickled_data.pickle', 'rb') as old:
    old_output = pickle.load(old)

snippets = [snippet for snippet in old_output if snippet.opt != '-Ofast']

unique_snippets = set()
for snippet in snippets:
    unique_snippets.add(snippet.binary + snippet.opt + hex(snippet.addr) + str(snippet.input_seq))

all_matches = list()
for binary in new_output:
    all_matches.extend(binary['matches'])

for match in all_matches:
    if len(match['blocks']) <6 and len(match['blocks']) > 3:
        for block in match['blocks']:
            print(block['node_type'])
            print(hex(block['address']))
            print('\n'.join(block['instructions']))
            print(block['inline_flags'])
        breakpoint()

unique_matches = set()
for match in all_matches:
    unique_matches.add(str(match))

print(len(snippets))
print(len(list(unique_snippets)))
print(len(all_matches))
print(len(list(unique_matches)))

count = 0
for match in all_matches:
    node_types = [block['node_type'] for block in match['blocks']]
    if node_types.count('Initial') > 1:
        count +=1

print(count)
exit()


snippet_index = sort_snippets(snippets)

present, absent = 0, 0
empty = 0

log = open('sanity_log.txt', 'w')

for binary in tqdm(new_output):
    possible_snippets = snippet_index[binary['binary']][binary['optimization']]
    for match in binary['matches']:
        if not match['blocks']:
            empty += 1
            break

        for i in range(len(possible_snippets)):
            if is_equivalent(possible_snippets[i], match):
                snippet = possible_snippets.pop(i)
                print('Match for {}{}'.format(binary['binary'], binary['optimization'], file=log))
                for new, old in zip(get_instructions(match), snippet.input_seq):
                    print('{} -> {}'.format(old, new), file=log)
                print('', file=log)
                present += 1
                break
            else:
                starting_addr = match['blocks'][0]['address']
                if abs(starting_addr - snippet.addr) < 16:
                    print('Weird...', file=log)
                    print(possible_snippets[i].addr, file=log)
                    for new, old in zip(get_instructions(match), possible_snippets[i].input_seq):
                        print('{} -> {}'.format(old, new), file=log)
                    print('', file=log)

    print(present, absent, empty)

breakpoint()

