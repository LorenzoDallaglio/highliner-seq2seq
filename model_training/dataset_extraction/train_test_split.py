from config.vars import METHODS, TEST_PERC, VAL_PERC
from json import load, dump

def flatten_to_seq(dataset):
    sequence_dataset = []
    for matched_binary in dataset:
        for matched_instance in matched_binary['matches']:
            if matched_instance['blocks']:
                sequence = {
                            'binary': matched_binary['binary'],
                            'opt': matched_binary['optimization'],
                            'method': matched_instance['method'],
                            'blocks': matched_instance['blocks']
                            }
                sequence_dataset.append(sequence)

    return sequence_dataset


def percentage_split(dataset, percentage):
    split_size = round(len(dataset) * (1-percentage) - 0.5)
    return dataset[:split_size], dataset[split_size:]

def split_by_methods(sequence_list, test_perc, val_perc):
	methods_dict = {method : [] for method in METHODS}
	for seq in sequence_list:
		method = seq['method']
		methods_dict[method].append(seq)

	train, val, test = [], [], []
	for key in methods_dict:
		method_train, method_test = percentage_split(methods_dict[key], test_perc)
		method_train, method_val = percentage_split(method_train, val_perc)
		train += method_train
		val += method_val
		test += method_test
	return train, val, test


if __name__== '__main__':
    with open("data/output.json", "rb") as extracted_data:
         dataset = load(extracted_data)

    sequences = flatten_to_seq(dataset)
    train_seqs, val_seqs, test_seqs = split_by_methods(sequences, TEST_PERC, VAL_PERC)

    with open("data/train.json", 'w') as train_file:
        dump(train_seqs, train_file, indent=2)
    with open("data/val.json", 'w') as val_file:
        dump(val_seqs, val_file, indent=2)
    with open("data/test.json", 'w') as test_file:
        dump(test_seqs, test_file, indent=2)
