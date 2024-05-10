import torch
import os
from json import load
from tqdm import tqdm

from palmtree.vocab import WordVocab
from palmtree.parsing import parse_instruction
from data.utils import get_instructions, get_inline_flags
from models.architecture import LSTMDecoder
from config import *
from train_model import tokenize, load_encoder

#test module is already existing in python - had to make it testing
from testing.roc import estimate_threshold
from testing.instruction_classifier import make_confusion_matrix
from testing.cross_report import method_opt_cross_report
from testing.length import length_report


def static_predict (seqs, encoder, vocab, model):
    res = [] 
    for seq in tqdm(seqs):
        with torch.no_grad():
            token_seq, segment_label = tokenize(get_instructions(seq), vocab)
            word_embedding = prediction = encoder.forward(token_seq, segment_label)
            embedding = torch.mean(word_embedding.detach(), dim=1)
            target = torch.LongTensor([1 if flag else 0 for flag in get_inline_flags(seq)])

            pred = model(embedding)

        seq['true'] = target.cpu().numpy()
        seq['pred'] = pred.cpu().numpy()
        res.append(seq)
    return res


def run_full_testing(model_name):
    device = 'cuda:0' if torch.cuda.is_available() else 'cpu'
    print("Currently using: " + device) 

    with open(DATA_PATH + "test.json", "rb") as test_file:
      test_seqs = load(test_file)

    asm_vocab, palmtree = load_encoder(device)
    model = torch.load("models/saved_models/{}.pt".format(model_name))
    model.eval()
    test_seqs = static_predict(test_seqs, palmtree, asm_vocab, model)
    
    report_dir = "testing/reports/" + model_name
    if not os.path.exists(report_dir):
        os.mkdir(report_dir)
    threshold = estimate_threshold(test_seqs, report_dir)
    make_confusion_matrix(test_seqs, threshold, report_dir)
    method_opt_cross_report(test_seqs, threshold, report_dir)
    length_report(test_seqs, 60, threshold, report_dir)
     

if __name__ == '__main__':
    run_full_testing('test_model')






