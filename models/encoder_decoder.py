import torch
from models.config import *
from models.palmtree.vocab import WordVocab
from models.highliner.decoder import BiLSTMPredictor

class EncoderDecoder:
    def __init__ (self, device):
        self.vocab =  WordVocab.load_vocab(VOCAB_PATH)
        self.encoder = torch.load(TRANSFORMER_PATH)
        self.encoder.eval()
        #BUG: model should be imported on CPU by default
        self.decoder = torch.load(DECODER_PATH, map_location=device)
        self.decoder.eval()
        self.device = device


    def encode(self, text, numpy=False):
        sequence = [self.vocab.to_seq(inst, seq_len=20, with_eos=True, with_sos=True) for inst in text]
        segment_label = [[1 if idx != 0 else 0 for idx in seq] for seq in sequence]

        sequence = torch.tensor(sequence, dtype=torch.long, device=self.device)
        segment_label = torch.tensor(segment_label, dtype=torch.long, device=self.device)

        self.encoder.to(self.device)
        encoded = self.encoder.forward(sequence, segment_label)
        embedding = torch.mean(encoded.detach(), dim=1)
        del encoded

        if numpy:
            return embedding.data.cpu().numpy
        else:
            return embedding


    def decode(self, embedding, window_len):
        #Model was trained with maximum length
        #Sequences longer than max length are split, predicted individually and merged back
        sliced_input = [embedding[i: i + window_len] for i in range(0, len(embedding), window_len)]
        sliced_pred = [self.decoder.forward(seq) for seq in sliced_input]
        prediction = torch.cat(sliced_pred)
        return prediction


    def predict(self, text):
        embedding = self.encode(text)
        output = self.decode(embedding, WINDOW_LEN)
        prediction = torch.flatten(output)
        return prediction.tolist()
