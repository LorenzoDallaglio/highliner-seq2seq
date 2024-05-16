import torch
from torch import nn
from torch.utils.data import DataLoader
from torcheval.metrics import BinaryConfusionMatrix
from json import load
from tqdm import tqdm

from palmtree.vocab import WordVocab
from palmtree.parsing import parse_instruction
from data.utils import get_instructions, get_inline_flags
from data.dataset import VariableLengthDataset, pack_collate
from models.architecture import LSTMDecoder
from models.params import *
from config import *
from train.training import train_one_epoch
from train.validation import validate, validation_report
from train.params import *


def load_encoder(device):
    vocab = WordVocab.load_vocab("./palmtree/vocab")
    encoder = torch.load("./palmtree/transformer.ep19")
    encoder.eval()
    encoder = encoder.to(device)
    return vocab, encoder


def tokenize(sequence, vocab):
    sequence = [parse_instruction(instruction, {}, {}) for instruction in sequence]
    token_seq = [vocab.to_seq(inst, seq_len=20, with_eos=True, with_sos=True) for inst in sequence]
    segment_label = [[1 if idx != 0 else 0 for idx in seq] for seq in token_seq]
    token_seq = torch.LongTensor(token_seq)
    segment_label = torch.LongTensor(segment_label)
    return token_seq, segment_label


# Use the encoder as-is, for pretraining without fine tuning
def static_embed(seqs, encoder, vocab, device):
    embedded_seqs, target_seqs = [], []
    for seq in tqdm(seqs):
        with torch.no_grad():
            token_seq, segment_label = tokenize(get_instructions(seq), vocab)
            token_seq = token_seq.to(device)
            segment_label = segment_label.to(device) 
            word_embedding = encoder.forward(token_seq, segment_label)
            embedding = torch.mean(word_embedding.detach(), dim=1)
            target = torch.LongTensor([1 if flag else 0 for flag in get_inline_flags(seq)]).to(device)

            embedded_seqs.append(embedding)
            target_seqs.append(target)

    return embedded_seqs, target_seqs


def train(model, model_name, train_loader, val_loader, loss_fn, optimizer, scheduler, epochs, device):
    train_history, val_history = [], []
    count = 0
    best_loss = 1000

    for i in range(1, epochs):
        print("EPOCH {}".format(i))

        #train the model
        model.train(True)
        train_loss = train_one_epoch(model, train_loader, loss_fn, optimizer, device)
        train_history.append(train_loss)

        #validate the model
        with torch.no_grad():
            model.eval()
            metric = BinaryConfusionMatrix(device=device)
            val_loss = validate(model, val_loader, loss_fn, metric, device)
            val_history.append(val_loss)

        #Print report
        report = "Training loss: {:4f}\n".format(train_loss)
        report += "Validation loss: {:4f}\n".format(val_loss)
        report += validation_report(metric)
        print(report)

        # Callbacks
        # Reduce LR on plateau
        scheduler.step(val_loss)

        # Early stopping
        if val_loss < best_loss:
          best_loss = val_loss
          count = 0
          #Checkpointing
          torch.save(model, "models/saved_models/{}.pt".format(model_name))
        else:
            count += 1

        if count >= EARLYSTOPTHRESH:
          break

    return train_loss, best_loss


if __name__ == "__main__":
    device = 'cuda:0' if torch.cuda.is_available() else 'cpu'
    print("Currently using: " + device) 

    asm_vocab, palmtree = load_encoder(device)

    with open(DATA_PATH + "train.json", "rb") as train_file:
      train_seqs = load(train_file)
    with open(DATA_PATH + "val.json", "rb") as val_file:
      val_seqs = load(val_file)

    input_train, target_train = static_embed(train_seqs[:100], palmtree, asm_vocab, device)
    input_val, target_val = static_embed(val_seqs[:100], palmtree, asm_vocab, device)

    batch_size = 256
    train_data = VariableLengthDataset(input_train, target_train)
    train_loader = DataLoader(train_data, batch_size=batch_size, shuffle=True, collate_fn = pack_collate)
    val_data = VariableLengthDataset(input_val, target_val)
    val_loader = DataLoader(val_data, batch_size=batch_size, collate_fn = pack_collate)

    print('Training set has {} instances'.format(len(train_loader)))
    print('Validation set has {} instances'.format(len(val_loader)))

    model = LSTMDecoder(INPUT_SIZE, HIDDEN_SIZE, NUM_LAYERS, DENSE_SIZE, True, DROPOUT).to(device)
    loss_fn = batched_loss
    optimizer = torch.optim.Adam(model.parameters(), lr=LR)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, factor=LR_FACTOR, patience=PATIENCE, cooldown=COOLDOWN, verbose=True)

    model_name = "test_model"
    train(model, model_name, train_loader, val_loader, loss_fn, optimizer, scheduler, EPOCH, device)
    model = torch.load("models/saved_models/{}.pt".format(model_name))
    model.eval()
