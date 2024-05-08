import torch
from torch.nn.utils.rnn import unpack_sequence

EPOCH = 100
LR = 1e-3
PATIENCE = 0
COOLDOWN = 5
LR_FACTOR = 0.1
EARLYSTOPTHRESH = 5

def batched_loss(inputs, target):
  inputs = unpack_sequence(inputs)
  inputs = torch.cat(inputs)
  target = torch.cat(target)
  target = target.to(torch.float32)
  loss = torch.nn.functional.binary_cross_entropy(inputs, target)
  return loss
