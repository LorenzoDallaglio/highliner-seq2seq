import torch
from torch.nn.utils.rnn import pack_padded_sequence, pad_packed_sequence

class LSTMDecoder(torch.nn.Module):

  def __init__(self, input_size, hidden_size, num_layers, dense_size, bi=False, dropout=0):
    super(LSTMDecoder, self).__init__()

    self.lstm = torch.nn.LSTM(input_size, hidden_size, num_layers=num_layers, batch_first = True, bidirectional=bi, dropout=dropout)
    self.dense = torch.nn.Linear(2*hidden_size, dense_size)
    self.dense_activation = torch.nn.LeakyReLU()
    self.dense_dropout = torch.nn.Dropout(p=dropout)
    self.linear = torch.nn.Linear(dense_size, 1)
    self.sigmoid = torch.nn.Sigmoid()


  def recurrent_forward(self, x):
    x, state = self.lstm(x)
    return x


  def linear_forward(self, x):
    x = self.dense(x)
    x = self.dense_activation(x)
    x = self.dense_dropout(x)
    x = self.linear(x)
    x = self.sigmoid(x)
    x = torch.flatten(x, start_dim=1)
    return x


  #expects a packed sequence as input, returns a packed sequence as output
  def variable_batch_forward(self, x):
    recurrent_x = self.recurrent_forward(x)

    padded_recurrent_x, lens = pad_packed_sequence(recurrent_x, batch_first=True)
    padded_linear_x = self.linear_forward(padded_recurrent_x)
    linear_x = pack_padded_sequence(padded_linear_x, lens, batch_first=True, enforce_sorted=False)

    return linear_x


  def forward(self, x):
    x = self.recurrent_forward(x)
    x = self.linear_forward(x)
    return x
