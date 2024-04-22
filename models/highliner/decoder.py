import torch

class BiLSTMPredictor(torch.nn.Module):
  def __init__(self, input_size, hidden_size, num_layers, dense_size, bi=False, dropout=0):
    super(BiLSTMPredictor, self).__init__()

    self.lstm = torch.nn.LSTM(input_size, hidden_size, num_layers=num_layers, batch_first = True, bidirectional=bi, dropout=dropout)
    self.dense = torch.nn.Linear(2*hidden_size, dense_size)
    self.dense_activation = torch.nn.LeakyReLU()
    self.dense_dropout = torch.nn.Dropout(p=dropout)
    self.linear = torch.nn.Linear(dense_size, 1)
    self.sigmoid = torch.nn.Sigmoid()

  def forward(self, x):
    x, state = self.lstm(x)
    x = self.dense(x)
    x = self.dense_activation(x)
    x = self.dense_dropout(x)
    x = self.linear(x)
    x = self.sigmoid(x)
    x = torch.flatten(x, start_dim=1)
    return x 

