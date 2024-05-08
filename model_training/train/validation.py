import torch
from torcheval.metrics import BinaryConfusionMatrix
from torch.nn.utils.rnn import unpack_sequence

def validation_report(bcm):
  values = bcm.compute()

  tn = values[0, 0]
  fp = values[0, 1]
  fn = values[1, 0]
  tp = values[1, 1]

  ##Negative class statistics:
  report = "Non-inlined class statistics:\n"
  report += "Non-inlined precision: {}\n".format(tn/(tn+fp))
  report += "Non-inlined recall: {}\n\n".format(tn/(tn+fn))
  report += "Inlined class statistics:\n"
  report += "Inlined precision: {:4f}\n".format(tp/(fn+tp))
  report += "Inlined recall: {:4f}\n".format(tn/(tn+fn))
  return report


def validate(model, val_loader, loss_fn, metric, device):
    avg_loss = 0
    num_batches = len(val_loader)
    for data in iter(val_loader):
        # Define input and target
        input, target = data
        input = input.to(device)
        # Predict
        output = model.variable_batch_forward(input)

        # Compute the loss
        loss = loss_fn(output, target)

        #Add loss
        avg_loss += loss.item()

        # Estimate metrics
        flat_output = torch.cat(unpack_sequence(output))
        flat_target = torch.cat(target).to(torch.long)
        metric.update(flat_output, flat_target)

    avg_loss /= num_batches
    return avg_loss
