def train_one_epoch(model, train_loader, loss_fn, optimizer, device):
  avg_loss = 0
  num_batches = len(train_loader)
  for data in iter(train_loader):
    # Define input and target
    input, target = data
    input = input.to(device)

    # Predict
    # Output is given as a packed sequence
    output = model.variable_batch_forward(input)

    # Compute the loss and its gradients
    loss = loss_fn(output, target)
    loss.backward()

    # update learning weights
    optimizer.step()

    # Zero the gradient, to avoid it stacking through epochs
    optimizer.zero_grad()

    #Add loss
    avg_loss += loss.item()

  avg_loss /= num_batches
  return avg_loss

