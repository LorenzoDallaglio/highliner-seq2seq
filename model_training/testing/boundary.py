import numpy as np
from testing.instruction_classifier import binary_pred

def get_initial_nodes(sample):
  blocks = sample['blocks']
  if len(blocks) == 1:
    size = len(blocks[0]['instructions'])
    return[(0, size)]
  else:
    slices = []
    start = 0
    for block in blocks:
      size = len(block['instructions'])
      if block['node_type'] == 'Initial':
        slices.append((start, start+size))
      start += size
    return slices


def get_final_nodes(sample):
  blocks = sample['blocks']
  if len(blocks) == 1:
    size = len(blocks[0]['instructions'])
    return[(0, size)]
  else:
    slices = []
    start = 0
    for block in blocks:
      size = len(block['instructions'])
      if block['node_type'] == 'Final':
        slices.append((start, start+size))
      start += size
    return slices


def eval_initial_boundary(true, pred):
  inlined_idx = np.nonzero(true)[0]
  predicted_idx = np.nonzero(pred)[0]
  if predicted_idx.size > 0:
    return(inlined_idx[0], predicted_idx[0])
  else:
    return(inlined_idx[0], -1)


def eval_final_boundary(true, pred):
  inlined_idx = np.nonzero(true)[0]
  predicted_idx = np.nonzero(pred)[0]
  if predicted_idx.size > 0:
    return(inlined_idx[-1], predicted_idx[-1])
  else:
    return(inlined_idx[-1], -1)


def get_boundary_comparison(sample, threshold):
  initial_boundaries, final_boundaries = [], []
  true = sample['true']
  pred = binary_pred(sample, threshold)

  for block_start, block_end in get_initial_nodes(sample):
    block_true, block_pred = true[block_start:block_end], pred[block_start:block_end]
    initial_boundaries.append(eval_initial_boundary(block_true, block_pred))
  init_correct_pred = False not in [true_bound == pred_bound for true_bound, pred_bound in initial_boundaries]

  for block_start, block_end in get_final_nodes(sample):
    block_true, block_pred = true[block_start:block_end], pred[block_start:block_end]
    final_boundaries.append(eval_final_boundary(block_true, block_pred))
  final_correct_pred = False not in[true_bound == pred_bound for true_bound, pred_bound in final_boundaries]

  return init_correct_pred, final_correct_pred


def get_bulk_boundary_comparison(sample_set, threshold):
  initial_boundaries, final_boundaries = [], []
  for sample in sample_set:
    init_correct_pred, final_correct_pred = get_boundary_comparison(sample, threshold)
    initial_boundaries.append(init_correct_pred)
    final_boundaries.append(final_correct_pred)

  return initial_boundaries, final_boundaries
