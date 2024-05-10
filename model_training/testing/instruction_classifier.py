import numpy as np
from testing.graph import plot_cm
from sklearn.metrics import confusion_matrix

def binary_pred(sample, threshold):
  return np.where(sample['pred'] > threshold, 1, 0)

def count_misclassified(sample, threshold):
  return np.count_nonzero(sample['true'] != binary_pred(sample, threshold))

def get_seq_accuracy(sample, threshold):
  errors = count_misclassified(sample, threshold)
  return 1 - errors/len(sample['true'])


def make_confusion_matrix(test_samples, threshold, report_dir):
  bulk_true = np.concatenate([sample['true'] for sample in test_samples])
  bulk_pred = np.concatenate([binary_pred(sample, threshold) for sample in test_samples])
  cm = np.array(confusion_matrix(bulk_true, bulk_pred))
  plot_cm(cm, report_dir)


