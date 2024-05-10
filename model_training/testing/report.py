import numpy as np
from sklearn.metrics import classification_report, accuracy_score
from testing.boundary import get_bulk_boundary_comparison
from testing.instruction_classifier import binary_pred, get_seq_accuracy

def get_metrics_dict(samples, threshold, target_names=['0', '1']):
  metrics_dict = dict()
  bulk_true = np.concatenate([sample['true'] for sample in samples])
  bulk_pred = np.concatenate([binary_pred(sample, threshold) for sample in samples])
  class_report = classification_report(bulk_true, bulk_pred, labels = [0, 1], target_names = target_names, output_dict = True)
  metrics_dict['Negative precision'] = class_report[target_names[0]]['precision']
  metrics_dict['Negative recall'] = class_report[target_names[0]]['recall']
  metrics_dict['Negative F1'] = class_report[target_names[0]]['f1-score']
  metrics_dict['Negative support'] = class_report[target_names[0]]['support']
  metrics_dict['Positive precision'] = class_report[target_names[1]]['precision']
  metrics_dict['Positive recall'] = class_report[target_names[1]]['recall']
  metrics_dict['Positive F1'] = class_report[target_names[1]]['f1-score']
  metrics_dict['Positive support'] = class_report[target_names[1]]['support']
  metrics_dict['Instruction-grain accuracy'] = accuracy_score(bulk_true, bulk_pred)

  seq_accuracy = [get_seq_accuracy(sample, threshold) for sample in samples]
  avg_accuracy = sum(seq_accuracy)/len(seq_accuracy)
  metrics_dict['Sequence-grain accuracy'] = avg_accuracy
  metrics_dict['Sequence number'] = len(seq_accuracy)

  initial_boundaries_pred, final_boundaries_pred = get_bulk_boundary_comparison(samples, threshold)
  overall_boundaries_pred = [init_eval and final_eval for init_eval, final_eval in zip(initial_boundaries_pred, final_boundaries_pred)]

  metrics_dict['Initial boundary accuracy'] = initial_boundaries_pred.count(True)/len(samples)
  metrics_dict['Final boundary accuracy'] = final_boundaries_pred.count(True)/len(samples)
  metrics_dict['Overall boundary accuracy'] = overall_boundaries_pred.count(True)/len(samples)

  return metrics_dict
