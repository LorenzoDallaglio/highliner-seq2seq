import numpy as np
import pandas as pd
from testing.report import get_metrics_dict
from testing.graph import plot_classifier_by_length, plot_boundary_by_length

def length_report(test_samples, max_block_size, threshold, report_dir, save=True):
    target_names = ['Not inlined', 'Inlined']
    size_metrics_map = {}
    for n in range(1, max_block_size):
      metrics_dict = dict()
      n_sized_samples = [sample for sample in test_samples if (len(sample['blocks']) == n)]
      if n_sized_samples:
        metrics_dict = get_metrics_dict(n_sized_samples, threshold, target_names)
        size_metrics_map[n] = metrics_dict
      else:
        pass
    
    overall_df = pd.DataFrame.from_dict(size_metrics_map, orient='index')
    if save:
        overall_df.to_csv(report_dir + "/Length related stats table.csv")

    plot_classifier_by_length(overall_df, 10, report_dir)
    return overall_df

