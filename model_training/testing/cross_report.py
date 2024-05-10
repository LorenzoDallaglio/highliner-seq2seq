import pandas as pd
from testing.report import get_metrics_dict

def method_opt_cross_report(test_samples, threshold, report_dir, save=True):
    methods = list(set([sample['method'] for sample in test_samples]))
    print(methods)
    method_sorted_data = dict()
    for m in sorted(methods):
      m_samples = [sample for sample in test_samples if sample['method'] == m]
      opt_sorted_data = dict()
      for o in ['-O2', '-O3', '-Os']:
        m_o_samples = [sample for sample in m_samples if sample['opt'] == o]
        if m_o_samples:
          metrics_dict = get_metrics_dict(m_o_samples, threshold)
        else:
          pass
        opt_sorted_data[o] = metrics_dict
      metrics_dict = get_metrics_dict(m_samples, threshold)
      opt_sorted_data["Overall"] = metrics_dict
      opt_sorted_data = pd.DataFrame.from_dict(opt_sorted_data, orient="columns")
      method_sorted_data[m] = opt_sorted_data

    overall_opt_data = dict()
    for o in ['-O2', '-O3', '-Os']:
        o_samples = [sample for sample in test_samples if sample['opt'] == o]
        if o_samples:
          metrics_dict = get_metrics_dict(o_samples, threshold)
        else:
          pass
        overall_opt_data[o] = metrics_dict

    metrics_dict = get_metrics_dict(test_samples, threshold, )
    overall_opt_data["Overall"] = metrics_dict
    overall_opt_data = pd.DataFrame.from_dict(overall_opt_data, orient="columns")
    method_sorted_data["Overall"] = overall_opt_data

    overall_df = pd.concat(method_sorted_data)
    if save:
        overall_df.to_csv(report_dir + "/Method-Optimization cross table.csv")
    return overall_df
