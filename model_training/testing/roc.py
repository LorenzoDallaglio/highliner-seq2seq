from sklearn.metrics import roc_curve, roc_auc_score
import numpy as np
from testing.graph import plot_roc

def get_optimal_threshold_index(tpr, fpr):
    tnr = 1 - fpr
    g_mean = np.sqrt(tnr*tpr)
    return np.argmax(g_mean)

def estimate_threshold(test_seqs, report_dir):
    bulk_true = np.concatenate([seq['true'] for seq in test_seqs])
    bulk_pred = np.concatenate([seq['pred'] for seq in test_seqs])
    fpr, tpr, potential_thresh = roc_curve(bulk_true, bulk_pred)
    opt_idx = get_optimal_threshold_index(tpr, fpr)
    threshold = potential_thresh[opt_idx]
    auc = roc_auc_score(bulk_true, bulk_pred)
    print('Optimal threshold is threshold {}: {}'.format(opt_idx, potential_thresh[opt_idx]))
    plot_roc(fpr, tpr, opt_idx, auc, report_dir)
    return threshold
