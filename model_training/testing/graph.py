import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

def plot_roc(fpr, tpr, opt_index, auc, report_dir=None, save=True):
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot([0,1], [0,1], linestyle='--', label='No Skill')
    ax.plot(fpr, tpr, label='Model - AUC {:.4f}'.format(auc))
    ax.scatter(fpr[opt_index], tpr[opt_index], marker='o', color='black', label='Best')
    # axis labels
    ax.set_xlabel('False Positive Rate')
    ax.set_ylabel('True Positive Rate')
    ax.legend()
    # show the plot
    if save:
        plt.savefig(report_dir + "/roc.pdf")
    #plt.show()
    return

def plot_cm(cm, report_dir=None, save=True):
    fig, ax = plt.subplots(figsize=(10, 5))
    cm_labels = ["True Negative","False Positive","False Negative","True Positive"]
    cm_counts = [f"{value:g}" for value in cm.flatten()]
    cm_percs = [f"{value:.2%}" for value in cm.flatten()/np.sum(cm)]
    annotations = [f"{v1}\n{v2}\n{v3}" for v1, v2, v3 in zip(cm_labels, cm_counts, cm_percs)]
    annotations = np.asarray(annotations).reshape(2,2)
    sns.heatmap(cm, fmt='', annot=annotations, ax=ax, xticklabels=["Not Inlined", "Inlined"], yticklabels=["Not Inlined", "Inlined"], square=True, cbar=True) # Missing axis, labels on numbers
    ax.set_ylabel("Correct", fontsize=12)
    ax.set_xlabel("Predicted", fontsize=12)
    ax.set_title("Confusion matrix", fontsize = 15)
    if save:
        plt.savefig(report_dir + "/confusion_matrix.pdf")
    #plt.show()
    return


def plot_classifier_by_length(data, min_support, report_dir=None, save=True):
    positive_data = data.loc[data['Positive support'] >= min_support]
    fig, ax = plt.subplots(figsize=(15, 5))
    sns.lineplot(data=positive_data[['Positive precision', 'Positive recall', 'Positive F1', 'Instruction-grain accuracy']], markers=True, ax=ax)
    ax.set_xlabel("Sample length in blocks", fontsize=12)
    ax.set_title("Positive class statistics over length in blocks")
    ax.set_ylim(0.5 - 0.05, 1)
    if save:
        plt.savefig(report_dir + "/length_classifier_stats.pdf")
    #plt.show()
    return

def plot_boundary_by_length(data, report_dir=None, save=True):
    fig, ax = plt.subplots(figsize=(15, 5))
    sns.lineplot(data=df[boundary_metrics], markers=True, ax=ax)
    ax.set_xlabel("Sample length in blocks", fontsize=12)
    ax.set_title("Boundary prediction accuracy over length in blocks")
    if save:
        plt.savefig(report_dir + "/length_boundary_stats.pdf")
    #plt.show()
    return
