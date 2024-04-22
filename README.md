# Highliner plugin for BINO

## Installation:
To install required libraries:
`pip install -r requirements`


## Inline instruction identification
`usage: highliner.py [-h] [-o OUTPUT_FILE] [-b BINARY_PATH] [-nogpu] [-t THRESHOLD] input_file`

input file is expected to be the JSON file produced by Bino by running it with the `-o [OUTPUT_FILE]` option

Optional parameters:
 * -o: output file to dump the results in as json. 
 * -b: binary file path which Bino analyzed (default: get from Bino output)
 * -t: threshold to distinguish between positive and negative class. Should be between 0 and 1. (default: optimal testing threshold)
 * -nogpu: disables GPU usage

Same binary test sample as BINO available in data/test_binaries/generic_binaries/, to have the tool still work with default options

Output file will be the same input dictionary with matches extended to include instructions and predicted probability of them being inline


## Dataset
Dataset the model was trained on is the same as BINO.
Can be downloaded at: https://mega.nz/file/eW5yhIJI#vsIjOz7_MNegW728R4KtN_KuZT2uJ18vWHo0_qTE0CI


## Computation time
Running highliner on BINO test binary (~17000 matched sequences) yields the following results:
* On GPU: 357s or 5m 57s, ~21 ms per match
* On CPU: 2730s or 45m 30s, ~160 ms per match
Execution on GPU is ~7.5 times faster than on CPU
