# CHECKLIST

# GROUND TRUTH EXTRACTION
## STEP 1: Compiling all projects
- [V] Download the projects dataset 
- [V] Choose folder/naming convention
- [V] Create makefile to bulk compile the projects using each project own makefile
- [V] Extract and isolate executable binaries

## STEP 2: Extract inlined snippets
- [V] Locate inlining in each binary (implement tool to)
- [V] List methods names to extract
- [V] Filter inlining instances by method name
- [V] Extract basic blocks and addresses for each instance (implement tool to)
- [V] Extract asm snippets for each instance (implement tool to)

## STEP 3: generalize to multiple projects
- [V] Choose folder/naming convention for snippets
- [V] Create appropriate folders

## REDESEING:
- [V] Use directly angr instead of pwntools
- [V] Add possibility to choose whether to save snippets to file or not
- [] Add pickling directly to extraction procedure
- [V] Remove the input-target division
- [] Test new speed and possibly remove checkpointing of execution
- [] Factor different modules: 1) DWARF parser, 2) Asm extractor 3) Storage

#MODEL DESISIGN
## POSSIBILE IMPROVEMENTS
- [ ] Add class label as input to the model
- [ ] Implement input class weights to alleviate bias
- [ ] Identify more precisely inlined instructions
- [ ] Implement arbitrary length sequence input into the recognizer instead of sliding window + padding
- [ ] Filter out methods which are too small from the dataset
- [ ] Try bidirectional LSTMs and GRUs

# TOOL DESIGN
- TBD after meeting with BINO author


Report:
- Wrote appropriate preprocessing of data (target encoding, sequence splitting, padding). 
	- Arbitrary length input is currently handled by a sliding window
- Designed, trained and tested first model
	- Have no benchmark, but results seem very good: 97% Precision, Recall with sliding window 20
	- Decided to stop for a moment (also because Colab took away my GPU)
	- Maybe meeting to discuss results and possible improvements?
- Started reworking the whole pipeline
	- Started using angr codeblocks to get disassembly instead of pwntools:
		- Fixes some bugs
		- More precise identification of inlined instructions
	- Solved bug which caused some methods not to be found: missed a comma, apparently
	- Keep more information about each snippet, e.g. which inlined method, which opt
- Next week: 
	- Rerun data analysis
	- Will implement more varied testing (e.g. by class, by optimization)
	- Implement result interpretability


NOTE: This file should be removed from history sooner or later.
https://stackoverflow.com/questions/3458685/how-can-i-completely-remove-a-file-from-a-git-repository
