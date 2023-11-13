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

## REDESIGNING:
- [V] Use directly angr instead of pwntools
- [V] Add possibility to choose whether to save snippets to file or not
- [V] Add pickling directly to extraction procedure
- [V] Remove the input-target division
- [V] Test new speed and possibly remove checkpointing of execution
- [V] Factor different modules: 1) DWARF parser, 2) Asm extractor 3) Storage

#MODEL DESISIGN
## POSSIBILE IMPROVEMENTS
- [ ] Add class label as input to the model
	-> maybe also output?
- [ ] Implement input class weights to alleviate bias
- [V] Identify more precisely inlined instructions
- [ ] Implement arbitrary length sequence input into the recognizer instead of sliding window + padding
- [ ] Filter out methods which are too small from the dataset
- [V] Try bidirectional LSTMs and GRUs

# TOOL DESIGN
- TBD after meeting with BINO author


NOTE: This file should be removed from history sooner or later.
https://stackoverflow.com/questions/3458685/how-can-i-completely-remove-a-file-from-a-git-repository
