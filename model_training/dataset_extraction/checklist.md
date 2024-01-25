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
- [V] Add class label as input to the model
	-> Opted to avoid it to avoid bias when working on unseen methods
- [V] Implement class weights to alleviate data bias
	- Didn't improve performance
- [V] Identify more precisely inlined instructions
- [V] Implement arbitrary length sequence input into the recognizer instead of sliding window + padding
	-> Longer sequences perform better
- [V] Try GRUs and mix with LSTM
	-> Didn't improve performance
- [V] Try bidirectional layers
- [V] Try  early stopping on other metrics (Negative accuracy. negative recall)
	-> Didn't improve performance

# TOOL DESIGN
- Parse command line input, with two options:
	- input from file or from hand?
	- output in text form or on terminal
- Get each inlined block with angr
- Feed ALL the tokenized instructions of the block into Palmtree
- Splice and manipulate sequence to feed into inliner, then recompose in order
- Keeping all block  and instruction-relevant information from angr
- For each instruction, print the probability of it being inlined and mark it someway if it is
- Print them 


NOTE: This file should be removed from history sooner or later.
https://stackoverflow.com/questions/3458685/how-can-i-completely-remove-a-file-from-a-git-repository
