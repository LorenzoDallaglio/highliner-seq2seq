# CHECKLIST

## STEP 1: Compiling all projects
- [V] Download the projects dataset 
- [V] Choose folder/naming convention
- [~] Create makefile to bulk compile the projects

## STEP 2: Extract inlined snippets
- [V] Locate inlining in each binary (implement tool to)
- [] List methods names to extract
- [] Extract basic blocks and addresses for each instance (implement tool to)
- [] Extract asm snippets for each instance (implement tool to)
- [] Choose folder/naming convention for snippets

## STEP 3: Patch binaries
- [] Download standard library sourcecode
- [] Compile library sourcecode to force methods not to inline (implement tool to)
- [] Patch each binary with respective library (implement tool to)

## STEP 4: Extract uninlined snippets
- [] Locate each snippet (same tool as before?)
- [] Extract basic block
- [] Extract asm snippets (Same tool)


To be discussed:
- Which blocks to extract for each inlined call in the CFG? Current implementation: from starting position, check if all ranges are covered. Blocks can be discarded or taken into consideration, and ranges are shrunk accordingly
	- But what's the meaning of the address listed in ranges? Is it relative to base?
	- Does the DW_AT_entry_pc represent the enter block? If so, why do some low addresses clash with it?
- How to relate an inlined call site to a non-inlined call site?
- How to use makefiles. Just, in general.
- How are names mangled?
- Non-contiguous mean in different BBs, right?
- Is the main of the parser actually used?
- At which point should the patched library be linked? Are optimizations applied after loading libraries?
