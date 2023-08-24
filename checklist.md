# CHECKLIST

## STEP 1: Compiling all projects
- [V] Download the projects dataset 
- [V] Choose folder/naming convention
- [] Create makefile to bulk compile the projects

## STEP 2: Extract inlined snippets
- [V] Locate inlining in each binary (implement tool to)
- [V] List methods names to extract
- [V] Extract basic blocks and addresses for each instance (implement tool to)
- [V] Extract asm snippets for each instance (implement tool to)
- [V] Choose folder/naming convention for snippets

## STEP 3: Patch binaries
- [V] Download standard library sourcecode -> already in /usr/include/c++
~~[] Compile library sourcecode to force methods not to inline (implement tool to)~~
~~[] Patch each binary with respective library (implement tool to)~~
	-> [] Relink GCC+ headers to custom ones  

## STEP 4: Extract uninlined snippets
- [] Locate each snippet (same tool as before?)
- [] Extract basic block
- [] Extract asm snippets (Same tool)

## STEP 5: generalize to multiple projects


To be discussed:
- Which blocks to extract for each inlined call in the CFG? Current implementation: from starting position, check if all ranges are covered. Blocks can be discarded or taken into consideration, and ranges are shrunk accordingly
- How to relate an inlined call site to a non-inlined call site?
- How to use makefiles. Just, in general.
- How are names mangled?
- Non-contiguous can mean in different BBs, right?
- Is the main of the parser actually used?
- At which point should the patched library be linked? Are optimizations applied after loading libraries? -> NO, one can just "fix" the imported headers. Or does it?
