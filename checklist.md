# CHECKLIST

## STEP 1: Compiling all projects
- [V] Download the projects dataset 
- [V] Choose folder/naming convention
- [] Create makefile to bulk compile the projects

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

