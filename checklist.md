# CHECKLIST

## STEP 1: Compiling all projects
- [V] Download the projects dataset 
- [V] Choose folder/naming convention
- [V] Create makefile to bulk compile the projects using each project own makefile
- [V] Extract and isolate executable binaries

## STEP 2: Extract inlined snippets
- [V] Locate inlining in each binary (implement tool to)
- [V] List methods names to extract
- [V]  Filter inlining instances by method name
- [V] Extract basic blocks and addresses for each instance (implement tool to)
- [V] Extract asm snippets for each instance (implement tool to)

## STEP 3: generalize to multiple projects
- [V] Choose folder/naming convention for snippets
- [V] Create appropriate folders

Questions:
- Why are Dwarf ranges so weird?:
	- entry\_pc does not correspond with low\_pc
	- Some ranges start with one byte as starting address, other have simply multiple instances with no starting address
	- Some ranges are only the starting address
	- Some ranges include zero-byte intervals
	- Some ranges are below entry block
- Possible errors in the dataset:
	- Output binary has weird extension such as .o -> isn't correctly extracted
	- Optimization flags of projects are specified in neither OPT\_FLAGS or CXX\_FLAGS, but after both

