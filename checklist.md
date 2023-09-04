# CHECKLIST

## STEP 1: Compiling all projects
- [V] Download the projects dataset 
- [V] Choose folder/naming convention
- [] Create makefile to bulk compile the projects using each project own makefile

## STEP 2: Extract inlined snippets
- [V] Locate inlining in each binary (implement tool to)
- [V] List methods names to extract
- []  Filter inlining instances by method name
- [V] Extract basic blocks and addresses for each instance (implement tool to)
- [V] Extract asm snippets for each instance (implement tool to)

## STEP 3: generalize to multiple projects
- [V] Choose folder/naming convention for snippets
- [V] Create appropriate folders

- Is the main of the parser actually used?
- What's the difference between entry\_pc and range starting point? Why do some rangelists start and end withy do some rangelists start and end with the same byte? 

Questions:
- Existing method/library to demangle names?
- Possible building solutions for dataset?
