#!/bin/bash

PROJECTS_DIR=./projects

.PHONY: compileall compile

compile:
	$(MAKE) -C $(PROJECTS_DIR)/test

#compileall: 
#	for dir in $(PROJECTS_DIR)/*/ ; do \
#		dir=${dir%*/} ; \
#		$(MAKE) -C $(dir) ; \
#	done

