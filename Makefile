#!/bin/bash

PROJDIRS=$(wildcard projects/*/.)

.PHONY: compile $(PROJDIRS)

compile: $(PROJDIRS)
$(PROJDIRS):
	$(MAKE) -C $@ CXXFLAGS='$(CXXFLAGS)' OPT_FLAGS='$(OPT_FLAGS)'

