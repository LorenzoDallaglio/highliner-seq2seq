#!/bin/bash

PROJDIRS=$(wildcard projects/*/.)

.PHONY: compile $(PROJDIRS)

compile: $(PROJDIRS)
$(PROJDIRS):
	$(MAKE) -C $@ CXXFLAGS+='$(OPT_FLAGS)' OPT_FLAGS+='$(OPT_FLAGS)'

