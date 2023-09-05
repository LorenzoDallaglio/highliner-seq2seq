#!/bin/bash

PROJDIRS=$(wildcard projects/*/.)

.PHONY: all $(PROJDIRS) 

all: $(PROJDIRS)
$(PROJDIRS):
	$(MAKE) -C $@

clean: $(PROJDIRS)
$(PROJDIRS):
	-$(MAKE) -C $@ clean

#$(PROJDIRS):


