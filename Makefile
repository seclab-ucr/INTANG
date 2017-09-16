# Top level makefile


default: all

.DEFAULT:
	cd src && $(MAKE) $@
	mkdir -p bin && cp src/intangd bin/

clean: 
	cd src && $(MAKE) $@

.PHONY: install

