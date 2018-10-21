.PHONY: build clean

SUBDIRS = test

build:
	@gcc -g  gcc_except_table.c -o gcc_except_table
	@$(MAKE) -C $(SUBDIRS)

clean:
	@rm -f gcc_except_table
	@$(MAKE) -C $(SUBDIRS) $@

