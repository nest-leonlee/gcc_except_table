.PHONY: build clean

build:
	@gcc -g  gcc_except_table.c -o gcc_except_table

clean:
	@rm gcc_except_table

