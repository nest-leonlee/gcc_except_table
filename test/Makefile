.PHONY: build clean

build:
	@g++ -g -O3 -fnon-call-exceptions -shared -fpic libtest3.cpp -o libtest3.so
	@g++ -g -O3 -fnon-call-exceptions -c libtest2.cpp -o libtest2.o
	@ar rs libtest2.a libtest2.o
	@g++ -g -O3 -fnon-call-exceptions -L. test.cpp -ltest2 -o test

clean:
	@rm -rf *.o libtest2.a libtest3.so test

