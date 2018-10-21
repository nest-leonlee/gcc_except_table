#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>

#include <exception>
#include <stdexcept>

class A
{
public:
    __attribute__((noinline)) A(const char *str) : str_(str) { printf("A::A() [%p] %s\n", this, str_); }
    __attribute__((noinline)) ~A() { printf("A::~A() [%p] %s\n", this, str_); }

private:
    const char *str_;
};

void test3()
{
    A a1("a1");

    int *p = NULL;
    *p = 1;

    A a2("a2");
}

void test3_noexcept() noexcept
{
    A a1("a1");

    int *p = NULL;
    *p = 1;

    A a2("a2");
}
