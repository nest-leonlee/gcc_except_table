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

extern void test2();
extern void test2_noexcept();

class A
{
public:
    __attribute__((noinline)) A(const char *str) : str_(str) { printf("A::A() [%p] %s\n", this, str_); }
    __attribute__((noinline)) ~A() { printf("A::~A() [%p] %s\n", this, str_); }

private:
    const char *str_;
};

void test1()
{
    A a1("a1");

    int *p = NULL;
    *p = 1;

    A a2("a2");
}

void test1_noexcept() noexcept
{
    A a1("a1");

    int *p = NULL;
    *p = 1;

    A a2("a2");
}

int main(int argc, char *argv[])
{
    int idx = 1;
    if (argc > 1 && argv[1][1] == '0')
    {
        if (argv[1][0] == '1') idx = 1;
        else if (argv[1][0] == '2') idx = 2;
    }

    try
    {
        switch (idx)
        {
        case 1:
            test1();
            test1_noexcept();
            break;

        case 2:
            test2();
            test2_noexcept();
            break;
        }
    }
    catch (std::exception& e)
    {
        printf("%s\n", e.what());
    }

    return 0;
}
