#include <dlfcn.h>

int main()
{
    void* handle = 0;

    handle = dlopen("libm.so", RTLD_NOW);
    dlclose(handle);    

    return 0;
}

