#include <hpfeeds.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char** argv)
{
    hpf_handle_t* handle = NULL;
    hpf_connect(&handle, "127.0.0.1", "10000");
    hpf_authenticate(handle, "boh", "bohhhh");
    return 1;
}
