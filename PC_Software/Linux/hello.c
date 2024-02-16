#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
    #define OS_NAME "Windows"
    #include <windows.h>
    #define SLEEP_SECONDS 1000 // Sleep for 1000 milliseconds
#else
    #define OS_NAME "Linux"
    #include <unistd.h>
    #define SLEEP_SECONDS 1 // Sleep for 1 second
#endif

int main()
{
    printf("Hello World from %s ....\n", OS_NAME);

    while (1)
    {
        #ifdef _WIN32
            Sleep(SLEEP_SECONDS);
        #else
            sleep(SLEEP_SECONDS);
        #endif
    }
    
    return 0;
}
