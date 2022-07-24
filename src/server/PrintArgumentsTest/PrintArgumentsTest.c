#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <Windows.h>

int main(int argc, char* argv[])
{
    int v = 0;
    bool run_forever = false;
    if (IsDebuggerPresent()) {
        fprintf(stdout, "Im' running under a debugger (PID: %d)! Press Enter to continue...", GetCurrentProcessId());
        scanf_s("%d", &v);
        fprintf(stdout, "continuing\n");
        run_forever = true;
    }   

    int i = 0;
    for (i = 0; i < argc; i++) {
        printf("Arg %d: %s\n", i, argv[i]);
    }

    while (run_forever) {
        fprintf(stdout, "I'll run forever!!!\n");
        Sleep(2000);
    }
    return 0;
}