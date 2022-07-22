/*
This file is only used for testing purpose.
It should never be included in the release package.
*/

#ifdef DEBUG

#include <Windows.h>
#include <io.h>
#include <fcntl.h>
#include <processthreadsapi.h>
#include <process.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "agent_output_interceptor.h"
#include "agent_utility.h"
#include "agent_named_pipe.h"
#include "agent_config.h"
#include "agent_event.h"

static pipe_handle* create_server() {
    // generate pipe name
    uint32_t seed = system_fingerprint() + _getpid();
    char pipe_name[64] = "//./pipe/";
    gen_random_string(seed, 32, &pipe_name[strlen(pipe_name)]);

    // create the named pipe
    pipe_handle* hPipe = pipe_server_new(pipe_name, 0x4000, true);
    if (!hPipe) goto fail;

    return hPipe;

fail:
    return NULL;
}

void handle_client_output(void* args) {
    pipe_handle* hPipe = (pipe_handle*)args;
    int result = 0;

    if (!pipe_server_connect(hPipe)) {
        result = ERROR_PIPE_SERVER_CONNECT;
        goto fail;
    }

    while (true) {
        char buf[4096] = { 0 };
        size_t nread = pipe_read(hPipe, sizeof buf, buf);
        if (nread > 0) {
            // if we reach this point the test was successful :) 
            result = 1;
        }        
    }

fail:
    return;
}

int main() {
    // See https://github.com/MicrosoftDocs/Console-Docs/issues/95
    // see https://gist.github.com/kingseva/a918ec66079a9475f19642ec31276a21
    // From: https://stackoverflow.com/questions/311955/redirecting-cout-to-a-console-in-windows/25927081#25927081
    // See https://stackoverflow.com/questions/54094127/redirecting-stdout-in-win32-does-not-redirect-stdout
    
    interceptor* intrc = interceptor_new();
    pipe_handle* server = create_server();
    if (server) {  
        _beginthreadex(
            NULL,
            0,
            (_beginthreadex_proc_type)handle_client_output,
            (void*)server,
            0,
            NULL
        );

        if (interceptor_run(intrc) == ERROR_OK) {
            // start an infinite loop that write content to the console
            while (true) {
                Sleep(500);
                size_t rr = 0;
                HANDLE hh = GetStdHandle(STD_OUTPUT_HANDLE);
                // NOT REDIRECTED => limitation of Windows OS
                WriteConsole(hh, "WriteConsole", strlen("WriteConsole"), &rr, 0);  
                WriteFile(hh, "WriteFile", strlen("WriteFile") * sizeof(TCHAR), &rr, 0);
                printf("printf");
            }
        }
    }

    return EXIT_SUCCESS;
}

int WinMain(
    HINSTANCE   hInstance,
    HINSTANCE   hPrevInstance,
    LPSTR       lpCmdLine,
    int         nCmdShow
) {
    return main();
}
#else
int main() {
    return 0;
}
#endif