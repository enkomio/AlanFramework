#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <processthreadsapi.h>
#include <process.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <ConsoleApi.h>
#include "agent_output_interceptor.h"
#include "agent_utility.h"
#include "agent_named_pipe.h"
#include "agent_config.h"
#include "agent_event.h"

uint32_t g_exited = 0;
interceptor* g_intrc = 0;

#define GOTO_EXIT_ON_ERROR(x)    \
  do {                           \
    if (!(x))                    \
      goto fail;                 \
  } while(0)

struct interceptor_s {
    HANDLE saved_output;
    HANDLE saved_input;
    HANDLE pipe_read;
    HANDLE pipe_write;
    uint32_t saved_output_mode;
    uint32_t saved_input_mode;
    uintptr_t interceptor_thread;
    pipe_handle* client_pipe;
    event_handle* termination_event;
};

static bool g_console_exists = true;

static int32_t send_output(interceptor* interc) {
    char buf[4096] = { 0 };
    OVERLAPPED overlapped = { 0 };
    size_t r = 0;
    int32_t bcount = 0;

    HANDLE hEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
    overlapped.hEvent = hEvent;
    if (ReadFile(interc->pipe_read, buf, (sizeof buf), NULL, &overlapped)) {
        uint32_t wait_result = WaitForSingleObject(hEvent, 0x4000);
        if (wait_result == WAIT_OBJECT_0) {
            if (GetOverlappedResult(interc->pipe_read, &overlapped, &r, true) && r)
                bcount = pipe_write(interc->client_pipe, r, buf);
        }
    }
    CloseHandle(hEvent);
    return bcount;
}

static void WINAPI intercept_output_thread(void* args) {
    interceptor* interc = (interceptor*)args;
    while (!event_is_signaled(interc->termination_event)) {
        send_output(interc);
    }
}

static bool WINAPI ctrl_handler(DWORD dwCtrlType) {
    interceptor_run_to_completation();
    return true;
}

static int interceptor_onexit(void) {
    interceptor_run_to_completation();
    return 1;
}

static uint32_t initialize_client_pipe(interceptor* interc) {
    pipe_handle* hPipe = ZERO(pipe_handle);
    uint32_t result = ERROR_OK;

    // generate pipe name
    uint32_t seed = system_fingerprint() + _getpid();
    char pipe_name[64] = "//./pipe/";
    gen_random_string(seed, 32, &pipe_name[strlen(pipe_name)]);

    // check if the server named pipe show-up
    if (pipe_client_wait_for_server(pipe_name, 0x4000)) {
        // create the named pipe	
        hPipe = pipe_client_connect(pipe_name);
        if (!hPipe) {
            result = ERROR_INTERCEPTOR_NAMEDPIPE_CLIENT;
            goto exit;
        }

        // create the event to stop the thread
        uint32_t termination_seed = system_fingerprint() + (_getpid() * 3);
        char termination_event_name[64] = "Global\\";
        gen_random_string(termination_seed, 32, &termination_event_name[strlen(termination_event_name)]);
        event_handle* e = event_new(termination_event_name);
        if (!e) {
            result = ERROR_EVENT_CREATION;
            goto exit;
        }

        // all fine, set info
        interc->client_pipe = hPipe;
        interc->termination_event = e;
    }
    else {
        result = ERROR_INTERCEPTOR_NAMEDPIPE_SERVER_DOWN;
        goto exit;
    }

exit:
    return result;
}

static bool interceptor_start(interceptor* interc) {    
    if (!AttachConsole(GetCurrentProcessId())) {
        AllocConsole();
        g_console_exists = false;
    }    

    HANDLE stdOutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE stdInHandle = GetStdHandle(STD_INPUT_HANDLE);

    // save console info
    GetConsoleMode(stdOutHandle, &interc->saved_output_mode);
    GetConsoleMode(stdInHandle, &interc->saved_input_mode);
    interc->saved_output = stdOutHandle;
    interc->saved_input = stdInHandle;

    // init console
    SetConsoleMode(stdInHandle, ENABLE_WINDOW_INPUT | ENABLE_LINE_INPUT);
    SetConsoleMode(stdOutHandle, ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT);

    // create pipe    
    SECURITY_ATTRIBUTES securityAttributes = { 0 };
    securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    securityAttributes.lpSecurityDescriptor = NULL;
    securityAttributes.bInheritHandle = TRUE;
    GOTO_EXIT_ON_ERROR(CreatePipe(&interc->pipe_read, &interc->pipe_write, &securityAttributes, 0));
    
    // set pipe as std handle
    SetStdHandle(STD_OUTPUT_HANDLE, interc->pipe_write);
    SetStdHandle(STD_INPUT_HANDLE, interc->pipe_read);

    // bind C runtime stdout
    FILE* dummyFile = ZERO(FILE);
    freopen_s(&dummyFile, "nul", "w", stdout);
    freopen_s(&dummyFile, "nul", "r", stdin);
    
    int fd_o = _open_osfhandle(interc->pipe_write, _O_TEXT);
    if (fd_o != -1) {
        FILE* file_o = _fdopen(fd_o, "w");
        if (file_o != NULL) {
            int err = _dup2(_fileno(file_o), _fileno(stdout));
            if (err != -1) {
                setvbuf(stdout, NULL, _IONBF, 0);
            }
        }
    }
    
    int fd_i = _open_osfhandle(interc->pipe_read, _O_TEXT);
    if (fd_i != -1) {
        FILE* file_i = _fdopen(fd_o, "w");
        if (file_i != NULL) {
            int err = _dup2(_fileno(file_i), _fileno(stdin));
            if (err != -1) {
                setvbuf(stdin, NULL, _IONBF, 0);
            }
        }        
    }

    // set exit handler
    SetConsoleCtrlHandler((PHANDLER_ROUTINE)ctrl_handler, true);
    _onexit(interceptor_onexit);
       
    interc->interceptor_thread = _beginthreadex(
        NULL,
        0,
        (_beginthreadex_proc_type)intercept_output_thread,
        (void*)interc,
        0,
        NULL
    );
    if (!interc->interceptor_thread) goto fail;
    
    // signal initialization termination event
    uint32_t initialization_seed = system_fingerprint() + (_getpid() * 2);
    char initialization_event_name[64] = "Global\\";
    gen_random_string(initialization_seed, 32, &initialization_event_name[strlen(initialization_event_name)]);
    event_handle* initialization_event = event_open(initialization_event_name);
    if (!initialization_event) goto fail;
    event_set(initialization_event);
    event_free(initialization_event);

    return true;

fail:
    return false;
}

bool interceptor_session_initialize(void) {
    g_intrc = OBJ_ALLOC(interceptor);
    return g_intrc != 0;
}

bool interceptor_run_to_completation(void) {
    if (g_intrc) {
        if (!InterlockedCompareExchange(&g_exited, 1, 1)) {
            while (send_output(g_intrc));
            g_exited = true;
        }
        return true;
    }
    return false;
}

uint32_t interceptor_run(void) {    
    uint32_t result = ERROR_UNKNOWN;
    if (!g_intrc) goto exit;

    // first connect to the server
    result = initialize_client_pipe(g_intrc);
    if (!SUCCESS(result)) goto exit;

    // now we can intercept the output to send to the server
    if (!interceptor_start(g_intrc)) {
        result = ERROR_INTERCEPTOR_NOT_STARTED;
        goto exit;
    }
exit:
    return result;
}

void interceptor_wait_completation(void) {
    if (g_intrc)
        WaitForSingleObject((HANDLE)g_intrc->interceptor_thread, INFINITE);
}

void interceptor_free(void) {
    if (g_intrc)
    {
        SetStdHandle(STD_OUTPUT_HANDLE, g_intrc->saved_output);
        SetStdHandle(STD_INPUT_HANDLE, g_intrc->saved_input);
        SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), g_intrc->saved_input_mode);
        SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), g_intrc->saved_output_mode);

        // bind C runtime stdout
        FILE* dummyFile = ZERO(FILE);
        freopen_s(&dummyFile, "nul", "w", stdout);
        freopen_s(&dummyFile, "nul", "r", stdin);

        int fd = _open_osfhandle(GetStdHandle(STD_OUTPUT_HANDLE), _O_WRONLY | _O_TEXT);
        if (fd != -1) {
            int err = _dup2(fd, _fileno(stdout));
            if (err != -1) {
                setvbuf(stdout, NULL, _IONBF, 0);
            }
        }

        fd = _open_osfhandle(GetStdHandle(STD_INPUT_HANDLE), _O_RDONLY | _O_TEXT);
        if (fd != -1) {
            int err = _dup2(fd, _fileno(stdin));
            if (err != -1) {
                setvbuf(stdin, NULL, _IONBF, 0);
            }
        }

        CloseHandle(g_intrc->pipe_write);
        CloseHandle(g_intrc->pipe_read);
        FREE(g_intrc);

        if (!g_console_exists)
            FreeConsole();
    }    
}