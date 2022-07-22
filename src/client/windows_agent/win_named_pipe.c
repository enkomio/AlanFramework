#include <Windows.h>
#include <fileapi.h>
#include <stdint.h>
#include <stdbool.h>
#include "agent_named_pipe.h"
#include "agent_utility.h"

pipe_handle* pipe_client_connect(const char* const pipe_name) {
    pipe_handle* hPipe = OBJ_ALLOC(pipe_handle);
    hPipe->is_client = true;
    hPipe->handle = (uintptr_t)CreateFile(
        pipe_name,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if ((HANDLE)(hPipe->handle) == INVALID_HANDLE_VALUE) goto fail;
    return hPipe;
fail:
    FREE(hPipe);
    return 0;
}

pipe_handle* pipe_server_new(const char* const pipe_name, int32_t timeout, bool async_pipe, bool message_pipe) 
{
    DWORD dwOpenMode = PIPE_ACCESS_DUPLEX;
    if (async_pipe)
        dwOpenMode |= FILE_FLAG_OVERLAPPED;

    DWORD dwPipeMode = PIPE_WAIT;
    if (message_pipe) {
        dwPipeMode |= PIPE_TYPE_MESSAGE;
        dwOpenMode |= PIPE_READMODE_MESSAGE;
    }        
    else {
        dwPipeMode |= PIPE_TYPE_BYTE;
        dwOpenMode |= PIPE_READMODE_BYTE;
    }        

    pipe_handle* hPipe = OBJ_ALLOC(struct pipe_handle_s);
    hPipe->is_client = false;
    hPipe->is_async = async_pipe;
    hPipe->handle = (uintptr_t)CreateNamedPipe(
        pipe_name,
        dwOpenMode,
        dwPipeMode,
        PIPE_UNLIMITED_INSTANCES,
        1024 * 16,
        1024 * 16,
        timeout,
        NULL
    );
    if ((HANDLE)hPipe->handle == INVALID_HANDLE_VALUE) goto fail;
    return hPipe;
fail:
    FREE(hPipe);
    return 0;
}

bool pipe_client_wait_for_server(const char* const pipe_name, int32_t timeout) 
{
    return WaitNamedPipe(pipe_name, timeout);
}

int32_t pipe_client_call_pipe(const char* const pipe_name, int32_t timeout, uint32_t req_size, uint8_t* req, uint32_t resp_size, uint8_t* resp)
{
    int32_t nread = 0;
    CallNamedPipeA(
        pipe_name,
        req,
        req_size,        
        resp,
        resp_size,
        &nread, 
        timeout
    );
    return nread;
}

bool pipe_server_connect(pipe_handle* hPipe, int32_t timeout) 
{
    bool result = false;
    if (hPipe->is_async) {
        if (hPipe->overlap) {
            HANDLE hEvent = ((OVERLAPPED*)hPipe->overlap)->hEvent;
            uint32_t wait_result = WaitForSingleObject(hEvent, timeout);
            result = wait_result == WAIT_OBJECT_0;
        }
        else {
            hPipe->overlap = OBJ_ALLOC(OVERLAPPED);
            HANDLE hEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
            ((OVERLAPPED*)hPipe->overlap)->hEvent = hEvent;
            if (!ConnectNamedPipe((HANDLE)hPipe->handle, (OVERLAPPED*)hPipe->overlap)) {
                uint32_t wait_result = WaitForSingleObject(hEvent, timeout);
                result = wait_result == WAIT_OBJECT_0;
            }
        }
    }
    else {
        result = ConnectNamedPipe((HANDLE)hPipe->handle, NULL) || GetLastError() == ERROR_PIPE_CONNECTED;
    }    

    if (result && hPipe->is_async && hPipe->overlap) {
        CloseHandle(((OVERLAPPED*)hPipe->overlap)->hEvent);
        FREE(hPipe->overlap);
    }
    
    return result;
}

int32_t pipe_write(pipe_handle* hPipe, size_t buffer_size, void* buffer) {
    DWORD cbWritten = 0;
    bool result = WriteFile(
        (HANDLE)hPipe->handle,
        buffer,
        buffer_size,
        &cbWritten,
        NULL
    );

    return !result ? -1 : cbWritten;
}

int32_t pipe_read(pipe_handle* hPipe, size_t buffer_size, void* buffer) {
    DWORD dwRead = 0;    
    if (hPipe && hPipe->handle && pipe_data_available(hPipe) && !ReadFile(
        (HANDLE)hPipe->handle,
        buffer,
        buffer_size,
        &dwRead,
        NULL
    )) dwRead = -1;    
    return dwRead;
}

void pipe_server_disconnect(pipe_handle* hPipe)
{
    if (hPipe && hPipe->handle && !hPipe->is_client) {
        if (hPipe->overlap) {
            CloseHandle(((OVERLAPPED*)hPipe->overlap)->hEvent);
            FREE(hPipe->overlap);
        }
        DisconnectNamedPipe((HANDLE)hPipe->handle);
    }
}

void pipe_free(pipe_handle* hPipe)
{
    if (hPipe) {
        if (hPipe->handle) {
            pipe_server_disconnect(hPipe);
            CloseHandle((HANDLE)hPipe->handle);
        }
        FREE(hPipe);
    }
}

bool pipe_data_available(pipe_handle* hPipe) {
    DWORD count = 0;
    if (!PeekNamedPipe(
        (HANDLE)hPipe->handle,
        NULL,
        0,
        NULL,
        &count,
        NULL
    )) goto fail;
    return count > 0;
fail:
    return false;
}


pipe_handle* pipe_from_handle(uintptr_t handle, bool is_client) {
    pipe_handle* hPipe = OBJ_ALLOC(pipe_handle);
    hPipe->is_client = is_client;
    hPipe->handle = handle;
    return hPipe;
}