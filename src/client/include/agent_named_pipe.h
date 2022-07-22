#pragma once
#ifndef NAMED_PIPE_H
#define NAMED_PIPE_H
#include <stdbool.h>
#include <stdint.h>

typedef struct pipe_handle_s pipe_handle;
struct pipe_handle_s {
    uintptr_t handle;
    void* overlap;
    bool is_client;
    bool is_async;
};

// Create a client named pipe
pipe_handle* pipe_client_connect(const char* const);

// Wait for the named pipe to be ready
bool pipe_client_wait_for_server(const char* const, int32_t);

// Create a server named pipe, and specify the wait timeout
pipe_handle* pipe_server_new(const char* const pipe_name, int32_t timeout, bool async_pipe, bool message_pipe);

// The server wait for a client to connect
bool pipe_server_connect(pipe_handle*, int32_t timeout);

// write to the pipe and return the number of written byte or -1 on error
int32_t pipe_write(pipe_handle*, size_t, void*);

// read from the pipe
int32_t pipe_read(pipe_handle*, size_t, void*);

// free the allocated pipe
void pipe_free(pipe_handle*);

// check if the pipe has data to be read
bool pipe_data_available(pipe_handle*);

// create a new pipe from an already existing handle
pipe_handle* pipe_from_handle(uintptr_t handle, bool is_client);

// disconnecte the server
void pipe_server_disconnect(pipe_handle* hPipe);

// call the named pipe by sending a message and reading a response
int32_t pipe_client_call_pipe(const char* const pipe_name, int32_t timeout, uint32_t req_size, uint8_t* req, uint32_t resp_size, uint8_t* resp);

#endif