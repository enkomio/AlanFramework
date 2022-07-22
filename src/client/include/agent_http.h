#pragma once
#ifndef HTTP_H
#define HTTP_H
#include <stdint.h>
#include <stdbool.h>
#include "agent_network.h"

typedef struct header_s header;
struct header_s {
    char* name;
    char* value;
};

typedef struct cookie_s cookie;
struct cookie_s {
    char* name;
    char* value;
};

typedef struct http_request_s http_request;
struct http_request_s {
    char* method;
    char* path;
    uint32_t headers_count;
    header** headers;
    uint32_t cookies_count;
    cookie** cookies;
    size_t data_size;
    void* data;
    bool use_https; 
    uint32_t timeout;
};

typedef struct http_response_s http_response;
struct http_response_s {
    uint32_t status_code;
    uint32_t headers_count;
    header** headers;
    uint32_t cookies_count;
    cookie** cookies;
    void* data;
    size_t data_size;
};

bool http_add_header(http_request* request, char* name, char* value);
bool http_add_cookie(http_request* request, char* name, char* value);
http_response* http_send_request(http_request* request, char* address, uint16_t port, proxy* proxy);
http_request* http_free_request(http_request* request);
http_response* http_free_response(http_response* response);

#endif