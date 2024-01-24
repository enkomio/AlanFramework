#pragma once
#ifndef NETWORK_H
#define NETWORK_H

#include <stdbool.h>
#include <stdint.h>

#define DEFAULT_TIMEOUT 2000

typedef enum proxy_type proxy_type;
enum proxy_type {
	SOCKS5,
	HTTP,	
	AUTO
};

typedef struct proxy_s proxy;
struct proxy_s {
	char* address;
	uint32_t port;
	proxy_type type;
	char* username;
	char* password;
};

// initialize the network system
bool network_initialize(void);

// cleanup the network system
void network_close(void);

// create a new proxy object
proxy* proxy_new(char* address, uint32_t port, char* username, char* password);

// free the proxy object
void proxy_free(proxy* p);

// retrieve the system HTTP proxy
bool proxy_get_system_http_proxy(char** address);

#endif