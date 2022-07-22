#pragma once
#ifndef SOCKS5_H
#define SOCKS5

#include <stdint.h>
#include "mbedtls/net_sockets.h"
#include "agent_network.h"

#define SOCKS4_VERSION 4
#define SOCKS5_VERSION 5
#define SOCKS5_METHOD_NOAUTH 0x0
#define SOCKS5_METHOD_USERNAME_PASSWORD 0x02
#define SOCKS5_AUTH_SUBNEGOTIATION 0x01
#define SOCKS5_COMMAND_CONNECT 0x01
#define SOCKS5_TYPE_IPV4_ADDRESS 0x1
#define SOCKS5_TYPE_DOMAIN_NAME 0x3
#define SOCKS5_REPLYSTATUS_OK 0x0
#define SOCKS5_REPLYSTATUS_GENERAL_ERROR 0x1
#define SOCKS5_REPLYSTATUS_HOST_UNREACHABLE 0x3

#ifdef WIN32
#include <WS2tcpip.h>
#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")
#endif

__pragma(pack(push, 1))
typedef struct proxy_session proxy_session;
struct proxy_session {
	SOCKET client;
	SOCKET server;
	struct proxy_session* next;
};

typedef struct socks5_context socks5_context;
struct socks5_context {
	uint32_t username_len;
	uint32_t password_len;
	char* username;
	char* password;
	char* address;
	uint32_t address_len;
	char* port;
	uint32_t port_len;
	bool terminate;
	bool use_proxy;
	socks5_context* proxy;
	uint64_t received_bytes;
	uint64_t transmitted_bytes;
};

typedef struct socks_negotiation_request socks_negotiation_request;
struct socks_negotiation_request {
	uint8_t ver;
	uint8_t n_methods;
	uint8_t methods[0];
};

typedef struct socks_negotiation_response socks_negotiation_response;
struct socks_negotiation_response {
	uint8_t ver;
	uint8_t method;
};

typedef struct socks_auth_request_username socks_auth_request_username;
struct socks_auth_request_username {
	uint8_t ver;
	uint8_t ulen;
};

typedef struct socks_auth_request_password socks_auth_request_password;
struct socks_auth_request_password {
	uint8_t plen;
};

typedef struct socks_auth_request_password_result socks_auth_request_password_result;
struct socks_auth_request_password_result {
	uint8_t ver;
	uint8_t status;
};

typedef struct socks_request_details socks_request_details;
struct socks_request_details {
	uint8_t ver;
	uint8_t cmd;
	uint8_t rsv;
	uint8_t atyp;
};

typedef struct socks_response_details socks_response_details;
struct socks_response_details {
	uint8_t ver;
	uint8_t rep;
	uint8_t rsv;
	uint8_t atyp;
	uint8_t bind_addr[0];
};
__pragma(pack(pop))

typedef enum {
	STOP = 1,
	CHAIN_CREATE = 2,
	CHAIN_STOP = 3,
	INFO = 4
} socks5_command_type;

typedef struct socks5_command socks5_command;
struct socks5_command {	
	socks5_command_type type;
	uint32_t response_size;
	uint8_t* response;
	uint32_t data_size;
	uint8_t data[0];
};

// start a new SOCKS5 proxy binding on the specific IP and PORT value
int proxy_server_start(char* ip, char* port, char* username, char* password);

// connect the client to the proxy
bool proxy_client_connect(mbedtls_net_context* f, char* ip, char* port, char* username, char* password);

// open a proxy session after that a connection is established
bool proxy_client_open(mbedtls_net_context* f, char* ip, char* port);

// send command to the proxy running on the same machine
bool proxy_send_command(socks5_command* cmd, char* port);
#endif