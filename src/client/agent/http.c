#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "agent_http.h"
#include "agent_utility.h"
#include "agent_socks5.h"
#include "agent_network.h"

#define COOKIE_HEADER "Cookie"
#define ENDLINE "\r\n"
#define ENDHEADER "\r\n\r\n"

static bool add_header_to_buffer_request(char** request_buffer, char* name, char* value)
{
	bool result = true;
	size_t buffer_size = strlen(*request_buffer);

	size_t hdr_length = snprintf(0, 0, "%s: %s%s", name, value, ENDLINE) + 1;
	if (!hdr_length) goto fail;
	buffer_size += hdr_length;
	*request_buffer = realloc(*request_buffer, buffer_size);
	if (!*request_buffer) goto fail;
	snprintf(*request_buffer + strlen(*request_buffer), hdr_length, "%s: %s%s", name, value, ENDLINE);

exit:
	return result;

fail:
	result = false;
	goto exit;
}

static char* create_request_buffer(http_request* request, char* address, char* port, size_t* buffer_size)
{
	char* request_buffer = ZERO(char);	
	char* cookie_header = ZERO(char);
	*buffer_size = 0;

	// create status line
	*buffer_size = snprintf(0, 0, "%s %s HTTP/1.1%s", request->method, request->path, ENDLINE) + 1;
	request_buffer = MEM_ALLOC(*buffer_size);
	if (!request_buffer) goto fail;
	snprintf(request_buffer, *buffer_size, "%s %s HTTP/1.1%s", request->method, request->path, ENDLINE);

	// add headers
	int i = 0;
	bool host_added = false;
	bool content_length_added = false;
	bool content_type_added = false;
	for (i = 0; i < request->headers_count; i++) {
		if (!add_header_to_buffer_request(&request_buffer, request->headers[i]->name, request->headers[i]->value)) goto fail;
		if (!strcmp(request->headers[i]->name, "Host"))
			host_added = true;
		if (!strcmp(request->headers[i]->name, "Content-Length"))
			content_length_added = true;
		if (!strcmp(request->headers[i]->name, "Content-Type"))
			content_type_added = true;
	}

	if (!host_added) {
		char* host_value = MEM_ALLOC(strlen(address) + strlen(port) + 2);
		if (!host_value) goto fail;
		strcat(host_value, address);
		if (request->use_https && !strcmp(port, "443") || !strcmp(port, "80")) {
			strcat(host_value, ":");
			strcat(host_value, port);
		}		
		if (!add_header_to_buffer_request(&request_buffer, "Host", host_value)) goto fail;
		FREE(host_value);
	}

	char* method_lc = _strlwr(_strdup(request->method));
	if (!strcmp(method_lc, "post")) {
		if (!content_length_added) {
			char sdata_size[32] = { 0 };
			snprintf(sdata_size, sizeof(sdata_size), "%d", request->data_size);
			if (!add_header_to_buffer_request(&request_buffer, "Content-Length", sdata_size)) goto fail;
		}

		if (!content_type_added && request->data_size) {
			if (!add_header_to_buffer_request(&request_buffer, "Content-Type", "text/plain")) goto fail;
		}
	}
	FREE(method_lc);

	// add cookies
	size_t cookie_header_size = 0;
	for (i = 0; i < request->cookies_count; i++) {
		cookie_header_size += snprintf(0, 0, "%s=%s; ", request->cookies[i]->name, request->cookies[i]->value);
	}
		
	cookie_header = MEM_ALLOC(cookie_header_size);
	if (!cookie_header) goto fail;

	for (i = 0; i < request->cookies_count; i++) {
		strcat(cookie_header, request->cookies[i]->name);
		strcat(cookie_header, "=");
		strcat(cookie_header, request->cookies[i]->value);
		if (i < request->cookies_count - 1)
			strcat(cookie_header, "; ");
	}
	if (!add_header_to_buffer_request(&request_buffer, COOKIE_HEADER, cookie_header)) goto fail;

	// close headers
	request_buffer = realloc(request_buffer, strlen(request_buffer) + strlen(ENDLINE) + 1);
	if (!request_buffer) goto fail;
	strcat(request_buffer, ENDLINE);
	*buffer_size = strlen(request_buffer);

	// add data
	if (request->data_size) {
		request_buffer = realloc(request_buffer, strlen(request_buffer) + request->data_size + 1);
		if (!request_buffer) goto fail;		
		memcpy(request_buffer + strlen(request_buffer), request->data, request->data_size);
		*buffer_size += request->data_size;
	}	
	
exit:
	return request_buffer;

fail:
	*buffer_size = 0;
	FREE(request_buffer);
	request_buffer = ZERO(char);
	goto exit;
}

static http_response* read_server_response(http_request* request, mbedtls_net_context* server_fd, mbedtls_ssl_context* ssl)
{
	http_response* response = ZERO(http_response);

	char tmp[1024] = { 0 };
	size_t response_buffer_size = 0;
	char* response_buffer = ZERO(char);	
	char* p = 0;
	char* body_start = 0;

	// read response header
	while (true) {
		int n = 0;
		if (request->use_https)
			n = mbedtls_ssl_read(ssl, tmp, sizeof(tmp));
		else
			n = mbedtls_net_recv(server_fd, tmp, sizeof(tmp));

		if (!n) break;
		response_buffer = realloc(response_buffer, response_buffer_size + n);
		if (!response_buffer) goto fail;
		memcpy(response_buffer + response_buffer_size, tmp, n);
		response_buffer_size += n;
		if (!body_start && (body_start = strstr(response_buffer, ENDHEADER))) break;
	}

	// mark the end of the headers
	if (body_start) {
		*body_start = 0;
		body_start += strlen(ENDHEADER);
	}		

	// going to compose the response object
	response = OBJ_ALLOC(http_response);
	if (!response) goto fail;

	// parse status-line
	p = strchr(response_buffer, ' ');
	if (p > strstr(response_buffer, ENDLINE)) goto fail;
	response->status_code = strtol(p, 0, 10);

	// get headers count
	p = strstr(response_buffer, ENDLINE) + strlen(ENDLINE);
	char* headers_ptr = strtok(response_buffer, ENDLINE);
	while (true) {
		headers_ptr = strtok(0, ENDLINE);
		if (!headers_ptr) break;
		if (!strncmp(headers_ptr, "Set-Cookie", 10))
			response->cookies_count++;
		else
			response->headers_count++;
	}

	// parse headers
	response->headers = MEM_ALLOC(sizeof(header) * response->headers_count);
	if (!response->headers) goto fail;

	response->cookies = MEM_ALLOC(sizeof(cookie) * response->cookies_count);
	if (!response->cookies) goto fail;

	int i = 0;
	headers_ptr = p;
	uint32_t body_size = 0;
	for (i = 0; i < response->headers_count;) {
		char* colon_pos = strchr(headers_ptr, ':');
		if (colon_pos) {
			if (!strncmp(headers_ptr, "Set-Cookie", 10)) {
				response->cookies[i] = OBJ_ALLOC(cookie);
				if (!response->cookies[i]) goto fail;

				response->cookies[i]->name = MEM_ALLOC(colon_pos - headers_ptr + 1);
				if (!response->cookies[i]->name) goto fail;
				strncpy(response->cookies[i]->name, headers_ptr, colon_pos - headers_ptr);

				colon_pos += 2;
				response->cookies[i]->value = MEM_ALLOC(strlen(colon_pos) + 1);
				if (!response->cookies[i]->value) goto fail;
				strncpy(response->cookies[i]->value, colon_pos, strlen(colon_pos));
			}
			else {
				response->headers[i] = OBJ_ALLOC(header);
				if (!response->headers[i]) goto fail;

				response->headers[i]->name = MEM_ALLOC(colon_pos - headers_ptr + 1);
				if (!response->headers[i]->name) goto fail;
				strncpy(response->headers[i]->name, headers_ptr, colon_pos - headers_ptr);

				colon_pos += 2;
				response->headers[i]->value = MEM_ALLOC(strlen(colon_pos) + 1);
				if (!response->headers[i]->value) goto fail;
				strncpy(response->headers[i]->value, colon_pos, strlen(colon_pos));

				// get the body size
				if (!strcmp(response->headers[i]->name, "Content-Length"))
					body_size = strtol(response->headers[i]->value, 0, 10);
			}
			i++;
		}
		headers_ptr += strlen(headers_ptr) + strlen(ENDLINE);
	}	

	// read the remaining body if any	
	if (body_size) {		
		ptrdiff_t headers_size = body_start - response_buffer;
		while (response_buffer_size - headers_size < body_size) {
			int n = 0;
			if (request->use_https)
				n = mbedtls_ssl_read(ssl, tmp, sizeof(tmp));
			else
				n = mbedtls_net_recv(server_fd, tmp, sizeof(tmp));
			if (n < 0) goto fail;
			response_buffer = realloc(response_buffer, response_buffer_size + n);
			memcpy(response_buffer + response_buffer_size, tmp, n);
			response_buffer_size += n;
		}

		response->data_size = body_size;
		response->data = MEM_ALLOC(body_size + 1);
		memcpy(response->data, response_buffer + headers_size, body_size);
	}
	else
		goto fail;
	
exit:
	FREE(response_buffer);
	return response;

fail:
	response = ZERO(http_response);
	goto exit;
}

http_response* http_send_request(http_request* request, char* address, uint16_t port, proxy* proxy) 
{
	http_response* response = ZERO(http_response);
	char* request_buffer = ZERO(char);
	size_t buffer_size = 0;

	mbedtls_net_context server_fd = { 0 };
	mbedtls_ctr_drbg_context drbg = { 0 };
	mbedtls_ssl_context ssl = { 0 };
	mbedtls_ssl_config conf = { 0 };
	mbedtls_entropy_context entropy = { 0 };

	char port_str[32] = { 0 };
	snprintf(port_str, sizeof(port_str), "%d", port);

	request_buffer = create_request_buffer(request, address, port_str, &buffer_size);
	if (!request_buffer) goto fail;

	mbedtls_net_init(&server_fd);
	if (proxy) {	
		if (proxy->type == SOCKS5) {
			snprintf(port_str, sizeof(port_str), "%d", proxy->port);
			if (!proxy_client_connect(
				&server_fd,
				proxy->address,
				port_str,
				proxy->username,
				proxy->password
			)) goto fail;

			snprintf(port_str, sizeof(port_str), "%d", port);
			if (!proxy_client_open(
				&server_fd,
				address,
				port_str
			)) goto fail;
		}
		else if (proxy->type == HTTP) {
			// TODO implement HTTP proxy
		}
		else if (proxy->type == AUTO) {
			// TODO implement AUTO proxy
			char* proxy_url = ZERO(char);
			if (!proxy_get_system_http_proxy(&proxy_url)) goto fail;

		}
		else {
			// unrecognized proxy value
			goto fail;
		}
			
	}
	else {
		if (mbedtls_net_connect(&server_fd, address, port_str, MBEDTLS_NET_PROTO_TCP)) goto fail;
	}

	if (request->use_https) {
		mbedtls_ctr_drbg_init(&drbg);
		mbedtls_ssl_init(&ssl);
		conf.read_timeout = request->timeout ? request->timeout : DEFAULT_TIMEOUT;
		mbedtls_ssl_config_init(&conf);
		mbedtls_entropy_init(&entropy);

		if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, 0, 0)) goto fail;
		mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
		if (mbedtls_ssl_setup(&ssl, &conf)) goto fail;
		if (mbedtls_ssl_config_defaults(
			&conf,
			MBEDTLS_SSL_IS_CLIENT,
			MBEDTLS_SSL_TRANSPORT_STREAM,
			MBEDTLS_SSL_PRESET_DEFAULT
		)) goto fail;

		mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
		mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
	}

	// send the request	
	size_t offset = 0;

	if (request->use_https)
		if (mbedtls_ssl_handshake(&ssl)) goto fail;

	while (true) {
		int n = 0;
		if (request->use_https)
			n = mbedtls_ssl_write(&ssl, request_buffer + offset, buffer_size - offset);
		else
			n = mbedtls_net_send(&server_fd, request_buffer + offset, buffer_size - offset);

		if (!n) break;
		offset += n;
	}

	// read the response
	response = read_server_response(request, &server_fd, &ssl);	

	// clean up all used resources and structures.
	if (request->use_https) {		
		if (mbedtls_ssl_close_notify(&ssl)) goto fail;
		mbedtls_ssl_free(&ssl);
		mbedtls_ssl_config_free(&conf);
		mbedtls_ctr_drbg_free(&drbg);
		mbedtls_entropy_free(&entropy);
	}
	
	mbedtls_net_free(&server_fd);
	if (!response) goto fail;

exit:
	return response;

fail:
	if (response) http_free_response(response);
	response = ZERO(http_response);
	goto exit;
}

http_request* http_free_request(http_request* request) {
	FREE(request->data);
	FREE(request->method);
	FREE(request->path);
	int i = 0;
	if (request->headers_count) {
		for (i = 0; i < request->headers_count; i++) {
			if (request->headers[i]) {
				header* hdr = request->headers[i];
				FREE(hdr->name);
				FREE(hdr->value);
				FREE(hdr);
				request->headers[i] = ZERO(header);
			}
		}
		FREE(request->headers);
	}
	if (request->cookies_count) {
		for (i = 0; i < request->cookies_count; i++) {
			if (request->cookies[i]) {
				cookie* ck = request->cookies[i];
				FREE(ck->name);
				FREE(ck->value);
				FREE(ck);
				request->cookies[i] = ZERO(cookie);
			}
		}
		FREE(request->cookies);
	}
	FREE(request);
	return ZERO(http_request);
}

http_response* http_free_response(http_response* response) {
	FREE(response->data);
	int i = 0;
	if (response->headers_count) {
		for (i = 0; i < response->headers_count; i++) {
			if (response->headers[i]) {
				header* hdr = response->headers[i];
				FREE(hdr->name);
				FREE(hdr->value);
				FREE(hdr);
				response->headers[i] = ZERO(header);
			}
		}
		FREE(response->headers);
	}
	if (response->cookies_count) {
		for (i = 0; i < response->cookies_count; i++) {
			if (response->cookies[i]) {
				cookie* ck = response->cookies[i];
				FREE(ck->name);
				FREE(ck->value);
				FREE(ck);
				response->cookies[i] = ZERO(cookie);
			}
		}
		FREE(response->cookies);
	}
	FREE(response);
	return (http_response*) { 0 };
}

bool http_add_cookie(http_request* request, char* name, char* value) {
	cookie* ck = OBJ_ALLOC(cookie);
	if (!ck) goto fail;

	char* c_name = MEM_ALLOC(strlen(name) + 1);
	char* c_value = MEM_ALLOC(strlen(value) + 1);
	if (!c_name || !c_value) goto fail;
	memcpy(c_name, name, strlen(name));
	memcpy(c_value, value, strlen(value));

	ck->name = c_name;
	ck->value = c_value;

	if (request->cookies) {
		request->cookies = realloc(request->cookies, (request->cookies_count + 1) * sizeof(cookie*));
		if (!request->cookies) goto fail;
	}
	else {
		request->cookies = OBJ_ALLOC(cookie*);
		if (!request->cookies) goto fail;
	}

	request->cookies[request->cookies_count] = ck;
	request->cookies_count++;
	return true;
fail:
	return false;
}

bool http_add_header(http_request* request, char* name, char* value) {
	header* hdr = OBJ_ALLOC(header);
	if (!hdr) goto fail;

	char* h_name = MEM_ALLOC(strlen(name) + 1);
	char* h_value = MEM_ALLOC(strlen(value) + 1);
	if (!h_name || !h_value) goto fail;
	memcpy(h_name, name, strlen(name));
	memcpy(h_value, value, strlen(value));

	hdr->name = h_name;
	hdr->value = h_value;

	if (request->headers) {
		request->headers = realloc(request->headers, (request->headers_count + 1) * sizeof(header*));
		if (!request->headers) goto fail;
	}
	else {
		request->headers = OBJ_ALLOC(header*);
		if (!request->headers) goto fail;
	}

	request->headers[request->headers_count] = hdr;
	request->headers_count++;
	return true;
fail:
	return false;
}