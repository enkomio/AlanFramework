#define UNICODE
#define _UNICODE

#include <tchar.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include "agent_utility.h"
#include "agent_socks5.h"

#include <WS2tcpip.h>
#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <Windows.h>

int _tWinMain(
	HINSTANCE   hInstance,
	HINSTANCE   hPrevInstance,
	LPTSTR      lpCmdLine,
	int         nCmdShow
) {
	int argc = 0;
	LPWSTR* argv = 0;	
	int result = 0;	
	char* ip_address = ZERO(char);
	char* port = ZERO(char);
	char* username = ZERO(char);
	char* password = ZERO(char);

	argv = CommandLineToArgvW(lpCmdLine, &argc);
	if (argv && argc >= 2) {
		ip_address = unicode_to_ascii(argv[0]);
		port = unicode_to_ascii(argv[1]);		
		if (port && ip_address) {
			if (argc >= 3)
				username = unicode_to_ascii(argv[2]);
			if (argc >= 4)
				password = unicode_to_ascii(argv[3]);

			result = proxy_server_start(ip_address, port, username, password);
		}
		LocalFree(argv);		
	}

	FREE(ip_address);
	FREE(port);
	FREE(username);
	FREE(password);
	return result;
}