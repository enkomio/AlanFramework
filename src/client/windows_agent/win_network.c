#include <stdbool.h>
#include "agent_network.h"
#include "agent_utility.h"

#include <WS2tcpip.h>
#include <WinSock2.h>
#include <winhttp.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Winhttp.lib")

bool network_initialize(void)
{
	WSADATA d = { 0 };
	return !WSAStartup(MAKEWORD(2, 2), &d);
}

void network_close(void)
{
	WSACleanup();
}

bool proxy_get_system_http_proxy(char** address)
{
	WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxy_info = { 0 };
	bool result;
	result = WinHttpGetIEProxyConfigForCurrentUser(&proxy_info);
	if (result) {		
		*address = unicode_to_ascii(proxy_info.lpszProxy);
		if (proxy_info.lpszProxy) GlobalFree(proxy_info.lpszProxy);
		if (proxy_info.lpszProxyBypass) GlobalFree(proxy_info.lpszProxyBypass);
		if (proxy_info.lpszAutoConfigUrl) GlobalFree(proxy_info.lpszAutoConfigUrl);
	}
	return result;
}