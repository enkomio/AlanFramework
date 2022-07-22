#include <stdbool.h>
#include "agent_network.h"
#include "agent_utility.h"

#include <WS2tcpip.h>
#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")

bool network_initialize(void)
{
	WSADATA d = { 0 };
	return !WSAStartup(MAKEWORD(2, 2), &d);
}

void network_close(void)
{
	WSACleanup();
}