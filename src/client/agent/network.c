#include <string.h>
#include "agent_network.h"
#include "agent_utility.h"

proxy* proxy_new(char* address, uint32_t port, char* username, char* password)
{
	proxy* p = OBJ_ALLOC(proxy);
	if (p) {
		p->address = _strdup(address);
		p->port = port;
		p->username = _strdup(username);
		p->password = _strdup(password);
	}
	return p;
}

void proxy_free(proxy* p)
{
	if (p) {
		FREE(p->address);
		FREE(p->username);
		FREE(p->password);
		FREE(p);
	}
}