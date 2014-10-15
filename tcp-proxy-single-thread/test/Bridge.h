#ifndef BRIDGE_H
#define BRIDGE_H

#include "Acceptor.h"

struct _proxy_bridge_t;
typedef struct _proxy_bridge_t * Proxy_Bridge_t;

Proxy_Bridge_t Proxy_Create_Bridge(Proxy_Acceptor_t acceptor,
								   int clientSocket, int serverSocket,
								   unsigned int bufferSize, int timeout);

int Proxy_Destroy_Bridge(Proxy_Bridge_t bridge);
int Proxy_Open_Bridge(Proxy_Bridge_t bridge);

#endif // BRIDGE_H
