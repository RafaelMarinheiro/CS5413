#ifndef BRIDGE_H
#define BRIDGE_H

#include "Acceptor.h"
#include "Util.h"

typedef struct{
	Proxy_Acceptor_t acceptor;
	Proxy_Buffer_t * buffer[2];
	int timeout;
	int sockets[2];
	Proxy_Error_t error;
} Proxy_Bridge_t;


Proxy_Bridge_t * Proxy_Create_Bridge(Proxy_Acceptor_t * acceptor,
								     int clientSocket, int serverSocket,
								     unsigned int bufferSize, int timeout);

int Proxy_Destroy_Bridge(Proxy_Bridge_t * bridge);
int Proxy_Open_Bridge(Proxy_Bridge_t * bridge);

#endif // BRIDGE_H
