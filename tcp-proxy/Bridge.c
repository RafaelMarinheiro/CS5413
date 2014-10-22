#include "Bridge.h"

#include <pthread.h>
#include <semaphore.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>

Proxy_Bridge_t * Proxy_Create_Bridge(Proxy_Acceptor_t * acceptor,
								     int clientSocket, int serverSocket,
								     unsigned int buffer_size, int timeout){
	Proxy_Bridge_t * ret = malloc(sizeof(Proxy_Bridge_t));
	ret->acceptor = acceptor;
	ret->sockets[0] = clientSocket;
	ret->sockets[1] = serverSocket;
	ret->buffer[0] = Proxy_Create_Buffer(buffer_size);
	ret->buffer[1] = Proxy_Create_Buffer(buffer_size);
	ret->reading[0] = ret->reading[1] = 1;
	ret->timeout = timeout;
	ret->time_clock[0] = ret->time_clock[1] = ret->timeout*1000.0;;
	ret->error = PROXY_ERROR_SUCCESS;

	return ret;
}

int Proxy_Destroy_Bridge(Proxy_Bridge_t * bridge){
	Proxy_Destroy_Buffer(bridge->buffer[0]);
	Proxy_Destroy_Buffer(bridge->buffer[1]);
	free(bridge);
	return 0;
}

int Proxy_Close_Bridge(Proxy_Bridge_t * bridge){
	close(bridge->sockets[0]);
	close(bridge->sockets[1]);
	Proxy_Notify_Connection_Closed(bridge->acceptor, bridge->error);
	return 0;
}

int Proxy_Open_Bridge(Proxy_Bridge_t * bridge){
	return 0;
}

Proxy_Error_t Proxy_Check_Bridge_Error(Proxy_Bridge_t * bridge){
	return bridge->error;
}