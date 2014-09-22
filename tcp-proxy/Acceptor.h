#ifndef ACCEPTOR_H
#define ACCEPTOR_H

#define MAX_LISTEN_BACKLOG 5
#define MAX_ADDR_NAME	32

#include "Worker.h"

typedef int Proxy_Error_t;

extern const Proxy_Error_t PROXY_ERROR_SUCCESS;
extern const Proxy_Error_t PROXY_ERROR_TIMEOUT;
extern const Proxy_Error_t PROXY_ERROR_WRITE_ERROR;

typedef struct{
	char * remote_name;
	unsigned short remote_port;
	unsigned short local_port;
	sem_t connection_semaphore;
	unsigned int buffer_size;
	int timeout_limit;

	//Workers

	int num_workers;
	Proxy_Worker_t * workers;
} Proxy_Acceptor_t;

Proxy_Acceptor_t * Proxy_Create_Acceptor(char * remote_name, unsigned short remote_port, unsigned short local_port,
									     unsigned int max_connections, unsigned int buffer_size, int timeout_limit,
									     unsigned int max_threads);

int Proxy_Destroy_Acceptor(Proxy_Acceptor_t * acceptor);

int Proxy_Start_Acceptor(Proxy_Acceptor_t * acceptor);
int Proxy_Notify_Connection_Closed(Proxy_Acceptor_t * acceptor, Proxy_Error_t error);

#endif // ACCEPTOR_H
