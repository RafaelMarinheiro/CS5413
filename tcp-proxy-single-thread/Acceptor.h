#ifndef ACCEPTOR_H
#define ACCEPTOR_H

#define MAX_LISTEN_BACKLOG 5
#define MAX_ADDR_NAME	32

struct _proxy_acceptor_t;
typedef struct _proxy_acceptor_t * Proxy_Acceptor_t;

typedef int Proxy_Error_t;

extern const Proxy_Error_t PROXY_ERROR_SUCCESS;
extern const Proxy_Error_t PROXY_ERROR_TIMEOUT;
extern const Proxy_Error_t PROXY_ERROR_WRITE_ERROR;

Proxy_Acceptor_t Proxy_Create_Acceptor(char * remote_name, unsigned short remote_port, unsigned short local_port,
									   unsigned int max_connections, unsigned int buffer_size, int timeout_limit);

int Proxy_Destroy_Acceptor(Proxy_Acceptor_t acceptor);

int Proxy_Start_Acceptor(Proxy_Acceptor_t acceptor);
int Proxy_Notify_Connection_Closed(Proxy_Acceptor_t acceptor, Proxy_Error_t error);

#endif // ACCEPTOR_H
