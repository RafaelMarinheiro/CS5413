#include "Acceptor.h"
#include "Bridge.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
// #include <semaphore.h>

const Proxy_Error_t PROXY_ERROR_SUCCESS 		= 0;
const Proxy_Error_t PROXY_ERROR_TIMEOUT 		= 1;
const Proxy_Error_t PROXY_ERROR_WRITE_ERROR 	= 2;

struct _proxy_acceptor_t{
	char * remote_name;
	unsigned short remote_port;
	unsigned short local_port;
	// sem_t connection_semaphore;
	unsigned int buffer_size;
	int timeout_limit;
};

Proxy_Acceptor_t Proxy_Create_Acceptor(char * remote_name, unsigned short remote_port, unsigned short local_port,
									   unsigned int max_connections, unsigned int buffer_size, int timeout_limit){
	Proxy_Acceptor_t ret = malloc(sizeof(struct _proxy_acceptor_t));

	ret->remote_name = remote_name;
	ret->remote_port = remote_port;
	ret->local_port  = local_port;
	ret->buffer_size = buffer_size;
	ret->timeout_limit = timeout_limit;
	// sem_init(&(ret->connection_semaphore), 0, max_connections);

	return ret;
}

int Proxy_Destroy_Acceptor(Proxy_Acceptor_t acceptor){
	// sem_destroy(&(acceptor->connection_semaphore));
	free(acceptor);
	return 0;
}

int Proxy_Notify_Connection_Closed(Proxy_Acceptor_t acceptor, Proxy_Error_t error){
	// sem_post(&(acceptor->connection_semaphore));
	// printf("Connection closed\n");
	return 0;
}

int Proxy_Start_Acceptor(Proxy_Acceptor_t acceptor){
	struct sockaddr_in remote_addr;
	struct sockaddr_in proxy_addr;
	struct sockaddr_in client_addr;
	char client_hname[MAX_ADDR_NAME+1];
	char server_hname[MAX_ADDR_NAME+1];
	socklen_t addr_size;
	struct hostent *h;
	int proxy_fd;

	int client_socket, server_socket;

	/* Lookup server name and establish control connection */
	if ((h = gethostbyname(acceptor->remote_name)) == NULL) {
		fprintf(stderr, "gethostbyname(%s) failed %s\n", acceptor->remote_name, 
			strerror(errno));
		return 1;
	}

	memset(&remote_addr, 0, sizeof(struct sockaddr_in));
	remote_addr.sin_family = AF_INET;
	memcpy(&remote_addr.sin_addr.s_addr, h->h_addr_list[0], sizeof(in_addr_t));
	remote_addr.sin_port = htons(acceptor->remote_port);
	
	/* open up the TCP socket the proxy listens on */
	if ((proxy_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		fprintf(stderr, "socket error %s\n", strerror(errno));
		return 1;
	}
	/* bind the socket to all local addresses */
	memset(&proxy_addr, 0, sizeof(struct sockaddr_in));
	proxy_addr.sin_family = AF_INET;
	proxy_addr.sin_addr.s_addr = INADDR_ANY; /* bind to all local addresses */
	proxy_addr.sin_port = htons(acceptor->local_port);

	int yes;

	// lose the pesky "address already in use" error message
    setsockopt(proxy_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

	if (bind(proxy_fd, (struct sockaddr *) &proxy_addr, 
			sizeof(proxy_addr)) < 0) {
		fprintf(stderr, "bind error %s\n", strerror(errno));
		return 1;
	}

	listen(proxy_fd, MAX_LISTEN_BACKLOG);

	printf("Listening on port %d\n", acceptor->local_port);

	//Loop
	while(1){
		// printf("HI\n");
		int value; 
	    // int e = sem_getvalue(&(acceptor->connection_semaphore), &value); 
	    // printf("The value of the semaphors is %d %d\n", value, e);
		// sem_wait(&(acceptor->connection_semaphore));

		memset(&client_addr, 0, sizeof(struct sockaddr_in));
		addr_size = sizeof(client_addr);

		client_socket = accept(proxy_fd, (struct sockaddr *)&client_addr,
					&addr_size);

		if(client_socket == -1){
			fprintf(stderr, "accept error %s\n", strerror(errno));
			continue;
		}

		// For debugging purpose
		if (getpeername(client_socket, (struct sockaddr *) &client_addr, &addr_size) < 0) {
			fprintf(stderr, "getpeername error %s\n", strerror(errno));
		}

		strncpy(client_hname, inet_ntoa(client_addr.sin_addr), MAX_ADDR_NAME);
		strncpy(server_hname, inet_ntoa(remote_addr.sin_addr), MAX_ADDR_NAME);

		// TODO: Disable following printf before submission
		printf("Connection proxied: %s:%d --> %s:%d\n",
				client_hname, ntohs(client_addr.sin_port),
				server_hname, ntohs(remote_addr.sin_port));

		if((server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
			fprintf(stderr, "socket error %s\n", strerror(errno));
			close(client_socket);
			continue;
		}

		if (connect(server_socket, (struct sockaddr *) &remote_addr, 
			sizeof(struct sockaddr_in)) <0) {
			if (errno != EINPROGRESS) {
				fprintf(stderr, "connect error %s\n", strerror(errno));
				close(client_socket);
				close(server_socket);
				continue;
			}		
		}

		Proxy_Bridge_t bridge = Proxy_Create_Bridge(acceptor,
													client_socket, server_socket,
													acceptor->buffer_size, acceptor->timeout_limit);

		Proxy_Open_Bridge(bridge);
		// printf("KTHXBIE\n");
	}
}

