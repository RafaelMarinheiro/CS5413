#include "Acceptor.h"
#include "Bridge.h"
#include "Worker.h"

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
#include <semaphore.h>

const Proxy_Error_t PROXY_ERROR_SUCCESS 		= 0;
const Proxy_Error_t PROXY_ERROR_TIMEOUT 		= 1;
const Proxy_Error_t PROXY_ERROR_WRITE_ERROR 	= 2;

struct _proxy_acceptor_t{
	char * remote_name;
	unsigned short remote_port;
	unsigned short local_port;
	sem_t connection_semaphore;
	unsigned int buffer_size;
	int timeout_limit;

	//Workers

	int num_workers;
	Proxy_Worker_t ** workers;
};

Proxy_Acceptor_t * Proxy_Create_Acceptor(char * remote_name, unsigned short remote_port, unsigned short local_port,
									     unsigned int max_connections, unsigned int buffer_size, int timeout_limit,
									     unsigned int max_threads){
	Proxy_Acceptor_t * ret = malloc(sizeof(Proxy_Acceptor_t));

	ret->remote_name = remote_name;
	ret->remote_port = remote_port;
	ret->local_port  = local_port;
	ret->buffer_size = buffer_size;
	ret->timeout_limit = timeout_limit;
	ret->num_workers = max_connections;

	if(max_connections > max_threads){
		ret->num_workers = max_threads;
	}

	ret->workers = malloc(sizeof(Proxy_Worker_t *) * ret->num_workers);

	int per_worker = max_connections/ret->num_workers;
	int rest = max_connections%ret->num_workers;

	int i;
	for(i = 0; i < ret->num_workers; i++){
		ret->workers[i] = Proxy_Create_Worker(per_worker + (rest > 0 ? 1 : 0));
		rest--;
	}

	sem_init(&ret->connection_semaphore, 0, max_connections);

	return ret;
}

int Proxy_Destroy_Acceptor(Proxy_Acceptor_t * acceptor){
	sem_destroy(&(acceptor->connection_semaphore));
	int i;

	for(i = 0; i < acceptor->num_workers; i++){
		Proxy_Destroy_Worker(acceptor->workers[i]);
	}
	free(acceptor->workers);
	free(acceptor);
	return 0;
}

int Proxy_Notify_Connection_Closed(Proxy_Acceptor_t * acceptor, Proxy_Error_t error){
	printf("Connection closed\n");
	sem_post(&(acceptor->connection_semaphore));
	return 0;
}

int Proxy_Start_Acceptor(Proxy_Acceptor_t * acceptor){
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

	// printf("Listening on port %d\n", acceptor->local_port);
	int worker_id;
	for(worker_id = 0; worker_id < acceptor->num_workers; worker_id++){
		Proxy_Start_Worker(acceptor->workers[worker_id]);
	}

	//Loop
	while(1){
		// printf("HI\n");
		// int value; 
	 //    int e = sem_getvalue(&(acceptor->connection_semaphore), &value); 
	 //    printf("The value of the semaphore is %d %d\n", value, e);
	 //    fprintf(stderr, "error %s\n", strerror(errno));
		sem_wait(&(acceptor->connection_semaphore));
		// printf("PASSEI\n");

		memset(&client_addr, 0, sizeof(struct sockaddr_in));
		addr_size = sizeof(client_addr);

		client_socket = accept(proxy_fd, (struct sockaddr *)&client_addr,
					&addr_size);

		printf("Connection accepted\n");

		if(client_socket == -1){
			fprintf(stderr, "accept error %s\n", strerror(errno));
			sem_post(&(acceptor->connection_semaphore));
			continue;
		}

		// // For debugging purpose
		// if (getpeername(client_socket, (struct sockaddr *) &client_addr, &addr_size) < 0) {
		// 	fprintf(stderr, "getpeername error %s\n", strerror(errno));
		// }

		// strncpy(client_hname, inet_ntoa(client_addr.sin_addr), MAX_ADDR_NAME);
		// strncpy(server_hname, inet_ntoa(remote_addr.sin_addr), MAX_ADDR_NAME);

		// // TODO: Disable following printf before submission
		// printf("Connection proxied: %s:%d --> %s:%d\n",
		// 		client_hname, ntohs(client_addr.sin_port),
		// 		server_hname, ntohs(remote_addr.sin_port));

		if((server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
			fprintf(stderr, "socket error %s\n", strerror(errno));
			close(client_socket);
			sem_post(&(acceptor->connection_semaphore));
			continue;
		}

		if (connect(server_socket, (struct sockaddr *) &remote_addr, 
			sizeof(struct sockaddr_in)) <0) {
			if (errno != EINPROGRESS) {
				fprintf(stderr, "connect error %s\n", strerror(errno));
				close(client_socket);
				close(server_socket);
				sem_post(&(acceptor->connection_semaphore));
				continue;
			}		
		}

		Proxy_Bridge_t * bridge = Proxy_Create_Bridge(acceptor,
													  client_socket, server_socket,
													  acceptor->buffer_size, acceptor->timeout_limit);

		//Assign the Bridge to a Worker
		int i;
		int found = 0;
		for(i = 0; i < acceptor->num_workers && found == 0; i++){
			if(Proxy_Try_Add_Bridge(acceptor->workers[i], bridge)){
				found = 1;
			}
		}

		if(found == 0){
			Proxy_Close_Bridge(bridge);
			Proxy_Destroy_Bridge(bridge);
		}
	}

	Proxy_Destroy_Acceptor(acceptor);
}

