#include "Acceptor.h"

#include <stdio.h>
#include <stdlib.h>

#define MAX_THREADS 4
#define MAX_CONNECTIONS 2
#define BUFFER_SIZE 8192
#define TIMEOUT_LIMIT 1


int main(int argc, char ** argv){
	char *remote_name;
	unsigned short local_port, remote_port;
	int arg_idx = 1;
	
	if (argc != 4)
	{
		fprintf(stderr, "Usage %s <remote-target> <remote-target-port> "
			"<local-port>\n", argv[0]);
		exit(1);
	}

	remote_name = argv[arg_idx++];
	remote_port = atoi(argv[arg_idx++]);
	local_port = atoi(argv[arg_idx++]);

	Proxy_Acceptor_t * acceptor = Proxy_Create_Acceptor(remote_name,
													  remote_port, local_port,
													  MAX_CONNECTIONS,
													  BUFFER_SIZE,
													  TIMEOUT_LIMIT,
													  MAX_THREADS);

	return Proxy_Start_Acceptor(acceptor);
}