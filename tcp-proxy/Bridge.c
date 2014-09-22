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
	ret->timeout = timeout;
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

	//Is sending/reading?
	int reading[2];
	reading[0] = reading[1] = 1;
	//Miliseconds to timeout
	double miliseconds_timeout[2];
	miliseconds_timeout[0] = miliseconds_timeout[1] = bridge->timeout*1000.0;

	//Reading sockets
	int read_socket[2];
	read_socket[0] = bridge->sockets[0]; read_socket[1] = bridge->sockets[1];
	int send_socket[2];
	send_socket[0] = bridge->sockets[1]; send_socket[1] = bridge->sockets[0];

	struct timeval timed_t;      
    timed_t.tv_sec = 5;
    timed_t.tv_usec = 0;
	setsockopt(send_socket[0], SOL_SOCKET, SO_SNDTIMEO, (char *)&timed_t, sizeof(timed_t));
	timed_t.tv_sec = 5;
    timed_t.tv_usec = 0;
	setsockopt(send_socket[1], SOL_SOCKET, SO_SNDTIMEO, (char *)&timed_t, sizeof(timed_t));

	//Buffer
	char * wholeBuffer = malloc(bridge->buffer_size*2*sizeof(char));
	char * buffer[2];
	buffer[0] = wholeBuffer;
	buffer[1] = wholeBuffer + bridge->buffer_size;

	unsigned int buffer_recv_position[2];
	unsigned int buffer_send_position[2];
	buffer_recv_position[0] = buffer_recv_position[1] = 0;
	buffer_send_position[0] = buffer_send_position[1] = 0;
	unsigned int buffer_size = bridge->buffer_size;
	
	int keepGoing = 1;
	
	fd_set socket_set;
	while(keepGoing){
		FD_ZERO(&socket_set);
		int i;
		int maxi = -1;
		for(i = 0; i < 2; i++){
			int space_left = buffer_size-buffer_recv_position[i];
			if(read_socket[i] > maxi) maxi = read_socket[i];
			if(reading[i] && space_left > 0) FD_SET(read_socket[i], &socket_set);
		}
		//Recv
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		int e = select(maxi+1, &socket_set, NULL, NULL, &tv);
		for(i = 0; i < 2; i++){
			if(FD_ISSET(read_socket[i], &socket_set)){
				// printf("READING %d\n", read_socket[i]);
				int bytes = recv(read_socket[i], buffer[i]+buffer_recv_position[i], buffer_size-buffer_recv_position[i], 0);
				// printf("READ %d\n", read_socket[i]);
				
				if(bytes > 0){
					buffer_recv_position[i] += bytes;
				} else if(bytes == 0){
					//Shutdown requested
					reading[i] = 0;
				} else{
					//Read error
					reading[i] = 0;
				}
			}
		}

		//Send
		maxi = -1;
		int anyInside = 0;
		FD_ZERO(&socket_set);
		for(i = 0; i < 2; i++){
			int bytes_to_send = buffer_recv_position[i]-buffer_send_position[i];
			if(send_socket[i] > maxi) maxi = send_socket[i];
			if(bytes_to_send > 0){
				FD_SET(send_socket[i], &socket_set);
			}
		}

		struct timeval begin;
		gettimeofday(&begin, NULL);

		tv.tv_sec = 1;
		tv.tv_usec = 0;
		// printf("Pre-send select\n");
		e = select(maxi+1, NULL, &socket_set, NULL, &tv);
		// printf("Post-send select %d %s\n", e, strerror(errno));

		struct timeval end;
		gettimeofday(&end, NULL);

		double timePassed = (end.tv_sec - begin.tv_sec)*1000.0 + (end.tv_usec - begin.tv_usec)/1000.0; 

		for(i = 0; i < 2; i++){
			int sent_something = 0;
			double thistime = 0;
			if(FD_ISSET(send_socket[i], &socket_set)){
				// printf("SENDING %d %d\n", send_socket[i], buffer_recv_position[i]);
				gettimeofday(&begin, NULL);
				int bytes = send(send_socket[i], buffer[i]+buffer_send_position[i], buffer_recv_position[i]-buffer_send_position[i], 0);
				gettimeofday(&end, NULL);
				thistime = (end.tv_sec - begin.tv_sec)*1000.0 + (end.tv_usec - begin.tv_usec)/1000.0;
				// printf("SENT %d\n", send_socket[i]);
				fflush(stdout);
				
				if(bytes > 0){
					buffer_send_position[i] += bytes;
					sent_something = 1;
				} else if(bytes == 0){
					//Nothing
				} else {
					bridge->error = PROXY_ERROR_WRITE_ERROR;
					break;
				}

			}

			if(buffer_send_position[i] == buffer_recv_position[i]){
				buffer_send_position[i] = buffer_recv_position[i] = 0;
			}

			if(buffer_recv_position[i] == 0){
				if(reading[i] == 0){
					shutdown(send_socket[i], SHUT_WR);
				}
			}

			if(sent_something){
				miliseconds_timeout[i] = bridge->timeout*1000.0;
			} else if(buffer_recv_position[i] > 0){
				//There is still data to send
				miliseconds_timeout[i] -= timePassed + thistime;
				if(miliseconds_timeout[i] < 0){
					// printf("TIMEOUT\n");
					bridge->error = PROXY_ERROR_TIMEOUT;
					break;
				}
			}
		}
		keepGoing = 0;
		for(i = 0; i < 2; i++){
			if(reading[i] != 0 || buffer_recv_position[i] != 0){
				keepGoing = 1;
			}
		}

		if(bridge->error != PROXY_ERROR_SUCCESS){
			keepGoing = 0;
		}
	}
	free(wholeBuffer);
	Proxy_Close_Bridge(bridge);
	Proxy_Destroy_Bridge(bridge);
	return 0;
}

Proxy_Error_t Proxy_Check_Bridge_Error(Proxy_Bridge_t * bridge){
	return bridge->error;
}