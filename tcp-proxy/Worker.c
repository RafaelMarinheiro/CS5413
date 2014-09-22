#include "Worker.h"
#include "Bridge.h"
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>

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

struct _proxy_worker_t{
	pthread_t thread;
	pthread_mutex_t bridge_mutex;

	int max_bridges;

	int current_bridges;
	Proxy_Bridge_t ** bridges;
};

Proxy_Worker_t * Proxy_Create_Worker(int max_bridges){
	Proxy_Worker_t * ret = malloc(sizeof(Proxy_Worker_t) * 1);
	ret->max_bridges = max_bridges;
	ret->current_bridges = 0;
	ret->bridges = malloc(sizeof(Proxy_Bridge_t *)*max_bridges);
	pthread_mutex_init(&ret->bridge_mutex, NULL);

	return ret;
}

int Proxy_Destroy_Worker(Proxy_Worker_t * worker){
	pthread_mutex_destroy(&worker->bridge_mutex);
	free(worker->bridges);
	free(worker);
}

void Proxy_Start_Worker(Proxy_Worker_t * worker){
	pthread_create(&worker->thread, NULL, Proxy_Worker_Thread, (void*) worker);
}

int Proxy_Remove_Bridge(Proxy_Worker_t * worker, int bridge_id){
	pthread_mutex_lock(&worker->bridge_mutex);
		if(worker->current_bridges > 0){
			unsigned int new_end = (worker->current_bridges - 1);
			worker->bridges[bridge_id] = worker->bridges[new_end];
			worker->current_bridges--;
		}
	pthread_mutex_unlock(&worker->bridge_mutex);
}

int Proxy_Try_Add_Bridge(Proxy_Worker_t * worker, Proxy_Bridge_t * bridge){
	int added = 0;
	pthread_mutex_lock(&worker->bridge_mutex);
		if(worker->current_bridges < worker->max_bridges){
			int id = worker->current_bridges;
			worker->bridges[id] = bridge;
			worker->current_bridges++;
			added = 1;
		}
	pthread_mutex_unlock(&worker->bridge_mutex);
	return added;
}

void * Proxy_Worker_Thread(void * worker_v){
	Proxy_Worker_t * worker = (Proxy_Worker_t *) worker_v;
	fd_set socket_set;

	while(1){

		// printf("CURRENT BRIDGES %d\n", worker->current_bridges);
		if(worker->current_bridges == 0){
			//Kinda Hacky
			//Should I use some kind of condition variable?
			sleep(1);
			continue;
		}
		
		//////////////////////////
		//recv
		//////////////////////////
		// printf("RECV\n");
		FD_ZERO(&socket_set);

		int i,j;
		int maxi = -1;
		for(i = 0; i < worker->current_bridges; i++){
			Proxy_Bridge_t * bridge = worker->bridges[i];
			for(j = 0; j < 2; j++){
				int space_left = bridge->buffer[j]->size - bridge->buffer[j]->end;
				if(bridge->sockets[j] > maxi) maxi = bridge->sockets[j];
				if(bridge->reading[j] && space_left > 0){
					FD_SET(bridge->sockets[j], &socket_set);
					// printf("ADDING RECV %d\n", bridge->sockets[j]);
				}
			}
		}

		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		int e = select(maxi+1, &socket_set, NULL, NULL, &tv);
		for(i = 0; i < worker->current_bridges; i++){
			Proxy_Bridge_t * bridge = worker->bridges[i];
			for(j = 0; j < 2; j++){
				if(FD_ISSET(bridge->sockets[j], &socket_set)){
					Proxy_Buffer_t * buffer = bridge->buffer[j];
					int space_left = buffer->size - buffer->end;
					// printf("RECV FROM %d\n", bridge->sockets[j]);
					int bytes = recv(bridge->sockets[j], buffer->data + buffer->end, space_left, 0);

					if(bytes > 0){
						buffer->end += bytes;
					} else if(bytes == 0){
						bridge->reading[j] = 0;
					} else{
						bridge->reading[j] = 0;
					}
				}
			}
		}


		/////////////////////////
		//send
		/////////////////////////
		FD_ZERO(&socket_set);

		maxi = -1;
		for(i = 0; i < worker->current_bridges; i++){
			Proxy_Bridge_t * bridge = worker->bridges[i];
			for(j = 0; j < 2; j++){
				int other = 1-j;
				int to_send = bridge->buffer[other]->end - bridge->buffer[other]->begin;
				if(bridge->sockets[j] > maxi) maxi = bridge->sockets[j];
				if(to_send > 0) FD_SET(bridge->sockets[j], &socket_set);
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
	
		for(i = 0; i < worker->current_bridges; i++){
			Proxy_Bridge_t * bridge = worker->bridges[i];
			for(j = 0; j < 2; j++){
				int bytes = 0;
				double thistime = 0;
				Proxy_Buffer_t * buffer = bridge->buffer[1-j];
				if(FD_ISSET(bridge->sockets[j], &socket_set) && bridge->error == PROXY_ERROR_SUCCESS){
					int to_send = buffer->end - buffer->begin;

					gettimeofday(&begin, NULL);
					bytes = send(bridge->sockets[j], buffer->data + buffer->begin, to_send, 0);
					gettimeofday(&end, NULL);
					thistime = (end.tv_sec - begin.tv_sec)*1000.0 + (end.tv_usec - begin.tv_usec)/1000.0;

					if(bytes > 0){
						buffer->begin += bytes;
					} else if(bytes == 0){
						//Nothing
					} else{
						bridge->error = PROXY_ERROR_WRITE_ERROR;
						continue;
					}
				}

				if(buffer->begin == buffer->end){
					buffer->begin = buffer->end = 0;
				}

				if(buffer->end == 0 && bridge->reading[1-j] == 0){
					shutdown(bridge->sockets[j], SHUT_WR);
				}

				if(bytes > 0){
					bridge->time_clock[j] = bridge->timeout*1000.0;
				} else if(buffer->end > 0){
					bridge->time_clock[j] -= timePassed + thistime;
					if(bridge->time_clock[j] < 0){
						bridge->error = PROXY_ERROR_TIMEOUT;
					}
				}
			}
		}

		/////////////////////
		// Clean-up
		/////////////////////

		for(i = 0; i < worker->current_bridges; i++){
			int alive = 0;
			Proxy_Bridge_t * bridge = worker->bridges[i];
			for(j = 0; j < 2; j++){
				if(bridge->reading[j] != 0 || bridge->buffer[j]->end != 0){
					alive = 1;
				}
			}

			if(bridge->error != PROXY_ERROR_SUCCESS){
				alive = 0;
			}

			if(!alive){
				Proxy_Close_Bridge(bridge);
				Proxy_Destroy_Bridge(bridge);
				Proxy_Remove_Bridge(worker, i);
				i = i-1;
			}
		}
	}

	pthread_exit(NULL);
}
