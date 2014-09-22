#include "Worker.h"
#include "Bridge.h"
#include <pthread.h>

typedef struct{
	pthread_t thread;
	pthread_mutex_t bridge_mutex;

	int max_bridges;


	int current_bridges;
	Proxy_Bridge_t * bridges;
	double * bridge_timeout;
} Proxy_Worker_t;

Proxy_Worker_t * Proxy_Create_Worker(int max_bridges){
	Proxy_Worker_t * ret = malloc(sizeof(Proxy_Worker_t));
	ret->max_bridges = bridges;
	ret->current_bridges = 0;
	ret->bridges = malloc(sizeof(Proxy_Bridge_t *)*max_bridges);
	ret->bridge_timeout = malloc(sizeof(double)*max_bridges);
	pthread_mutex_init(&ret->bridge_mutex, NULL);

	return ret;
}

int Proxy_Destroy_Worker(Proxy_Worker_t * worker){
	pthread_mutex_destroy(&worker->bridge_mutex);
	free(worker->bridge_timeout);
	free(worker->bridges);
	free(worker);
}

void * Proxy_Worker_Thread(void * worker_v){
	//Do the work
}

void Proxy_Start_Worker(Proxy_Worker_t * worker){
	pthread_create(&worker->thread, NULL, Proxy_Worker_Thread, (void*) worker);
}

int Proxy_Remove_Bridge(Proxy_Worker_t * worker, int bridge_id){
	pthread_mutex_lock(&worker->bridge_mutex);
		if(worker->current_bridges > 0){
			unsigned int new_end = (worker->current_bridges - 1);
			worker->bridges[bridge_id] = worker->bridges[new_end];
			worker->bridge_timeout[bridge_id] = worker->bridge_timeout[new_end];
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
			worker->bridge_timeout[id] = 0;
			worker->current_bridges++;

			added = 1;
		}
	pthread_mutex_unlock(&worker->bridge_mutex);
	return added;
}