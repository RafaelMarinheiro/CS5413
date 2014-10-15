#include "Proxy.h"

#include <stdlib.h>
#include <semaphore.h>
#include <pthread.h>

struct _proxy_data_t{
	int clientSocket;
	int serverSocket;
	Proxy_Error_t error;

	sem_t signal[2];
	pthread_mutex_t lock;
};

struct _proxy_worker_t{
	int id;
	Proxy_Worker_Status_t status;
	Proxy_Data_t proxyData;
};

int Proxy_Create_Data(int server, int client, Proxy_Data_t * data){
	Proxy_Data_t proxyData = (Proxy_Data_t) malloc(sizeof(_proxy_data_t));
	proxyData->clientSocket = client;
	proxyData->serverSocket = server;
	proxyData->error = PROXY_ERROR_SUCCESS;
	sem_init(&(proxyData->signal[0]), 0, 0);
	sem_init(&(proxyData->signal[1]), 0, 0);
	pthread_mutex_init(&(proxyData->lock), NULL);
	*data = proxyData;
	return 0;
}

int Proxy_Destroy_Data(Proxy_Data_t data){
	sem_destroy(&(data->signal[0]));
	sem_destroy(&(data->signal[1]));
	pthread_mutex_destroy(&(proxyData->lock));
	free(data);
	return 0;
}

int Proxy_Create_Workers(int server, int client, Proxy_Worker_t * master, Proxy_Worker_t * slave){
	Proxy_Data_t proxyData;
	Proxy_Create_Data(server, client, &proxyData);
	*master = (Proxy_Worker_t) malloc(sizeof(_proxy_worker_t));
	*slave  = (Proxy_Worker_t) malloc(sizeof(_proxy_worker_t));

	(*master)->id = 0;
	(*master)->status = PROXY_STATUS_IDLE;
	(*master)->proxyData = proxyData;
	(*slave)->id = 1;
	(*slave)->status = PROXY_STATUS_IDLE;
	(*slave)->proxyData = proxyData;

	return 0;
}

int Proxy_Destroy_Worker(Proxy_Worker_t worker){
	int id = worker->id;
	if(id == 0){
		Proxy_Destroy_Data(worker->proxyData);
	}
}

Proxy_Error_t Proxy_Signal_Error(Proxy_Worker_t worker, const Proxy_Error_t error){
	int id = worker->id;
	int final_error = 0;
	pthread_mutex_lock(&(worker->proxyData->lock));
		if(error > worker->proxyData->error){
			worker->proxyData->error = error;
		}
		final_error = worker->proxyData->error;
		sem_post(&(worker->proxyData->signal[id]));
	pthread_mutex_unlock(&(worker->proxyData->lock));
	return final_error;
}

Proxy_Error_t Proxy_Signal_Shutdown(Proxy_Worker_t worker){
	return Proxy_Signal_Error(worker, 0);
}

Proxy_Error_t Proxy_Signal_Close(Proxy_Worker_t worker){
	return Proxy_Signal_Shutdown(worker);
}

Proxy_Error_t Proxy_Check_Error(Proxy_Worker_t worker){
	return worker->proxyData->error;
}

int Proxy_Wait_For_Other_Worker(Proxy_Worker_t worker){
	int my_id = worker->id;
	int other_id = 1-my_id;
	sem_wait(&(worker->proxyData->signal[other_id]));
	return 0;
}

int Proxy_Get_Sender_Socket(Proxy_Worker_t worker){
	int my_id = worker->id;
	if(my_id == 0){
		return worker->proxyData->clientSocket;
	} else{
		return worker->proxyData->serverSocket;
	}
}

int Proxy_Get_Receiver_Socket(Proxy_Worker_t worker){
	int my_id = worker->id;
	if(my_id == 0){
		return worker->proxyData->serverSocket;
	} else{
		return worker->proxyData->clientSocket;
	}
}





