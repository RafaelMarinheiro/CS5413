#ifndef WORKER_H
#define WORKER_H

struct _proxy_worker_t;
typedef struct _proxy_worker_t Proxy_Worker_t;

Proxy_Worker_t * Proxy_Create_Worker(int max_bridges);
int Proxy_Destroy_Worker(Proxy_Worker_t * worker);

void * Proxy_Worker_Thread(void * worker);

void Proxy_Start_Worker(Proxy_Worker_t * worker);

int Proxy_Try_Add_Bridge(Proxy_Worker_t * worker, Proxy_Bridge_t * bridge);

#endif