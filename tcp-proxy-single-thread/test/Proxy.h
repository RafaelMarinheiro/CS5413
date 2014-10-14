#ifndef PROXY_H
#define PROXY_H

struct _proxy_data_t;
typedef _proxy_data_t * Proxy_Data_t;

struct _proxy_worker_t;
typedef _proxy_worker_t * Proxy_Worker_t;

typedef int Proxy_Worker_Status_t;

const Proxy_Worker_Status_t PROXY_STATUS_IDLE					= 1;
const Proxy_Worker_Status_t PROXY_STATUS_WORKING				= 2;
const Proxy_Worker_Status_t PROXY_STATUS_WAITING_FOR_SIGNAL  	= 3;
const Proxy_Worker_Status_t PROXY_STATUS_FREE 					= 4;

int Proxy_Create_Data(int server, int client, Proxy_Data_t * data);
int Proxy_Destroy_Data(Proxy_Data_t * data);
int Proxy_Create_Workers(int server, int client, Proxy_Worker_t * master, Proxy_Worker_t * slave);
int Proxy_Destroy_Worker(Proxy_Worker_t worker);

int Proxy_Get_Worker_Id(Proxy_Worker_t worker);

Proxy_Error_t Proxy_Signal_Shutdown(Proxy_Worker_t worker);
Proxy_Error_t Proxy_Signal_Error(Proxy_Worker_t worker, const Proxy_Error_t error);
Proxy_Error_t Proxy_Signal_Close(Proxy_Worker_t worker);
Proxy_Error_t Proxy_Check_Error(Proxy_Worker_t worker);

Proxy_Worker_Status_t Proxy_Get_Worker_Status(Proxy_Worker_t worker);
Proxy_Worker_Status_t Proxy_Set_Worker_Status(Proxy_Worker_t worker, Proxy_Worker_Status_t status);

int Proxy_Wait_For_Other_Worker(Proxy_Worker_t worker);
int Proxy_Get_Sender_Socket(Proxy_Worker_t worker);
int Proxy_Get_Receiver_Socket(Proxy_Worker_t worker);

#endif // PROXY_H
