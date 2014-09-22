#ifndef UTIL_H
#define UTIL_H

typedef struct{
	unsigned int size;
	unsigned int begin;
	unsigned int end;
	char * data;
} Proxy_Buffer_t;

Proxy_Buffer_t * Proxy_Create_Buffer(int size);
int Proxy_Destroy_Buffer(Proxy_Buffer_t * buffer);

#endif // UTIL_H
