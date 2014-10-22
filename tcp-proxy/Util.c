#include "Util.h"

#include <stdlib.h>

Proxy_Buffer_t * Proxy_Create_Buffer(int size){
	Proxy_Buffer_t * ret = malloc(sizeof(Proxy_Buffer_t));
	ret->data = malloc(size*sizeof(char));
	ret->begin = 0;
	ret->end = 0;
	ret->size = size;
	return ret;
}

int Proxy_Destroy_Buffer(Proxy_Buffer_t * buffer){
	free(buffer->data);
	free(buffer);
	return 0;
}