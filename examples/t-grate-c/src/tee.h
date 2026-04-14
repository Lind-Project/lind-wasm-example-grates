#ifndef TEE_H
#define TEE_H

#include <semaphore.h>

typedef struct TeeState {
    int primary_target;
    int secondary_target;
    sem_t *exiting;
    sem_t *primary_done; 
    sem_t *secondary_done;
} TeeState;

extern TeeState TEESTATE;

#endif
