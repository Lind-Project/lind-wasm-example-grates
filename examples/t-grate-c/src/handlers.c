#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include <lind_syscall.h>

#include "tee.h"

int exec_handler(
	uint64_t cageid, 
	uint64_t arg1, uint64_t arg1cage,
	uint64_t arg2, uint64_t arg2cage,
	uint64_t arg3, uint64_t arg3cage,
	uint64_t arg4, uint64_t arg4cage,
	uint64_t arg5, uint64_t arg5cage,
	uint64_t arg6, uint64_t arg6cage
) {
	uint64_t tee_cage = cageid;
	char buf[256];

	copy_data_between_cages(tee_cage, arg1cage, arg1, arg1cage, (uint64_t)buf, tee_cage, 256, 0);

	printf("[t-grate] exec path: %s\n", buf);
	if (strcmp(buf, "%}") == 0) {
		printf("[t-grate] %%} detected.\n");
		if(TEESTATE.primary_target == -1) {
			TEESTATE.primary_target = arg1cage;
			sem_post(TEESTATE.primary_done);
			printf("[t-grate] primary_target init'd. %d\n", TEESTATE.primary_target);
		} else {
			TEESTATE.secondary_target = arg1cage;
			sem_post(TEESTATE.secondary_done);
			printf("[t-grate] secondary_target init'd. %d\n", TEESTATE.secondary_target);
		}

		while(1) {}

		/*
		return make_threei_call(
			59, 
			0, 
			tee_cage,
			arg1cage,
			arg1, arg1cage, 
			arg2, arg2cage, 
			arg3, arg3cage, 
			arg4, arg4cage, 
			arg5, arg5cage, 
			arg6, arg6cage, 
			0
		);
		*/

		// kill(TEESTATE.primary_target, SIGSTOP);

		//printf("[t-grate] waiting for target cage exit...\n");
		//sem_wait(TEESTATE.exiting);
		//printf("[t-grate] exiting %%} cage...\n");

		return 0;
	} else {
		return make_threei_call(
			59, 
			0, 
			tee_cage, 
			arg1cage,
			arg1, arg1cage, 
			arg2, arg2cage, 
			arg3, arg3cage, 
			arg4, arg4cage, 
			arg5, arg5cage, 
			arg6, arg6cage, 
			0
		);
	}
}
