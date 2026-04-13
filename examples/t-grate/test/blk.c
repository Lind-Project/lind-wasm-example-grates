#include <unistd.h>
#include <sched.h>
#include <stdlib.h>

int main() {
	while(1) {
		//sched_yield();
		sleep(10);
	}
}
