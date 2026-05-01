#include <stdio.h>
#include <unistd.h>

int main() {
	char buf[10];

	int ret = read(12, buf, 4);

	printf("[CAGE] read=%d\n", ret);
}
