#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

int main() {
    // place hello.exe in LIND_ROOT
    const char *filename = "hello.exe";
    char *argv[] = { (char *)filename, NULL };
    char *envp[] = { NULL };

    printf("[Test|Grate|execve] Attempting to execve with PE file: %s\n", filename);

    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
	printf("[Test|Grate|execve] Current working directory: %s\n", cwd);
    } else {
    	perror("getcwd failed");
    }

    int ret = execve(filename, argv, envp);
    
    if (ret == -1) {
        perror("execve failed");
    }

    return 0;
}

