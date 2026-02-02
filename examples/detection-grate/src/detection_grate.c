#include <errno.h>
#include <fcntl.h>
#include <lind_syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sched.h>

// Dispatcher function
int pass_fptr_to_wt(uint64_t fn_ptr_uint, uint64_t cageid, uint64_t arg1,
                    uint64_t arg1cage, uint64_t arg2, uint64_t arg2cage,
                    uint64_t arg3, uint64_t arg3cage, uint64_t arg4,
                    uint64_t arg4cage, uint64_t arg5, uint64_t arg5cage,
                    uint64_t arg6, uint64_t arg6cage) {
    if (fn_ptr_uint == 0) {
        fprintf(stderr, "[Grate|execve] Invalid function ptr\n");
        return -1;
    }

    printf("[Grate|execve] Handling function ptr: %llu from cage: %llu\n",
           fn_ptr_uint, cageid);

    int (*fn)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
              uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
              uint64_t) = (void *)fn_ptr_uint;

    return fn(cageid, arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
              arg4, arg4cage, arg5, arg5cage, arg6, arg6cage);
}

// execve() handler function
int execve_grate(uint64_t cageid, uint64_t arg1, uint64_t arg1cage,
                 uint64_t arg2, uint64_t arg2cage, uint64_t arg3,
                 uint64_t arg3cage, uint64_t arg4, uint64_t arg4cage,
                 uint64_t arg5, uint64_t arg5cage, uint64_t arg6,
                 uint64_t arg6cage) {

    printf("[Grate|execve] Inside execve_grate for cage: %llu\n", cageid);

    int grateid = getpid();

    printf("[Grate|execve] In execve_grate %d handler for cage: %llu\n",
           grateid, cageid);

    char *pathname = malloc(256);
    if (pathname == NULL) {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }

    // copy pathname to grate's address space
    if (copy_data_between_cages(grateid, arg1cage, arg1, arg1cage,
                                (uint64_t)pathname, grateid, 256, 1) < 0) {
        printf("[Grate|execve] copy_data_between_cages failed.\n");
        return -EFAULT;
    }
    
    // open file and read first two bytes
    int fd = open(pathname, O_RDONLY);
    if (fd >= 0) {
        unsigned char header[2];
        ssize_t n = read(fd, header, 2);
        close(fd);
	
	// perform check for PE file detection
        if (header[0] == 'M' && header[1] == 'Z') {
            printf("[Grate|execve] SUCCESS: Blocked PE file at %s\n", pathname);
            free(pathname);
	    return -ENOEXEC;
        }
    } else {
        printf("[Grate|execve] Warning: Grate could not open %s (errno %d)\n",
               pathname, errno);
	free(pathname);
    }

    /*
    // forward syscall and resume execution
    return make_threei_call(59, 0, grateid, cageid,
                            arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
                            0, 0, 0, 0, 0, 0, 1);
    */
   
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <cage_file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int grateid = getpid();
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork failed");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        int cageid = getpid();

        uint64_t fn_ptr_addr = (uint64_t)(uintptr_t)&execve_grate;

        printf("[Grate|execve] Registering execve handler for cage %d in grate %d\n",
               cageid, grateid);

        if (register_handler(cageid, 59, 1, grateid, fn_ptr_addr) < 0) {
            fprintf(stderr, "[Grate|execve] Failed to register handler\n");
        }

        if (execv(argv[1], &argv[1]) == -1) {
            perror("execv failed");
            exit(EXIT_FAILURE);
        }
    } else {
        int status;

        while (1) {
            pid_t result = waitpid(pid, &status, WNOHANG);

            if (result > 0) {
                printf("[Grate|execve] Child terminated, status: %d\n", status);
                break;
            } else if (result < 0) {
                perror("waitpid failed");
                break;
            }
        }
    }

    return 0;
}

