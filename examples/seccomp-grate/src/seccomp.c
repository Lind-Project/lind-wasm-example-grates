#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "seccomp.h"
#include "syscalls.h"

syscall_handler_t syscall_handler_table[MAX_SYSCALLS] = {0};

int syscall_mode[MAX_SYSCALLS] = {0};

// generate one handler per syscall at compile time
#define X(name, num) DEFINE_HANDLER(name, num)
SYSCALL_LIST
#undef X

static const syscall_entry_t syscall_map[] = {
#define X(name, num) { "SYS_" #name, num, name##_grate },
    SYSCALL_LIST
#undef X
};

#define NUM_SYSCALLS (sizeof(syscall_map) / sizeof(syscall_map[0]))

// runtime INI Parser
void parse_config(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Failed to open config file");
        exit(EXIT_FAILURE);
    }

    char line[256];
    int current_mode = -1;

    // default mode set to BL (safety fallback)
    int default_mode = BL;

    while (fgets(line, sizeof(line), fp)) {
	// strip newline
        line[strcspn(line, "\r\n")] = 0;

        if (line[0] == '\0' || line[0] == ';' || line[0] == '#') continue;

        if (strcmp(line, "[whitelist]") == 0) { current_mode = WL; continue; }
        if (strcmp(line, "[blacklist]") == 0) { current_mode = BL; continue; }
        if (strcmp(line, "[default]") == 0)   { current_mode = 2;  continue; }

	// default
        if (current_mode == 2) {
            if (strcmp(line, "whitelist") == 0) default_mode = WL;
            else if (strcmp(line, "blacklist") == 0) default_mode = BL;
            continue;
        }

        if (current_mode == -1) continue;

        // map explicitly listed syscalls
        for (size_t i = 0; i < NUM_SYSCALLS; i++) {
            if (strcmp(line, syscall_map[i].name) == 0) {
                int sys_num = syscall_map[i].num;
                syscall_mode[sys_num] = current_mode;
                syscall_handler_table[sys_num] = syscall_map[i].handler;
                break;
            }
        }
    }
    fclose(fp);

    // backfill unconfigured syscalls with the default rule
    for (size_t i = 0; i < NUM_SYSCALLS; i++) {
        int sys_num = syscall_map[i].num;
        // if not explicitly set in the INI file
        if (syscall_handler_table[sys_num] == NULL) {
            syscall_mode[sys_num] = default_mode;
            syscall_handler_table[sys_num] = syscall_map[i].handler;
        }
    }
}

// dispatcher function
int pass_fptr_to_wt(uint64_t fn_ptr_uint, uint64_t cageid,
                    uint64_t arg1, uint64_t arg1cage, 
                    uint64_t arg2, uint64_t arg2cage,
                    uint64_t arg3, uint64_t arg3cage, 
                    uint64_t arg4, uint64_t arg4cage,
                    uint64_t arg5, uint64_t arg5cage, 
                    uint64_t arg6, uint64_t arg6cage) {

    if (fn_ptr_uint == 0) return -1;

    syscall_handler_t fn = (syscall_handler_t)(uintptr_t)fn_ptr_uint;

    return fn(cageid, arg1, arg1cage, arg2, arg2cage, arg3, arg3cage, 
              arg4, arg4cage, arg5, arg5cage, arg6, arg6cage);
}
