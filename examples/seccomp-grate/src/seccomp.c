#include "seccomp.h"
#include "syscalls.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// syscall handler table
syscall_handler_t syscall_handler_table[MAX_SYSCALLS] = {0};

// default every syscall to blacklist for safety
seccomp_mode_t syscall_mode[MAX_SYSCALLS] = {BL};

// blacklisted syscall handler
int blacklist_handler(uint64_t cageid, uint64_t arg1, uint64_t arg1cage,
                      uint64_t arg2, uint64_t arg2cage, uint64_t arg3,
                      uint64_t arg3cage, uint64_t arg4, uint64_t arg4cage,
                      uint64_t arg5, uint64_t arg5cage, uint64_t arg6,
                      uint64_t arg6cage) {
  return -EPERM;
}

// creates syscall map
static const syscall_entry_t syscall_map[] = {
#define X(name, num) {"SYS_" #name, num},
    SYSCALL_LIST
#undef X
};

#define NUM_SYSCALLS (sizeof(syscall_map) / sizeof(syscall_map[0]))

// helper function to clean whitespaces
char *trim_whitespace(char *str) {
  char *end;
  while (isspace((unsigned char)*str))
    str++;
  if (*str == 0)
    return str;
  end = str + strlen(str) - 1;
  while (end > str && isspace((unsigned char)*end))
    end--;
  end[1] = '\0';
  return str;
}

// this function parses and validates the config file
void parse_config(const char *filename) {
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    perror("Failed to open config file");
    exit(EXIT_FAILURE);
  }

  char line[256];

  seccomp_mode_t current_mode = MODE_UNASSIGNED;
  seccomp_mode_t default_mode = BL;

  int explicitly_set[MAX_SYSCALLS] = {0};
  int line_num = 0;

  while (fgets(line, sizeof(line), fp)) {
    line_num++;
    line[strcspn(line, "\r\n")] = 0;
    char *trimmed = trim_whitespace(line);

    // skip comments, empty lines
    if (trimmed[0] == '\0' || trimmed[0] == ';' || trimmed[0] == '#')
      continue;

    // handle section headers
    if (trimmed[0] == '[') {
      size_t len = strlen(trimmed);
      if (trimmed[len - 1] != ']') {
        fprintf(stderr, "Config Error: Malformed section header on line %d\n",
                line_num);
        exit(EXIT_FAILURE);
      }
      if (strcmp(trimmed, "[whitelist]") == 0) {
        current_mode = WL;
        continue;
      }
      if (strcmp(trimmed, "[blacklist]") == 0) {
        current_mode = BL;
        continue;
      }
      if (strcmp(trimmed, "[default]") == 0) {
        current_mode = MODE_DEFAULT;
        continue;
      }

      fprintf(stderr, "Config Error: Unknown section '%s' on line %d\n",
              trimmed, line_num);
      exit(EXIT_FAILURE);
    }

    // catch orphaned entries
    if (current_mode == MODE_UNASSIGNED) {
      fprintf(stderr,
              "Config Error: Orphaned entry '%s' found before any section on "
              "line %d\n",
              trimmed, line_num);
      exit(EXIT_FAILURE);
    }

    // handle [default] section
    if (current_mode == MODE_DEFAULT) {
      if (strcmp(trimmed, "whitelist") == 0)
        default_mode = WL;
      else if (strcmp(trimmed, "blacklist") == 0)
        default_mode = BL;
      else {
        fprintf(stderr, "Config Error: Invalid default mode '%s' on line %d\n",
                trimmed, line_num);
        exit(EXIT_FAILURE);
      }
      continue;
    }

    // handle syscall mapping and validation
    int found = 0;
    for (size_t i = 0; i < NUM_SYSCALLS; i++) {
      if (strcmp(trimmed, syscall_map[i].name) == 0) {
        int sys_num = syscall_map[i].num;
        syscall_mode[sys_num] = current_mode;
        explicitly_set[sys_num] = 1;
        found = 1;
        break;
      }
    }

    if (!found) {
      fprintf(stderr, "Config Error: Unknown syscall '%s' on line %d\n",
              trimmed, line_num);
      exit(EXIT_FAILURE);
    }
  }
  fclose(fp);

  // backfill unconfigured syscalls with the default rule
  for (int i = 0; i < MAX_SYSCALLS; i++) {
    if (!explicitly_set[i]) {
      syscall_mode[i] = default_mode;
    }
  }
}

// dispatcher function
int pass_fptr_to_wt(uint64_t fn_ptr_uint, uint64_t cageid, uint64_t arg1,
                    uint64_t arg1cage, uint64_t arg2, uint64_t arg2cage,
                    uint64_t arg3, uint64_t arg3cage, uint64_t arg4,
                    uint64_t arg4cage, uint64_t arg5, uint64_t arg5cage,
                    uint64_t arg6, uint64_t arg6cage) {

  if (fn_ptr_uint == 0)
    return -1;

  syscall_handler_t fn = (syscall_handler_t)(uintptr_t)fn_ptr_uint;

  return fn(cageid, arg1, arg1cage, arg2, arg2cage, arg3, arg3cage, arg4,
            arg4cage, arg5, arg5cage, arg6, arg6cage);
}
