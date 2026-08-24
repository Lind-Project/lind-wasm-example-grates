#include "seccomp.h"
#include "syscalls.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* default every syscall to blacklist for safety */
seccomp_mode_t syscall_mode[MAX_SYSCALLS] = {BL};

/*
 * Blacklisted syscall handler — current 3i ABI. Denies the call with -EPERM.
 * All arguments are ignored: a blacklisted syscall is refused regardless of
 * its arguments.
 */
long blacklist_handler(pid_t cageid, const int arg_cage[6],
                       unsigned long args[6]) {
  (void)cageid; (void)arg_cage; (void)args;
  return -EPERM;
}

/* build the name->number map from the X-macro list (now kernel __NR_*) */
static const syscall_entry_t syscall_map[] = {
#define X(name, num) {"SYS_" #name, num},
    SYSCALL_LIST
#undef X
};

#define NUM_SYSCALLS (sizeof(syscall_map) / sizeof(syscall_map[0]))

char *trim_whitespace(char *str) {
  char *end;
  while (isspace((unsigned char)*str)) str++;
  if (*str == 0) return str;
  end = str + strlen(str) - 1;
  while (end > str && isspace((unsigned char)*end)) end--;
  end[1] = '\0';
  return str;
}

void parse_config(const char *filename) {
  FILE *fp = fopen(filename, "r");
  if (!fp) { perror("Failed to open config file"); exit(EXIT_FAILURE); }

  char line[256];
  seccomp_mode_t current_mode = MODE_UNASSIGNED;
  seccomp_mode_t default_mode = BL;
  int explicitly_set[MAX_SYSCALLS] = {0};
  int line_num = 0;

  while (fgets(line, sizeof(line), fp)) {
    line_num++;
    line[strcspn(line, "\r\n")] = 0;
    char *trimmed = trim_whitespace(line);

    if (trimmed[0] == '\0' || trimmed[0] == ';' || trimmed[0] == '#') continue;

    if (trimmed[0] == '[') {
      size_t len = strlen(trimmed);
      if (trimmed[len - 1] != ']') {
        fprintf(stderr, "Config Error: Malformed section header on line %d\n", line_num);
        exit(EXIT_FAILURE);
      }
      if (strcmp(trimmed, "[whitelist]") == 0) { current_mode = WL; continue; }
      if (strcmp(trimmed, "[blacklist]") == 0) { current_mode = BL; continue; }
      if (strcmp(trimmed, "[default]") == 0)   { current_mode = MODE_DEFAULT; continue; }
      fprintf(stderr, "Config Error: Unknown section '%s' on line %d\n", trimmed, line_num);
      exit(EXIT_FAILURE);
    }

    if (current_mode == MODE_UNASSIGNED) {
      fprintf(stderr, "Config Error: Orphaned entry '%s' before any section on line %d\n", trimmed, line_num);
      exit(EXIT_FAILURE);
    }

    if (current_mode == MODE_DEFAULT) {
      if (strcmp(trimmed, "whitelist") == 0) default_mode = WL;
      else if (strcmp(trimmed, "blacklist") == 0) default_mode = BL;
      else { fprintf(stderr, "Config Error: Invalid default mode '%s' on line %d\n", trimmed, line_num); exit(EXIT_FAILURE); }
      continue;
    }

    int found = 0;
    for (size_t i = 0; i < NUM_SYSCALLS; i++) {
      if (strcmp(trimmed, syscall_map[i].name) == 0) {
        int sys_num = syscall_map[i].num;
        if (sys_num < 0 || sys_num >= MAX_SYSCALLS) {   /* guard the index */
          fprintf(stderr, "Config Error: syscall '%s' number %d out of range on line %d\n", trimmed, sys_num, line_num);
          exit(EXIT_FAILURE);
        }
        if (explicitly_set[sys_num]) {
          fprintf(stderr, "Config Error: Duplicate definition of syscall '%s' on line %d\n", trimmed, line_num);
          exit(EXIT_FAILURE);
        }
        syscall_mode[sys_num] = current_mode;
        explicitly_set[sys_num] = 1;
        found = 1;
        break;
      }
    }

    if (!found) {
      fprintf(stderr, "Config Error: Unknown syscall '%s' on line %d\n", trimmed, line_num);
      exit(EXIT_FAILURE);
    }
  }
  fclose(fp);

  for (int i = 0; i < MAX_SYSCALLS; i++)
    if (!explicitly_set[i]) syscall_mode[i] = default_mode;
}
