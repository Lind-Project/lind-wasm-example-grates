This folder contains example grate implementations, as well as an example runner for grate-cage configurations.

### Compile

`./tools/compile.sh <grate source files>`

### Run

- Compile all cages present in the `cage/` folder, and place them into `LIND_ROOT` using the `scripts/lind_compile.sh` command.
- Compile all grates present in the `grates/` folder, and place them into `LIND_ROOT`.
- Run an example grate configuration using `./tools/run.sh`. This will run the following configuration:

```
geteuid_grate:
    getegid_grate.wasm:
        bash -c "etest & imfs_grate runopen & getgid_grate gidtest" 
```

### File Structure 

```
grates/
    imfs_grate.c // Grate source code with wrappers for individual syscalls.
    imfs.* // IMFS source code.
    ... // Other Grate examples 

cages/
    mash.c // Barebones, minimal bash source code. 
    etest.c 
    runopen.c 
    ... // Example cage source code.

syscalls // List of syscalls along with the arguments required.

tools/
    - wand.py // Python script that generates bindings for syscall conversions. 
    - magic.*tmpl // Template files for .h and .c files with the necessary bindings.
    - compile.sh // Compilation script.
    - run.sh    // Run runopen.c
```

### Writing a syscall wrapper

Consider the example of the `xstat_grate` syscall wrapper written with the new API:

```c
int xstat_syscall(int cageid, char *pathname, struct stat *statbuf) {
	return imfs_stat(cageid, pathname, statbuf);
}
```

The syscall wrapper only has to deal with parameters that a regular syscall declaration would take, along with the `cageid` parameter which points to the id of the cage that called this syscall.

Handling of copying data in or out of cages is handled internally. In this example, `pathname` already points to a valid memory address in this grate, and anything written to `*statbuf` is copied out to the appropriate location in the calling cage's memory.

For an example of a complete grate file, view `imfs_grate.c`. A short example is below:

```c
#include <sys/types.h>
#include <sys/stat.h>

#include <lind_syscall_num.h>
#include "magic.h" // These are the headers required to use the bindings.

#include "imfs.h"

// grate_syscalls* are extern'd variables. These should be a list of syscall nums.
int grate_syscalls[] = {XSTAT_SYSCALL};
int grate_syscalls_len = 1;

// Optional initialization and destroy logic or the grate.
void grate_init() {
	imfs_init();
}

void grate_destroy() {
    printf("IMFS Exiting\n");
}

int xstat_syscall(int cageid, char *pathname, struct stat *statbuf) {
	return imfs_stat(cageid, pathname, statbuf);
}
```

### Internals

The full implementation of how these bindings are generated can be seen in `tools/wand.py`, and `tools/compile.sh`.

We begin with a list of syscall declarations, which give us extra information about the parameters of a given syscall. Some examples are below:

```js
xstat = {
	IN	char*	pathname
	OUT	struct stat*	statbuf
}

read = {
	N	int	fd
	OUT	void*	buf[count]
	N	size_t	count
}

write = {
	N	int	fd 
	IN	void*	buf[count]
	N	size_t	count
}
```

The `IN/OUT/N` tags tell us when or if to call `copy_data_between_cages` for a particular argument. This is extrapolated using the type of the argument as listed on the man pages. For e.g. `const` pointers are not copied out. Reguar pointers are copied in before the syscall and copied out after it (useful for calls such as `recvmsg()`). Integer and integer-aliased types are not copied. 

These tagged structs allow us to generate the `<syscall>_grate` functions that eventually call the user-defined wrappers. Some examples are cited below, for an example generated binding, view `magic.c` and `magic.h`.


```c
// Close doesn't require any copying of data. 
int close_grate(uint64_t cageid, ..., uint64_t arg6cage) {
  if (!close_syscall) {
    return -1;
  }

  int fd = arg1;

  int ret = close_syscall(cageid, fd);

  return ret;
}
```

```c
// XSTAT requires us to copy over the "pathname" before we call our wrapper, and call copy on "statbuf" to return the result to the calling cage.
int xstat_grate(uint64_t cageid, ..., uint64_t arg6cage) {
  if (!xstat_syscall) {
    return -1;
  }

  struct stat *statbuf = malloc(sizeof(struct stat));

  if (statbuf == NULL) {
    perror("malloc failed");
    exit(EXIT_FAILURE);
  }

  copy_data_between_cages(thiscage, arg2cage, arg2, arg2cage, (uint64_t)statbuf,
                          thiscage, sizeof(struct stat), 0);

  char *pathname = malloc(256);

  if (pathname == NULL) {
    perror("malloc failed");
    exit(EXIT_FAILURE);
  }

  copy_data_between_cages(thiscage, arg1cage, arg1, arg1cage,
                          (uint64_t)pathname, thiscage, 256, 1);

  int ret = xstat_syscall(cageid, pathname, statbuf);

  if (arg2 != 0) {
    copy_data_between_cages(thiscage, arg2cage, (uint64_t)statbuf, thiscage,
                            arg2, arg2cage, sizeof(struct stat), 0);
  }

  free(statbuf);
  free(pathname);

  return ret;
}
```

#### Notes on dealing with a `buffer` vs `char *`:

When allocating memory for "strings", there are two distinct cases to handle. 

For a `char *`, for now we assign a constant `256` bytes of memory and copies are done using `StrCpy` mode (relying on `\0` as the terminating character). Example - `char * pathname` in `open`)

For buffers, (`read/write` has `void buf[count]`), we allocate the mentioned size of memory, and use `RawCpy` to copy exactly this size. 

For non-string pointers (such as `struct stat *statbuf`), we allocate `sizeof(<type>)` bytes, and use `RawCpy`.

The current bindings generator implicitly handles all these cases.
