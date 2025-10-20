## In Memory File System 

The In Memory File System (IMFS) provides a self-contained implementation of a POSIX-like FS backed by memory. It serves as a backbone that can later be integrated as a grate to sandbox any FS calls made by a cage. IMFS exposes POSIX-like APIs and maintains its own inode and file descriptor tables to provide an end-to-end FS interface.

New implementations to IMFS are usually tested in a sandboxed manner on Linux natively, before being tested in `lind-3i` with a grate function wrapping the new functionality.

### File System APIs

IMFS mirrors POSIX system calls with an added `cageid` parameter. For example:

```
open(const char* pathname, int flags, mode_t mode)
->
imfs_open(int cageid, const char* pathname, int flags, mode_t mode)
```

The behaviours of these APIs closely match those of their corresponding Linux system calls. They follow the semantics described in man pages including types, return values, and error codes. This allows easy integration of IMFS into a grate, and allows for easy testing on native environments. 

When running this module on Linux, the `cageid` parameter should be stubbed as a constant between `[0,128)`, like so:

```
#define CAGEID 0

int fd = imfs_open(CAGEID, "/testfile.txt", O_RDONLY, 0); 
imfs_close(CAGEID, fd);
```
### Utility Functions. 

In addition to POSIX APIs, IMFS also provides helper functions for moving files in and out of memory. 

- `load_file(char *path)` Load a single file into IMFS at `path`, recursively creating any required folders. 

- `dump_file(char *path, char *actual_path)` Copy IMFS file at `path` to the host filesystem at `actual_path`

- `preloads(char *preload_files)` Copy files from host to IMFS, `preload_files` being a `:` separated list of filenames. 

These utility functions are called before executing any child cages, and after they exit. The IMFS grate is responsible for calling these to stage files into memory (`load_file`, `preloads`) and to persist results back (`dump_file`).

In the accompanying example grate, the grate reads the environment variables `"PRELOADS"` to determine which files are meant to be staged.

## Implementation

### Inodes 

IMFS maintains an array of `Node` objects each of which serve as an inode to represent an FS object (file, directory, symlink, or pipe). Allocation of nodes is performed using a free-list mechanism along with a pointer that tracks the next available slot within the array. 

The structure of the node is specialized according to its type:

- Directories contain references to child nodes.
- Symlinks maintain a pointer to the target node. 
- Regular files store data in fixed-sized `Chunk`s, each of which store 1024 bytes of data. These chunks are organized as a singly linked list. 

### File Descriptors

Each cage has its own array of `FileDesc` objects that represent a file descriptor. The file descriptors used by these FS calls are indices into this array. 

File descriptor allocation begins at index 3. The management of standard descriptors (`stdin`, `stdout`, `stderr`) are delegated to the enclosing grate.

Descriptors are allocated using `imfs_open` or `imfs_openat`. Each file descriptor object stores:

- A pointer to the associated node. 
- The current file offset. 
- Open flags

## Building

### Native Build

- `make lib` to build as a library
- `make imfs` to build with the main function
- `make debug` build with debug symbols

### Lind Integration Build

The following compile flags are required to compile IMFS for a Lind build:

- `-DLIB` omit the main function
- `-DDIAG` to enable diagnostic logging
- `-D_GNU_SOURCE` needed to support `SEEK_HOLE` and `SEEK_DATA` operations in `imfs_lseek()`

## Grate Integration

The grate implementation currently provides syscall wrappers for the following FS syscalls:

- [`open`](https://man7.org/linux/man-pages/man2/open.2.html)
- [`close`](https://man7.org/linux/man-pages/man2/close.2.html)
- [`read`](https://man7.org/linux/man-pages/man2/read.2.html)
- [`write`](https://man7.org/linux/man-pages/man2/write.2.html)
- [`fcntl`](https://man7.org/linux/man-pages/man2/fcntl.2.html)

## Testing 

POSIX compliance is validated through `pjdfstest`, a widely adopted test suite for file systems for both BSD and Linux file systems. The tests are executed natively on Linux, which required modifications to `pjdfstest` in order to support a persistent test runner capable of maintaining FS state in memory. 

`pdjfstest` provides a comprehensive list of assertions each designed to verify a specific FS property. This approach allows for easier detection of edge-cases. 

The test suite is invoked using:

- `make test` run all tests
- `make test-<feature>` run all tests in a particular feature

## Example Usage: Running `tcc` with IMFS Grate

Check out the documentation [here](https://github.com/stupendoussuperpowers/lind-wasm/tree/ea95e1742c4c497ae7d859603869d8612f695ad7/imfs_grate).

## Future Work

- Currently only a handful of the most common logical branches are supported for most syscalls. For example, not all flags are supported for `open`. 
- Access control is not implemented, by default all nodes are created with mode `0755` allowing for any user or group to access them. 
- `mmap` is yet to be implemented. 
- Performance testing for reading and writing. 
- Integrating FD table management with `fdtables` crate.

