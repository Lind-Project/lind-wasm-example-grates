#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "imfs.h"

// Global state for the IMFS
struct IMFState {
	Node nodes[MAX_NODES];
	int next_node;
	int free_list[MAX_NODES];
	int free_list_size;
};

static struct IMFState g_state;

#define g_next_node g_state.next_node
#define g_nodes g_state.nodes
#define g_free_list g_state.free_list
#define g_free_list_size g_state.free_list_size

// Each Process (Cage) has it's own FD Table, all of which are initiated
// in memory when imfs_init() is called. Node are allocated using the use of
// g_next_node and g_free_list, as described below.
//
// This tracks "Holes" in the g_nodes table, caused by nodes that were deleted.
// When creating a new node, we check which index this free list points to and
// creates the node there. In case there are no free nodes in this list, we use
// the global g_next_node index.

static FileDesc g_fdtable[MAX_PROCS][MAX_FDS];

// We use the same logic for fd allocations.
static int g_next_fd[MAX_PROCS];
static int g_fd_free_list[MAX_PROCS][MAX_FDS];
static int g_fd_free_list_size[MAX_PROCS];

static Node *g_root_node = NULL;

//
// String Utils
//

static size_t str_len(const char *name) {
	int i = 0;
	while (name[i] != '\0') {
		i++;
	}
	return i;
}

static char *str_rchr(const char *s, const char c) {
	char *last = 0;

	while (*s != '\0') {
		if (*s == (char)c) {
			last = (char *)s;
		}
		s++;
	}

	if (c == '\0') {
		return (char *)s;
	}

	return last;
}

static void split_path(const char *path, int *count,
		       char namecomp[MAX_DEPTH][MAX_NODE_NAME]) {
	*count = 0;

	int i = 0;
	if (path[i] == '/')
		i++;

	int current_len = 0;
	while (path[i] != '\0') {
		if (path[i] == '/') {
			namecomp[*count][current_len] = '\0';
			(*count)++;
			current_len = 0;
		} else {
			namecomp[*count][current_len++] = path[i];
		}

		i++;
	}
	namecomp[*count][current_len] = '\0';
	(*count)++;
}

static int str_compare(const char *a, const char *b) {
	int a_len = 0;
	while (a[a_len] != '\0')
		a_len++;
	int b_len = 0;
	while (b[b_len] != '\0')
		b_len++;

	if (a_len != b_len)
		return 0;
	int i = 0, j = 0;
	while (a[i] != '\0' && b[j] != '\0') {
		if (a[i] != b[j])
			return 0;
		i++;
		j++;
	}
	return 1;
}

static void str_ncopy(char *dst, const char *src, int n) {
	size_t i;
	for (i = 0; i < n && src[i] != '\0'; i++) {
		dst[i] = src[i];
	}
}

static void mem_cpy(void *dst, const void *src, size_t n) {
	size_t i;
	unsigned char *d = dst;
	const unsigned char *s = src;

	for (i = 0; i < n; i++) {
		d[i] = s[i];
	}
}

// Return a buffer that contains the entire file in. Avoids having to call
// realloc over and over for preloaded files.
static char *read_full_file(char *path, size_t *out_size) {
	FILE *fp = fopen(path, "rb");

	fseek(fp, 0, SEEK_END);
	long size = ftell(fp);
	rewind(fp);

	char *buf = malloc(size);

	size_t read = fread(buf, 1, size, fp);
	fclose(fp);
	*out_size = (size_t)size;

	return buf;
}

//
//  IMFS Utils
//

void imfs_copy_fd_tables(int srcfd, int dstfd) {
	for (int i = 0; i < MAX_FDS; i++) {
		g_fdtable[dstfd][i] = g_fdtable[srcfd][i];
	}
}

static Node *imfs_create_node(const char *name, NodeType type, mode_t mode) {
	if (g_free_list_size == -1 && g_next_node >= MAX_NODES) {
		errno = ENOMEM;
		return NULL;
	}

	int node_index;
	if (g_free_list_size == -1)
		node_index = g_next_node++;
	else
		node_index = g_free_list[g_free_list_size--];

	if (g_nodes[node_index].type != M_NON) {
		errno = ENOMEM;
		return NULL;
	}

	g_nodes[node_index].in_use = 0;
	g_nodes[node_index].doomed = 0;
	g_nodes[node_index].type = type;
	g_nodes[node_index].total_size = 0;
	g_nodes[node_index].d_count = 0;
	g_nodes[node_index].r_head = NULL;
	g_nodes[node_index].r_tail = NULL;
	g_nodes[node_index].parent_idx = -1;
	g_nodes[node_index].mode = g_nodes[node_index].type | (mode & 0777);
	g_nodes[node_index].owner = GET_UID;
	g_nodes[node_index].group = GET_GID;

	clock_gettime(CLOCK_REALTIME, &g_nodes[node_index].atime);
	clock_gettime(CLOCK_REALTIME, &g_nodes[node_index].btime);
	clock_gettime(CLOCK_REALTIME, &g_nodes[node_index].ctime);
	clock_gettime(CLOCK_REALTIME, &g_nodes[node_index].mtime);

	str_ncopy(g_nodes[node_index].name, name, MAX_NODE_NAME);
	int length = str_len(name);
	g_nodes[node_index].name[length] = '\0';

	/* If directory, allocate initial children array */
	if (type == M_DIR) {
		g_nodes[node_index].d_capacity = MAX_NODES;
		g_nodes[node_index].d_children = calloc(g_nodes[node_index].d_capacity, sizeof(DirEnt));
		if (!g_nodes[node_index].d_children) {
			errno = ENOMEM;
			return NULL;
		}
		g_nodes[node_index].d_count = 0;
	}
	return &g_nodes[node_index];
}

static int imfs_allocate_fd(int cage_id, Node *node, int flags) {
	if (!node)
		return -1;

	int i;
	if (g_fd_free_list_size[cage_id] > -1) {
		i = g_fd_free_list[cage_id][g_fd_free_list_size[cage_id]--];
	} else {
		i = g_next_fd[cage_id]++;
	}

	if (i == MAX_FDS) {
		errno = EMFILE;
		return -1;
	}

	g_fdtable[cage_id][i] = (FileDesc){
	    .node = node,
	    .offset = 0,
	    .link = NULL,
	    .status = 1,
	    .flags = flags,
	};

	node->in_use++;

	clock_gettime(CLOCK_REALTIME, &node->atime);

	return i;
}

static FileDesc *get_filedesc(int cage_id, int fd) {
	if (g_fdtable[cage_id][fd].link)
		return g_fdtable[cage_id][fd].link;

	return &g_fdtable[cage_id][fd];
}

//
// These two functions are used to perform a Node lookup. The implementation for
// this is to start from the '/' REG and iteratively go through their child
// nodes.
//
// imfs_find_node_namecomp() takes as input an array of path name components.
// imfs_find_node() takes as input a pathname which is then split by '/'
//
// The runtime should likely be improved by using a different method like a hash
// table.
//
static Node *
imfs_find_node_namecomp(int cage_id, int dirfd,
			const char namecomp[MAX_DEPTH][MAX_NODE_NAME],
			int count) {
	FileDesc *fd = get_filedesc(cage_id, dirfd);
	if (count == 0)
		return g_root_node;

	Node *current;
	if (dirfd == AT_FDCWD)
		current = g_root_node;
	else
		current = fd->node;

	for (int i = 0; i < count && current; i++) {
		Node *found = NULL;
		for (size_t j = 0; j < current->d_count; j++) {
			if (str_compare(namecomp[i],
					current->d_children[j].name) == 1) {
				switch (current->d_children[j].node->type) {
					case M_LNK:
						found = current->d_children[j]
							    .node->l_link;
						break;
					case M_DIR:
					case M_REG:
						found =
						    current->d_children[j].node;
						break;
					default:
						found = NULL;
				}
				break;
			}
		}

		if (!found) {
			return NULL;
		}

		current = found;
	}

	return current;
}

static Node *imfs_find_node(int cage_id, int dirfd, const char *path) {
	if (!path || !g_root_node)
		return NULL;

	if (path[0] == '/' && path[1] == '\0')
		return g_root_node;

	int count;
	char namecomps[MAX_DEPTH][MAX_NODE_NAME];

	split_path(path, &count, namecomps);

	return imfs_find_node_namecomp(cage_id, dirfd, namecomps, count);
}

static int add_child(Node *parent, Node *node) {
	if (!parent || !node || parent->type != M_DIR)
		return -1;

	/* grow children array if needed */
	if (parent->d_count >= parent->d_capacity) {
		size_t newcap = parent->d_capacity ? parent->d_capacity * 2 : MAX_NODES;
		DirEnt *n = realloc(parent->d_children, newcap * sizeof(DirEnt));
		if (!n)
			return -1;
		parent->d_children = n;
		parent->d_capacity = newcap;
	}

	size_t new_count = parent->d_count + 1;

	parent->d_children[parent->d_count].node = node;

	str_ncopy(parent->d_children[parent->d_count].name, node->name,
		  MAX_NODE_NAME);
	int length = str_len(node->name);
	parent->d_children[parent->d_count].name[length] = '\0';

	parent->d_count = new_count;
	node->parent_idx = parent->index;

	return 0;
}

static Pipe *get_pipe(int cage_id, int fd) {
	FileDesc *fdesc = get_filedesc(cage_id, fd);
	if (fdesc->node->type != M_PIP) {
		return NULL;
	}

	return fdesc->node->p_pipe;
}

static int imfs_dup_fd(int cage_id, int oldfd, int newfd) {
	if (newfd == oldfd)
		return newfd;

	int i;
	if (newfd != -1) {
		i = newfd;
		goto allocate;
	}

	if (g_fd_free_list_size[cage_id] > -1) {
		i = g_fd_free_list[cage_id][g_fd_free_list_size[cage_id]--];
	} else {
		i = g_next_fd[cage_id]++;
	}

	if (i == MAX_FDS) {
		errno = EMFILE;
		return -1;
	}

allocate:

	if (g_fdtable[cage_id][i].node || g_fdtable[cage_id][i].link)
		imfs_close(cage_id, i);

	g_fdtable[cage_id][i] = (FileDesc){
	    .link = &g_fdtable[cage_id][oldfd],
	    .node = NULL,
	    .offset = 0,
	};

	return i;
}

static int remove_child(Node *node) {
	size_t total_nodes = g_nodes[node->parent_idx].d_count;
	int remove_idx;

	for (int i = 0; i < total_nodes; i++) {
		if (str_compare(g_nodes[node->parent_idx].d_children[i].name,
				node->name)) {
			remove_idx = i;
			break;
		}
	}

	for (int i = remove_idx; i < total_nodes - 1; i++) {
		g_nodes[node->parent_idx].d_children[i] =
		    g_nodes[node->parent_idx].d_children[i + 1];
	}

	g_nodes[node->parent_idx].d_count--;

	return 0;
}

//
// Most FS APIs contain duplicated workflows, these functions deal with that.
// This allows for exports FS APIs to be brief. For e.g., the difference between
// write() and pwrite() is only on how offsets are used and updated. The rest of
// the logic remains the same.
//

static int imfs_remove_file(Node *node) {
	remove_child(node);

	node->doomed = 1;

	if (!node->in_use) {
		g_free_list[++g_free_list_size] = node->index;
		node->type = M_NON;
	}

	return 0;
}

static int imfs_remove_pipe(Node *node) {
	node->doomed = 1;

	g_free_list[++g_free_list_size] = node->index;
	node->type = M_NON;

	return 0;
}

static int imfs_remove_dir(Node *node) {
	if (node == g_root_node || node->d_count > 2) {
		errno = EBUSY;
		return -1;
	}

	if (!node->in_use) {
		g_free_list[++g_free_list_size] = node->index;
		/* free dynamic children storage if allocated */
		if (node->d_children) {
			free(node->d_children);
			node->d_children = NULL;
			node->d_capacity = 0;
		}
		node->type = M_NON;
	}

	remove_child(node);
	node->doomed = 1;
	return 0;
}

static int imfs_remove_link(Node *node) {
	if (!node->in_use) {
		g_free_list[++g_free_list_size] = node->index;
		node->type = M_NON;
	}

	remove_child(node);
	node->doomed = 1;
	return 0;
}

static ssize_t __imfs_pipe_read(int cage_id, int fd, void *buf, size_t count,
				int pread, off_t offset) {
	Pipe *_pipe = get_pipe(cage_id, fd);

	LOG("[pipe] [read] offset=%zd status=%d\n", count,
	    _pipe->writefd->status);
	while (_pipe->writefd->status && _pipe->offset <= 0) {
	};

	int to_read = _pipe->offset;
	memcpy(buf, _pipe->data, to_read);
	_pipe->offset = 0;

	return to_read;
}

static ssize_t imfs_new_read(int cage_id, int fd, void *buf, size_t count,
			     int pread, off_t offset) {
	FileDesc *fdesc = get_filedesc(cage_id, fd);

	if ((fdesc->flags & O_ACCMODE) == O_WRONLY) {
		errno = EBADF;
		return -1;
	}

	Node *node = fdesc->node;
	off_t use_offset = pread ? offset : fdesc->offset;

	if (use_offset >= node->total_size)
		return 0;

	if (use_offset + count > node->total_size)
		count = node->total_size - use_offset;

	size_t read = 0;
	size_t local_offset = use_offset;
	Chunk *c = node->r_head;

	while (c && local_offset >= 1024) {
		local_offset -= 1024;
		c = c->next;
	}

	while (read < count && c) {
		size_t available = c->used - local_offset;
		size_t to_copy = count - read;
		if (to_copy > available) {
			to_copy = available;
		}

		memcpy(buf + read, c->data + local_offset, to_copy);

		read += to_copy;
		local_offset = 0;
		c = c->next;
	}

	if (!pread)
		fdesc->offset += read;

	return read;
}

static ssize_t __imfs_readv(int cage_id, int fd, const struct iovec *iov,
			    int len, off_t offset, int pread) {
	int ret, fin = 0;
	for (int i = 0; i < len; i++) {
		ret = imfs_new_read(cage_id, fd, iov[i].iov_base,
				    iov[i].iov_len, pread, offset);
		if (ret == -1)
			return ret;
		else
			fin += ret;
	}

	return fin;
}

static ssize_t __imfs_pipe_write(int cage_id, int fd, const void *buf,
				 size_t count, int pread, off_t offset) {
	Pipe *_pipe = get_pipe(cage_id, fd);

	memcpy(_pipe->data, buf, count);
	_pipe->offset += count;
	LOG("[pipe] offset=%zd\n", count);

	return count;
}

static ssize_t imfs_new_write(int cage_id, int fd, const void *buf,
			      size_t count, int pread, off_t offset) {
	FileDesc *fdesc = get_filedesc(cage_id, fd);

	if ((fdesc->flags & O_ACCMODE) == O_RDONLY) {
		errno = EBADF;
		return -1;
	}

	Node *node = fdesc->node;
	off_t use_offset = pread ? offset : (fdesc->flags & O_APPEND ? node->total_size : fdesc->offset);

	size_t written = 0;

	size_t chunk_offset = 0;
	Chunk *c = node->r_head;
	size_t local_offset = use_offset;

	while (c && local_offset >= 1024) {
		local_offset -= 1024;
		chunk_offset += c->used;
		if (!c->next)
			break;
		c = c->next;
	}

	while (written < count) {
		if (!c) {
			Chunk *new_chunk = calloc(1, sizeof(Chunk));
			if (!new_chunk)
				return -1;
			if (node->r_tail)
				node->r_tail->next = new_chunk;
			node->r_tail = new_chunk;
			if (!node->r_head)
				node->r_head = new_chunk;
			c = new_chunk;
		}

		size_t space = 1024 - local_offset;
		size_t to_copy = count - written;
		if (to_copy > space)
			to_copy = space;

		// Zero-fill any hole before writing
		if (local_offset > c->used) {
			memset(c->data + c->used, 0, local_offset - c->used);
		}

		memcpy(c->data + local_offset, buf + written, to_copy);

		if (local_offset + to_copy > c->used)
			c->used = local_offset + to_copy;

		written += to_copy;
		local_offset = 0;
		c = c->next;
	}

	if(use_offset + written > node->total_size)
		node->total_size = use_offset + written;

	if (!pread)
		fdesc->offset += written;

	clock_gettime(CLOCK_REALTIME, &node->mtime);

	return written;
}

static ssize_t __imfs_writev(int cage_id, int fd, const struct iovec *iov,
			     int count, off_t offset, int pread) {
	int ret, fin = 0;
	for (int i = 0; i < count; i++) {
		ret = imfs_new_write(cage_id, fd, iov[i].iov_base,
				     iov[i].iov_len, pread, count);
		if (ret == -1)
			return ret;
		else
			fin += ret;
	}
	return fin;
}

static int __imfs_stat(int cage_id, Node *node, struct stat *statbuf) {
	if (node == NULL)
		return -1;

	*statbuf = (struct stat){
	    .st_dev = GET_DEV,
	    .st_ino = node->index,
	    .st_mode = node->mode,
	    .st_nlink = 1,
	    .st_uid = GET_UID,
	    .st_gid = GET_GID,
	    .st_rdev = 0,
	    .st_size = node->total_size,
	    .st_blksize = 512,
	    .st_blocks = node->total_size / 512,
#ifdef __APPLE__
	    .st_atimespec = node->atime,
	    .st_mtimespec = node->mtime,
	    .st_ctimespec = node->ctime,
	    .st_birthtimespec = node->btime,
#else
	    .st_atim = node->atime,
	    .st_mtim = node->mtime,
	    .st_ctim = node->ctime,
#endif
	};

	return 0;
}

//
// Exported Utility Functions
//

void load_file(char *path) {
	FILE *fp = fopen("preloads.log", "a");

	fprintf(fp, "\n[load_file] loading=%s\n", path);

	char split_path[4096];
	strcpy(split_path, path);

	for (char *p = split_path + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			int ret = imfs_mkdir(0, split_path, 0755);
			*p = '/';
			fprintf(fp, "[load_file] mkdir=%d\n", ret);
		}
	}

	int imfs_fd = imfs_open(0, path, O_CREAT | O_WRONLY, 0777);
	fprintf(fp, "[load_file] created file: %s\n", path);

	size_t size;
	char *data = read_full_file(path, &size);

	imfs_write(0, imfs_fd, data, size);
	free(data);

	imfs_close(0, imfs_fd);
}

void dump_file(char *path, char *actual_path) {
	char split_path[4096];
	strcpy(split_path, path);

	for (char *p = split_path + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			int ret = mkdir(split_path, 0755);
			*p = '/';
		}
	}

	int fd = open(actual_path, O_CREAT | O_WRONLY | O_TRUNC, 0777);
	int ifd = imfs_open(0, path, O_RDONLY, 0);

	size_t nread;
	char buf[1024];

	while (1) {
		char buf[1024];
		size_t nread = imfs_read(0, ifd, buf, 1024);

		if (nread <= 0) {
			break;
		}

		write(fd, buf, nread);
	}

	close(fd);
	imfs_close(0, ifd);
}

void preloads(const char *env) {
	if (!env) {
		fprintf(stderr, "no preloads.\n");
		return;
	}

	char *list = strdup(env);
	if (!list) {
		return;
	}

	fprintf(stderr, "Loading all files\n");
	char *line = strtok(list, ":");

	FILE *fp = fopen("preloads.log", "a");

	while (line) {
		fprintf(fp, "Loading= %s\n", line);

		struct stat st;
		if (stat(line, &st) < 0) {
			line = strtok(NULL, ":");
			continue;
		}

		if (strlen(line) > 0) {
			if (S_ISREG(st.st_mode))
				load_file(line);
		}
		fprintf(fp, "Loaded {%s}\n", line);
		line = strtok(NULL, ":");
	}

	fclose(fp);
	free(list);
}

void imfs_init(void) {
	g_free_list_size = -1;

	for (int cage_id = 0; cage_id < MAX_PROCS; cage_id++) {
		for (int i = 0; i < MAX_FDS; i++) {
			g_fdtable[cage_id][i] = (FileDesc){
			    .node = NULL,
			    .offset = 0,
			};
		}
	}

	for (int i = 0; i < MAX_NODES; i++) {
		g_nodes[i] = (Node){
			.type = M_NON,
			.index = i,
			.in_use = 0,
			.d_count = 0,
			.total_size = 0,
			.mode = 0,
		};
		/* ensure dir children pointer is NULL and capacity zero */
		g_nodes[i].d_children = NULL;
		g_nodes[i].d_capacity = 0;
	}

	for (int i = 0; i < MAX_PROCS; i++) {
		g_fd_free_list_size[i] = -1;
	}

	for (int i = 0; i < MAX_PROCS; i++) {
		g_next_fd[i] = 3;
	}

	Node *root_node = imfs_create_node("/", M_DIR, 0755);
	root_node->parent_idx = root_node->index;

	Node *dot = imfs_create_node(".", M_LNK, 0);
	if (!dot)
		exit(1);
	dot->l_link = root_node;

	Node *dotdot = imfs_create_node("..", M_LNK, 0);
	if (!dotdot)
		exit(1);

	if (add_child(root_node, dot) != 0)
		exit(1);
	if (add_child(root_node, dotdot) != 0)
		exit(1);
	dotdot->l_link = root_node;

	g_root_node = &g_nodes[0];
}

//
// FS Entrypoints
//

int imfs_fcntl(int cage_id, int fd, int op, int arg) {
	FileDesc *fdesc = get_filedesc(cage_id, fd);

	if (!fdesc) {
		return -1;
	}

	switch (fd) {
		case F_GETFL:
			return fdesc->flags;
		default:
			return -1;
	}
}

int imfs_openat(int cage_id, int dirfd, const char *path, int flags,
		mode_t mode) {
	if (!path) {
		errno = EINVAL;
		return -1;
	}

	if (dirfd == -1) {
		errno = EBADF;
		return -EBADF;
	}

	int count;
	char namecomp[MAX_DEPTH][MAX_NODE_NAME];

	split_path(path, &count, namecomp);

	char *filename = namecomp[count - 1];

	Node *parent_node;

	parent_node =
	    imfs_find_node_namecomp(cage_id, dirfd, namecomp, count - 1);

	if (!parent_node || parent_node->type != M_DIR) {
		errno = ENOTDIR;
		return -ENOTDIR;
	}

	Node *node = imfs_find_node(cage_id, dirfd, path);

	// New File
	if (!node) {
		if (!(flags & O_CREAT)) {
			errno = ENOENT;
			return -ENOENT;
		}

		if (str_len(filename) > MAX_NODE_NAME - 1) {
			errno = ENAMETOOLONG;
			return -ENAMETOOLONG;
		}

		if (str_len(filename) > 64) {
			errno = ENAMETOOLONG;
			return -ENAMETOOLONG;
		}

		node = imfs_create_node(filename, M_REG, mode);
		if (!node) {
			return -ENOMEM;
		}

		if (add_child(parent_node, node) != 0) {
			errno = ENOMEM;
			node->type = M_NON;
			return -ENOMEM;
		}
	} else {
		// File Exists
		if (flags & O_EXCL && flags & O_CREAT) {
			errno = EEXIST;
			return -EEXIST;
		}

		if (node->type == M_DIR && !(flags & O_DIRECTORY)) {
			errno = EISDIR;
			return -EISDIR;
		}

		// Check for file access based on flags and mode.

		switch (O_ACCMODE & flags) {
			case O_RDONLY:
				if (!(node->mode & S_IRUSR)) {
					errno = EACCES;
					return -EACCES;
				}
				break;
			case O_RDWR:
				if (!(node->mode & S_IWUSR) ||
				    !(node->mode & S_IRUSR)) {
					errno = EACCES;
					return -EACCES;
				}
				break;
			case O_WRONLY:
				if (!(node->mode & S_IWUSR)) {
					errno = EACCES;
					return -EACCES;
				}
				break;
			default:
				break;
		}
	}

	return imfs_allocate_fd(cage_id, node, flags);
}

int imfs_open(int cage_id, const char *path, int flags, mode_t mode) {
	return imfs_openat(cage_id, AT_FDCWD, path, flags, mode);
}

int imfs_creat(int cage_id, const char *path, mode_t mode) {
	return imfs_open(cage_id, path, O_WRONLY | O_CREAT | O_TRUNC, mode);
}

int imfs_close(int cage_id, int fd) {
	if (fd < 0 || fd >= MAX_FDS || !g_fdtable[cage_id][fd].node) {
		errno = EBADF;
		return -1;
	}

	FileDesc *fdesc = get_filedesc(cage_id, fd);
	fdesc->node->in_use--;

	if (fdesc->node->doomed) {
		/* if it's a directory, free its children buffer */
		if (fdesc->node->type == M_DIR && fdesc->node->d_children) {
			free(fdesc->node->d_children);
			fdesc->node->d_children = NULL;
			fdesc->node->d_capacity = 0;
		}
		fdesc->node->type = M_NON;
		g_free_list[++g_free_list_size] = fdesc->node->index;
	}

	g_fd_free_list[cage_id][++g_fd_free_list_size[cage_id]] = fd;

	// Reclaim anonymous pipe if both fd's are closed.
	if (fdesc->node->type == M_PIP) {
		if (!fdesc->node->p_pipe->readfd->status &&
		    !fdesc->node->p_pipe->writefd->status) {
			imfs_remove_pipe(fdesc->node);
		}
	}

	*fdesc = (FileDesc){
	    .node = NULL,
	    .offset = 0,
	    .status = 0,
	};

	return 0;
}

ssize_t imfs_write(int cage_id, int fd, const void *buf, size_t count) {
	return imfs_new_write(cage_id, fd, buf, count, 0, 0);
}

ssize_t imfs_pwrite(int cage_id, int fd, const void *buf, size_t count,
		    off_t offset) {
	return imfs_new_write(cage_id, fd, buf, count, 1, offset);
}

ssize_t imfs_writev(int cage_id, int fd, const struct iovec *iov, int count) {
	return __imfs_writev(cage_id, fd, iov, count, 0, 0);
}

ssize_t imfs_pwritev(int cage_id, int fd, const struct iovec *iov, int count,
		     off_t offset) {
	return __imfs_writev(cage_id, fd, iov, count, offset, 1);
}

ssize_t imfs_read(int cage_id, int fd, void *buf, size_t count) {
	return imfs_new_read(cage_id, fd, buf, count, 0, 0);
}

ssize_t imfs_pread(int cage_id, int fd, void *buf, size_t count, off_t offset) {
	return imfs_new_read(cage_id, fd, buf, count, 1, offset);
}

ssize_t imfs_readv(int cage_id, int fd, const struct iovec *iov, int count) {
	return __imfs_readv(cage_id, fd, iov, count, 0, 0);
}

ssize_t imfs_preadv(int cage_id, int fd, const struct iovec *iov, int count,
		    off_t offset) {
	return __imfs_readv(cage_id, fd, iov, count, offset, 1);
}

int imfs_mkdirat(int cage_id, int fd, const char *path, mode_t mode) {
	if (!path) {
		errno = EINVAL;
		return -1;
	}

	Node *parent;

	char namecomp[MAX_DEPTH][MAX_NODE_NAME];
	int count;

	split_path(path, &count, namecomp);
	char *filename = namecomp[count - 1];

	if (str_compare(filename, ".") || str_compare(filename, "..")) {
		errno = EINVAL;
		return -1;
	}

	// Invalid path (parent doesn't exist)
	parent = imfs_find_node_namecomp(cage_id, fd, namecomp, count - 1);
	if (!parent) {
		errno = EINVAL;
		return -1;
	}

	Node *node;

	// Invalid path (directory already exists)
	node = imfs_find_node_namecomp(cage_id, fd, namecomp, count);
	if (node) {
		errno = EEXIST;
		return -1;
	}

	// Node creation failed
	node = imfs_create_node(filename, M_DIR, mode);
	if (!node) {
		return -1;
	}

	// Add new node to parent, and add . & .. to new node.
	if (add_child(parent, node) != 0) {
		errno = ENOMEM;
		node->type = M_NON;
		return -1;
	}

	Node *dot = imfs_create_node(".", M_LNK, 0);
	if (!dot)
		return -1;
	dot->l_link = node;

	Node *dotdot = imfs_create_node("..", M_LNK, 0);
	if (!dotdot)
		return -1;

	if (add_child(node, dot) != 0)
		return -1;
	if (add_child(node, dotdot) != 0)
		return -1;

	dotdot->l_link = &g_nodes[node->parent_idx];

	LOG("Created Node: \n");
	LOG("Index: %d \n", node->index);
	LOG("Name: %s\n", node->name);
	LOG("Type: %d\n", node->type);

	return 0;
}

int imfs_mkdir(int cage_id, const char *path, mode_t mode) {
	return imfs_mkdirat(cage_id, AT_FDCWD, path, mode);
}

int imfs_linkat(int cage_id, int olddirfd, const char *oldpath, int newdirfd,
		const char *newpath, int flags) {
	Node *oldnode = imfs_find_node(cage_id, olddirfd, oldpath);

	if (!oldnode) {
		errno = EINVAL;
		return -1;
	}

	char namecomp[MAX_DEPTH][MAX_NODE_NAME];
	int count;

	Node *newnode = imfs_find_node(cage_id, newdirfd, newpath);
	if (newnode != NULL) {
		errno = EINVAL;
		return -1;
	}

	split_path(newpath, &count, namecomp);

	char *filename = namecomp[count - 1];

	Node *newnode_parent =
	    imfs_find_node_namecomp(cage_id, newdirfd, namecomp, count - 1);
	newnode = imfs_create_node(filename, M_LNK, 0);

	newnode->l_link = oldnode;

	if (add_child(newnode_parent, newnode) != 0) {
		errno = ENOMEM;
		newnode->type = M_NON;
		return -1;
	}

	clock_gettime(CLOCK_REALTIME, &newnode->ctime);

	return 0;
}

int imfs_link(int cage_id, const char *oldpath, const char *newpath) {
	return imfs_linkat(cage_id, AT_FDCWD, oldpath, AT_FDCWD, newpath, 0);
}

int imfs_symlink(int cage_id, const char *oldpath, const char *newpath) {
	return imfs_linkat(cage_id, AT_FDCWD, oldpath, AT_FDCWD, newpath, 0);
}

int imfs_rename(int cage_id, const char *oldpath, const char *newpath) {
	int count;
	char namecomp[MAX_DEPTH][MAX_NODE_NAME];

	split_path(oldpath, &count, namecomp);
	Node *current_node =
	    imfs_find_node_namecomp(0, AT_FDCWD, namecomp, count);
	if (!current_node) {
		errno = ENOENT;
		return -1;
	}

	split_path(newpath, &count, namecomp);
	Node *new_parent =
	    imfs_find_node_namecomp(0, AT_FDCWD, namecomp, count - 1);
	char *new_filename = namecomp[count - 1];
	if (!new_parent) {
		errno = ENOENT;
		return -1;
	}

	str_ncopy(current_node->name, new_filename, MAX_NODE_NAME);
	int length = str_len(new_filename);
	current_node->name[length] = '\0';

	// Remode node from old parent.
	remove_child(current_node);

	// Add node to new parent
	add_child(new_parent, current_node);

	return 0;
}

int imfs_chown(int cage_id, const char *pathname, uid_t owner, gid_t group) {
	Node *node = imfs_find_node(cage_id, AT_FDCWD, pathname);
	if (!node) {
		return -1;
	}

	node->owner = owner;
	node->group = group;

	clock_gettime(CLOCK_REALTIME, &node->ctime);
	return 0;
}

int imfs_chmod(int cage_id, const char *pathname, mode_t mode) {
	Node *node = imfs_find_node(cage_id, AT_FDCWD, pathname);

	if (!node) {
		errno = ENOENT;
		return -1;
	}

	node->mode = (node->mode & ~0777) | mode;

	return 0;
}

int imfs_fchmod(int cage_id, int fd, mode_t mode) {
	FileDesc *fdesc = get_filedesc(cage_id, fd);

	if (!fdesc || !fdesc->node) {
		errno = ENOENT;
		return -1;
	}

	fdesc->node->mode = (fdesc->node->mode & ~0777) | mode;

	return 0;
}

int imfs_remove(int cage_id, const char *pathname) {
	Node *node = imfs_find_node(cage_id, AT_FDCWD, pathname);

	if (!node) {
		errno = ENOENT;
		return -1;
	}

	switch (node->type) {
		case M_DIR:
			return imfs_remove_dir(node);
		case M_LNK:
			return imfs_remove_link(node);
		case M_REG:
			return imfs_remove_file(node);
		default:
			return 0;
	}
}

int imfs_rmdir(int cage_id, const char *pathname) {
	return imfs_remove(cage_id, pathname);
}

int imfs_unlink(int cage_id, const char *pathname) {
	return imfs_remove(cage_id, pathname);
}

off_t imfs_lseek(int cage_id, int fd, off_t offset, int whence) {
	FileDesc *fdesc = get_filedesc(cage_id, fd);

	if (!fdesc->node) {
		errno = EBADF;
		return -1;
	}

	off_t ret = fdesc->offset;

	// SEEK_HOLE and SEEK_DATA need to be reworked. Unclear as to what it is
	// they do
	switch (whence) {
		case SEEK_SET:
			ret = offset;
			break;
		case SEEK_CUR:
			ret += offset;
			break;
		case SEEK_END:
			ret = fdesc->node->total_size + offset;
			break;
#ifdef _GNU_SOURCE
		case SEEK_HOLE:
			while (*(char *)(fdesc->node + ret)) {
				ret++;
			}
			break;
		case SEEK_DATA:
			while (!*(char *)(fdesc->node + ret)) {
				ret++;
			}
			break;
#endif
		default:
			errno = EINVAL;
			return ret - 1;
	}

	fdesc->offset = ret;

	return ret;
}

int imfs_dup(int cage_id, int fd) { return imfs_dup_fd(cage_id, fd, -1); }

int imfs_dup2(int cage_id, int oldfd, int newfd) {
	return imfs_dup_fd(cage_id, oldfd, newfd);
}

int imfs_lstat(int cage_id, const char *pathname, struct stat *statbuf) {
	Node *node = imfs_find_node(cage_id, AT_FDCWD, pathname);
	return __imfs_stat(cage_id, node, statbuf);
}

int imfs_stat(int cage_id, const char *pathname, struct stat *statbuf) {
	LOG("cage=%d pathname=%s\n", cage_id, pathname);
	Node *node = imfs_find_node(cage_id, AT_FDCWD, pathname);
	if (!node) {
		errno = ENOENT;
		return -1;
	}
	if (node->type == M_LNK)
		return __imfs_stat(cage_id, node->l_link, statbuf);
	return __imfs_stat(cage_id, node, statbuf);
}

int imfs_fstat(int cage_id, int fd, struct stat *statbuf) {
	Node *node = get_filedesc(cage_id, fd)->node;
	if (node->type == M_LNK)
		return __imfs_stat(cage_id, node->l_link, statbuf);
	return __imfs_stat(cage_id, node, statbuf);
}

I_DIR *imfs_opendir(int cage_id, const char *name) {
	I_DIR *dirstream = NULL;
	int fd = imfs_open(cage_id, name, O_DIRECTORY, 0);
	Node *node = get_filedesc(cage_id, fd)->node;

	*dirstream = (I_DIR){
	    .fd = fd,
	    .node = node,
	    .size = 0,
	    .offset = 0,
	    .filepos = 0,
	};

	return dirstream;
}

struct dirent *imfs_readdir(int cage_id, I_DIR *dirstream) {
	struct dirent *ret = malloc(sizeof(struct dirent));

	Node *dirnode = dirstream->node;

	if (dirstream->offset >= dirnode->d_count) {
		return NULL;
	}

	// Next entry

	struct DirEnt nextentry = dirnode->d_children[dirstream->offset++];

	int ino = nextentry.node->index;
	int _type = nextentry.node->type;
	size_t namelen = str_len(nextentry.name);

	*ret = (struct dirent){
	    .d_ino = ino,   // 8
	    .d_reclen = 32, // 24
	    // .d_namlen = namelen,  // 32 + X
	    .d_type = _type, // 36 + X
	};

	str_ncopy(ret->d_name, nextentry.name, namelen);
	ret->d_name[namelen + 1] = '\0';

	return ret;
}

// pipe and pipe2 have only gone limited testing. Since IMFS doesn't support
// multi-processing on native builds, these need to be tested out in Lind.
int imfs_pipe(int cage_id, int pipefd[2]) {
	Node *pipenode = imfs_create_node("APIP", M_PIP, 0);
	pipefd[0] = imfs_allocate_fd(cage_id, pipenode, O_RDONLY);
	pipefd[1] = imfs_allocate_fd(cage_id, pipenode, O_WRONLY);

	pipenode->p_pipe = mmap(NULL, sizeof(Pipe), PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	pipenode->p_pipe->offset = 0;
	pipenode->p_pipe->readfd = get_filedesc(cage_id, pipefd[0]);
	pipenode->p_pipe->writefd = get_filedesc(cage_id, pipefd[1]);

	return 0;
}

int imfs_pipe2(int cage_id, int pipefd[2], int flags) {
	return imfs_pipe(cage_id, pipefd);
}

int imfs_mkfifo(int cage_id, const char *pathname, mode_t mode) {
	errno = EOPNOTSUPP;
	return -1;
}

int imfs_mknod(int cage_id, const char *pathname, mode_t mode, dev_t dev) {
	errno = EOPNOTSUPP;
	return -1;
}

int imfs_bind(int cage_id, int sockfd, const struct sockaddr *addr,
	      socklen_t length) {
	errno = EOPNOTSUPP;
	return -1;
}

int imfs_pathconf(int cage_id, const char *pathname, int name) {
	return PC_CONSTS[name];
}

int imfs_fpathconf(int cage_id, int fd, int name) { return PC_CONSTS[name]; }

