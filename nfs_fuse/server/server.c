#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <libsocket/libinetsocket.h>

#include "../common/headers.h"
#include "../third_party/log.c/src/log.h"

static char* nfs_root_path;
static int nfs_root_path_l;

// File descriptor for the connection. It's acquired before the fork so
// technically each fork can access the connections from other forks, which
// is kinda bad... But our implementation should really be discarding them
// so there shouldn't be a way of figuring out the difference :)
// TODO Ensure this global variable won't create problems.
static int cfd;

void sig_handler(int signo) {
  close(cfd);
}

// Forward declare for use by _create.
void handle_request_getattr(char* complete_path);

// This appends the requested path to the nfs root folder.
char* make_complete_path(char* added_path, int len) {
  log_trace("Appending |%s| (%d) %s", nfs_root_path, len, added_path);
  char* complete_path = malloc(nfs_root_path_l + len + 1);
  memcpy(complete_path, nfs_root_path, nfs_root_path_l);
  memcpy(complete_path + nfs_root_path_l, added_path, len);
  complete_path[nfs_root_path_l + len] = '\0';
  log_trace("My complete path is %s", complete_path);

  return complete_path;
}

request_t* read_request(int cfd) {
  // Make sure we have the right types/sizes.
  request_t req;
  read(cfd, &req.type, sizeof(req.type));
  read(cfd, &req.path_l, sizeof(req.path_l));

  // +1 length for \0.
  request_t* req_ptr = malloc(sizeof(request_t) + req.path_l + 1);
  req_ptr->type   = req.type;
  req_ptr->path_l = req.path_l;

  read(cfd, req_ptr->path, req_ptr->path_l);
  req_ptr->path[req_ptr->path_l] = '\0';

  log_debug("Received Request");
  log_debug("Path: (%d) %s", req_ptr->path_l, req_ptr->path);
  return req_ptr;
}

void handle_request_create(char* complete_path) {
  log_trace("Handling Request: Create %s", complete_path);

  request_create_t req_create;
  read(cfd, &req_create, sizeof(request_create_t));

  int fd;
  response_create_t resp_create;

  resp_create.ret = 0;
  if ((fd = creat(complete_path, req_create.mode)) == -1) {
    log_error("Couldn't open file %s with flags %x: %s",
              complete_path, req_create.mode, strerror(errno));
    resp_create.ret = errno;
  } else if (fstat(fd, &resp_create.sb) == -1) {
    log_error("Bug: Couldn't get stats for file %s with: %s",
              complete_path, strerror(errno));
    resp_create.ret = -EFAULT;
    unlink(complete_path);
  }
  close(fd);

  write(cfd, &resp_create, sizeof(response_open_t));
  log_trace("End Handling Create");
}

void handle_request_chmod(char* complete_path) {
  log_trace("Handling Request: Chmod %s", complete_path);

  request_chmod_t req_mode;
  read(cfd, &req_mode, sizeof(request_chmod_t));

  response_chmod_t resp;
  memset(&resp.sb, 0, sizeof(struct stat));
  resp.ret = 0;
  if (chmod(complete_path, req_mode.mode) != 0) {
    resp.ret = errno;
    log_error("Error setting mod of %s: %s", complete_path, strerror(errno));
  } else if (stat(complete_path, &resp.sb) != 0) {
    log_error("Unable to retrieve stats for %s: %s",
              complete_path, strerror(errno));
  }

  write(cfd, &resp, sizeof(response_chmod_t));

  log_trace("End Handling Chmod");
}

void handle_request_chown(char* complete_path) {
  log_trace("Handling Request: Chown %s", complete_path);

  request_chown_t req_own;
  read(cfd, &req_own, sizeof(request_chown_t));

  response_chown_t resp;
  memset(&resp.sb, 0, sizeof(struct stat));
  resp.ret = 0;
  if (chown(complete_path, req_own.uid, req_own.gid) != 0) {
    resp.ret = errno;
    log_error("Error setting own of %s: %s", complete_path, strerror(errno));
  } else if (stat(complete_path, &resp.sb) != 0) {
    log_error("Unable to retrieve stats for %s: %s",
              complete_path, strerror(errno));
  }

  write(cfd, &resp, sizeof(response_chown_t));

  log_trace("End Handling Chown");
}

void handle_request_destroy(char* complete_path) {
  log_trace("Handling Request: Destroy %s");
  close(cfd);
  log_trace("End Handling Destroy");
}

void handle_request_getattr(char* complete_path) {
  log_trace("Handling Request: GetAttr %s", complete_path);

  response_getattr_t resp_getattr;
  resp_getattr.ret = stat(complete_path, &resp_getattr.sb);

  if (resp_getattr.ret == 0) {
    log_trace("Stats for %s: %d %d %d (ret %d)",
        complete_path,
        resp_getattr.sb.st_uid,
        resp_getattr.sb.st_gid,
        resp_getattr.sb.st_size,
        resp_getattr.ret);
  } else {
    resp_getattr.ret = errno;
    log_error("Failed to get stat for %s: %s", complete_path, strerror(errno));
  }

  write(cfd, &resp_getattr, sizeof(response_getattr_t));
  log_trace("End Handling GetAttr");
}

void handle_request_mkdir(char* complete_path) {
  log_trace("Handling Request: Mkdir %s", complete_path);

  mode_t mode;
  read(cfd, &mode, sizeof(mode_t));

  int ret = mkdir(complete_path, mode);
  if (ret != 0) {
    ret = errno;
    log_error("Failed to mkdir for %s: %s", complete_path, strerror(errno));
  }
  write(cfd, &ret, sizeof(int));

  log_trace("End Handling Mkdir");
}

void handle_request_open(char* complete_path) {
  log_trace("Handling Request: Open %s", complete_path);

  request_open_t req_open;
  read(cfd, &req_open, sizeof(request_open_t));

  int fd;
  response_open_t resp_open;

  resp_open.ret = 0;
  if ((fd = open(complete_path, req_open.flags)) == -1) {
    log_error("Couldn't open file %s with flags %x: %s",
              complete_path, req_open.flags, strerror(errno));
    resp_open.ret = errno;
  } else if (fstat(fd, &resp_open.sb) == -1) {
    log_error("Couldn't get stats for file %s with: %s",
              complete_path, strerror(errno));
    resp_open.ret = ENOENT; // Need to have open errors.
  }
  close(fd);

  write(cfd, &resp_open, sizeof(response_open_t));
  log_trace("End Handling Open");
}

// Should only happen on non cached environments.
void handle_request_read(char* complete_path) {
  log_trace("Handling Request: Read %s", complete_path);
  request_read_t req_read;
  read(cfd, &req_read, sizeof(request_read_t));

  int open_flags = O_RDONLY;
  int fd = open(complete_path, open_flags);
  if (fd == -1) {
    log_error("Couldn't open file %s: %s", complete_path, strerror(errno));
    response_read_t resp_read;
    resp_read.ret = errno;
    resp_read.size = 0;
    write(cfd, &resp_read, sizeof(response_read_t));
    return;
  }

  struct stat sb;
  if (fstat(fd, &sb) == -1) {
    log_error("Couldn't get stat for %s: %s", complete_path, strerror(errno));
    response_read_t resp_read;
    resp_read.ret = errno;
    resp_read.size = 0;
    write(cfd, &resp_read, sizeof(response_read_t));
    return;
  } else {
    log_debug("File should have %d bytes - trying to read %d at off %d",
        sb.st_size, req_read.size, req_read.offset);
    if (req_read.offset < sb.st_size &&
        req_read.offset + req_read.size > sb.st_size) {
      req_read.size = sb.st_size - req_read.offset;
    } else {
      req_read.size = 0;
    }
    log_debug("Actually reading %lu", req_read.size);

    size_t resp_l = sizeof(response_read_t) + req_read.size;
    response_read_t* resp_read = malloc(resp_l);
    resp_read->ret = 0;
    resp_read->stamp = sb.st_mtim;
    resp_read->size = req_read.size;

    if (pread(fd, resp_read->data, resp_read->size, req_read.offset) == -1) {
      resp_read->ret = errno;
      log_error("Read %s failed (%d): %s",
                complete_path, resp_read->ret, strerror(errno));
    }

    write(cfd, resp_read, resp_l);
    free(resp_read);
    close(fd);
  }

  log_trace("End Handling Read %s", complete_path);
}

void handle_request_readdir(char* complete_path) {
  log_trace("Handling Request: Read Dir %s", complete_path);

  response_readdir_t resp_readdir;
  struct dirent* dp;
  DIR* dirp;

  if ((dirp = opendir(complete_path)) == NULL) {
    resp_readdir.ret = ENOENT;
    resp_readdir.size = 0;
    write(cfd, &resp_readdir, sizeof(response_readdir_t));
    return;
  }

  // To much work to do it efficiently, so using two pass strategy.
  // One pass just to count, so that we can allocate the proper size.
  int total_name_alloc_size = 0;
  errno = 0;
  resp_readdir.size = 0;
  resp_readdir.ret = 0;
  while ((dp = readdir(dirp)) != NULL) {
    log_trace("Found path %s", dp->d_name);
    resp_readdir.size++;
    total_name_alloc_size += strlen(dp->d_name);
  }

  if (errno != 0) {
    resp_readdir.ret = errno;
    resp_readdir.size = 0;
    write(cfd, &resp_readdir, sizeof(response_readdir_t));
    return;
  }

  log_debug("At dir %s got %d entries with total name length of %d",
      complete_path, resp_readdir.size, total_name_alloc_size);

  int total_resp_size =
      sizeof(response_readdir_t) +
      resp_readdir.size*sizeof(response_readdir_entry_t) +
      total_name_alloc_size;

  response_readdir_t* resp_readdir_ptr = malloc(total_resp_size);

  resp_readdir_ptr->ret = resp_readdir.ret;
  resp_readdir_ptr->size = resp_readdir.size;

  // Reset the directory for another read.
  closedir(dirp);
  dirp = opendir(complete_path);

  errno = 0;
  response_readdir_entry_t* ent = (response_readdir_entry_t*) resp_readdir_ptr->data;
  while ((dp = readdir(dirp)) != NULL) {
    int complete_path_l = strlen(complete_path);
    int entry_name_l = strlen(dp->d_name);
    int entry_l = sizeof(response_readdir_entry_t) + entry_name_l;

    char* total_path = malloc(complete_path_l + entry_name_l + 1);
    memcpy(total_path, complete_path, complete_path_l);
    memcpy(total_path + complete_path_l, dp->d_name, entry_name_l);
    total_path[complete_path_l + entry_name_l] = '\0';
    stat(total_path, &ent->sb);
    free(total_path);

    ent->name_l = entry_name_l;
    memcpy(ent->name, dp->d_name, entry_name_l);
    ent = (response_readdir_entry_t*) (((char*) ent) + entry_l);
  }

  if (errno != 0) {
    free(resp_readdir_ptr);
    resp_readdir.ret = errno;
    resp_readdir.size = 0;
    write(cfd, &resp_readdir, sizeof(response_readdir_t));
    log_trace("End Handling Read Dir");
    return;
  }

  write(cfd, resp_readdir_ptr, total_resp_size);
  free(resp_readdir_ptr);
  closedir(dirp);

  log_trace("End Handling Read Dir");
}

void handle_request_release(char* complete_path) {
  log_trace("Handling Request: Release %s", complete_path);

  // Every operation opens the file anyway, so no need to open file here.
  int ret = 0;
  write(cfd, &ret, sizeof(int));

  log_trace("End Handling Release");
}

void handle_request_rmdir(char* complete_path) {
  log_trace("Handling Request: Rmdir %s", complete_path);

  int ret = rmdir(complete_path);
  if (ret != 0) {
    log_error("Unable to Rmdir %s: %s", complete_path, strerror(errno));
    ret = errno;
  }
  write(cfd, &ret, sizeof(int));

  log_trace("End Handling Rmdir");
}

void handle_request_statvfs(char* complete_path) {
  log_trace("Handling Request: StatVFS %s", complete_path);

  response_statvfs_t resp;
  if (statvfs(complete_path, &resp.sb) == -1) {
    log_error("Unable to get statvfs: %s", strerror(errno));
    resp.ret = errno;
  } else {
    resp.ret = 0;
  }

  log_trace("Got FS of bsize %d", resp.sb.f_bsize);
  write(cfd, &resp, sizeof(response_statvfs_t));

  log_trace("End Handling StatVFS");
}

void handle_request_truncate(char* complete_path) {
  log_trace("Handling Request: Truncate %s", complete_path);

  request_truncate_t req_trunc;
  read(cfd, &req_trunc, sizeof(request_truncate_t));

  response_truncate_t resp;
  memset(&resp.sb, 0, sizeof(struct stat));
  resp.ret = truncate(complete_path, req_trunc.offset);
  if (resp.ret != 0) {
    log_error("Unable to truncate %s: %s", complete_path, strerror(errno));
    resp.ret = errno;
  } else if (stat(complete_path, &resp.sb) == -1) {
    log_error("Couldn't get stats for file %s with: %s",
              complete_path, strerror(errno));
  }
  write(cfd, &resp, sizeof(response_truncate_t));

  log_trace("End Handling Truncate");
}

void handle_request_unlink(char* complete_path) {
  log_trace("Handling Request: Unlink %s", complete_path);

  int ret = unlink(complete_path);
  if (ret != 0) {
    log_error("Unable to unlink %s: %s", complete_path, strerror(errno));
    ret = errno;
  }
  write(cfd, &ret, sizeof(int));

  log_trace("End Handling Unlink");
}

void handle_request_utimens(char* complete_path) {
  log_trace("Handling Request: Utimens %s", complete_path);

  struct timespec tv[2];
  read(cfd, &tv, 2*sizeof(struct timespec));

  response_utimens_t resp;
  memset(&resp.sb, 0, sizeof(resp.sb));
  resp.ret = 0;
  int fd;
  if ((fd = open(complete_path, O_WRONLY | O_TRUNC)) == -1) {
    log_error("Unable to open file for utimens %s: %s",
              complete_path, strerror(errno));
    resp.ret = errno;
  } else if (futimens(fd, tv) == -1) {
    log_error("Unable to set utimens for %s: %s",
              complete_path, strerror(errno));
    resp.ret = errno;
    return;
  } else if (fstat(fd, &resp.sb) == -1) {
    log_error("Unable to retrieve stats for %s: %s",
              complete_path, strerror(errno));
  }

  write(cfd, &resp, sizeof(response_utimens_t));
  log_trace("End Handling Utimens");
}

void handle_request_write(char* complete_path) {
  log_trace("Handling Request: Write %s", complete_path);

  request_write_t req_write;
  read(cfd, &req_write, sizeof(request_write_t));
  char* data = malloc(req_write.size);
  read(cfd, data, req_write.size);
  log_debug("Write: Got data of length %lu at off %lu",
            req_write.size, req_write.offset);

  response_write_t resp_write;

  int access = O_WRONLY;
  int fd = open(complete_path, access, S_IRWXU);
  if (fd == -1) {
    log_error("Unable to open file %s with write, create, truncate: %s",
              complete_path, strerror(errno));
    resp_write.ret = errno;
    resp_write.size = 0;
  } else {
    log_trace("Opened file");

    resp_write.ret = pwrite(fd, data, req_write.size, req_write.offset);
    if (resp_write.ret == -1 || fstat(fd, &resp_write.sb) == -1) {
      log_error("Unable to write file %s: %s",
                complete_path, strerror(errno));
      resp_write.ret  = errno;
      resp_write.size = 0;
    } else {
      log_trace("Wrote to file");

      resp_write.size = resp_write.ret;
      resp_write.ret = 0;
    }

    close(fd);
  }

  free(data);
  write(cfd, &resp_write, sizeof(response_write_t));

  log_trace("End Handling Write");
}

void handle_requests() {
  while (1) {
    request_t* req = read_request(cfd);
    char* complete_path = make_complete_path(req->path, req->path_l);

    switch (req->type) {
      case NFS_FUSE_REQUEST_CREATE:   handle_request_create(complete_path);
        break;
      case NFS_FUSE_REQUEST_CHMOD:    handle_request_chmod(complete_path);
        break;
      case NFS_FUSE_REQUEST_CHOWN:    handle_request_chown(complete_path);
        break;
      case NFS_FUSE_REQUEST_DESTROY:  handle_request_destroy(complete_path);
                                      return;
        break;
      case NFS_FUSE_REQUEST_GETATTR:  handle_request_getattr(complete_path);
        break;
      case NFS_FUSE_REQUEST_MKDIR:    handle_request_mkdir(complete_path);
        break;
      case NFS_FUSE_REQUEST_OPEN:     handle_request_open(complete_path);
        break;
      case NFS_FUSE_REQUEST_READ:     handle_request_read(complete_path);
        break;
      case NFS_FUSE_REQUEST_READDIR:  handle_request_readdir(complete_path);
        break;
      case NFS_FUSE_REQUEST_RELEASE:  handle_request_release(complete_path);
        break;
      case NFS_FUSE_REQUEST_RMDIR:    handle_request_rmdir(complete_path);
        break;
      case NFS_FUSE_REQUEST_STATVFS:  handle_request_statvfs(complete_path);
        break;
      case NFS_FUSE_REQUEST_TRUNCATE: handle_request_truncate(complete_path);
        break;
      case NFS_FUSE_REQUEST_UNLINK:   handle_request_unlink(complete_path);
        break;
      case NFS_FUSE_REQUEST_UTIMENS:  handle_request_utimens(complete_path);
        break;
      case NFS_FUSE_REQUEST_WRITE:    handle_request_write(complete_path);
        break;
      // Socket broken case.
      default:
        log_error("Invalid request type or not properly formatted.");
        handle_request_destroy("");
        return;
    }

    free(complete_path);
    free(req);
  }
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    log_error("Wrong number of arguments!");
    exit(1);
  }

  nfs_root_path = argv[1];
  nfs_root_path_l = strlen(argv[1]);

  log_set_level(LOG_TRACE);
  int sfd;
  char src_host[128], src_port[7];

  src_host[127] = 0;
  src_port[6] = 0;

  sfd = create_inet_server_socket(
      "::", "1111", LIBSOCKET_TCP, LIBSOCKET_IPv6, 0);
  if (sfd == -1) {
    perror("Couldn't create server");
    exit(1);
  }
  log_trace("Socket up and running");

  while (1) {
    cfd = accept_inet_stream_socket(
        sfd, src_host, 127, src_port, 6, LIBSOCKET_NUMERIC,0);
    if (cfd == -1) {
      perror("Couldn't accept connection");
      exit(1);
    }

    log_debug("Connection from %s port %s.", src_host, src_port);
    if (fork() == 0) {
      struct sigaction sa;
      sa.sa_handler = &sig_handler;
      sa.sa_flags = SA_RESTART;
      sigfillset(&sa.sa_mask);
      sigaction(SIGSTOP, &sa, NULL);

      handle_requests();
      return 0;
    }
  }

  if (destroy_inet_socket(sfd) < 0) {
    perror(0);
    exit(1);
  }

  return 0;
}
