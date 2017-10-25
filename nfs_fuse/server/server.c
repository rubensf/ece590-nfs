#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
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

char* nfs_root_path;
int nfs_root_path_l;

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

void handle_request_create(int cfd, char* complete_path) {
  log_trace("Handling Create %s", complete_path);
  request_create_t req_create;
  read(cfd, &req_create, sizeof(request_create_t));

  int ret = 0;
  int fd = creat(complete_path, req_create.mode);
  if (fd == -1) {
    ret = errno;
    log_error("Error creating %s: %s", complete_path, strerror(errno));
  }

  write(cfd, &ret, sizeof(int));
  close(fd);

  log_trace("End handling Create.");
}

void handle_request_chmod(int cfd, char* complete_path) {
  log_trace("Handling Chmod %s", complete_path);
  request_chmod_t req_mode;
  read(cfd, &req_mode, sizeof(request_chmod_t));

  int ret = 0;
  if (chmod(complete_path, req_mode.mode) != 0) {
    ret = errno;
    log_error("Error setting mod of %s: %s", complete_path, strerror(errno));
  }

  write(cfd, &ret, sizeof(int));

  log_trace("End handling Create.");
}

void handle_request_chown(int cfd, char* complete_path) {
  log_trace("Handling Chown %s", complete_path);
  request_chown_t req_own;
  read(cfd, &req_own, sizeof(request_chown_t));

  int ret = 0;
  if (chown(complete_path, req_own.uid, req_own.gid) != 0) {
    ret = errno;
    log_error("Error setting mod of %s: %s", complete_path, strerror(errno));
  }

  write(cfd, &ret, sizeof(int));

  log_trace("End handling Create.");
}

void handle_request_destroy(int cfd, char* complete_path) {
  log_debug("Handling Destroy Request.");
  // TODO I don't know what to do here.
}

void handle_request_getattr(int cfd, char* complete_path) {
  log_debug("Handling GetAttr Request: %s", complete_path);

  response_getattr_t resp_getattr;
  resp_getattr.ret = stat(complete_path, &resp_getattr.sb);

  if (resp_getattr.ret == 0) {
    log_trace("Stats for %s: %d %d %d",
        complete_path,
        resp_getattr.sb.st_uid,
        resp_getattr.sb.st_gid,
        resp_getattr.sb.st_size);
  } else {
    resp_getattr.ret = errno;
    log_trace("Failed to get stat: %s", strerror(resp_getattr.ret));
  }

  write(cfd, &resp_getattr, sizeof(response_getattr_t));
  log_trace("End Handling GetAttr.");
}

void handle_request_mkdir(int cfd, char* complete_path) {
  log_trace("handling mkdir. %s", complete_path);

  mode_t mode;
  read(cfd, &mode, sizeof(mode_t));

  int ret = mkdir(complete_path, mode);
  if (ret != 0) ret = errno;
  write(cfd, &ret, sizeof(int));

  log_trace("end handling mkdir.");
}

void handle_request_read(int cfd, char* complete_path) {
  log_trace("Handling Read %s", complete_path);
  request_read_t req_read;
  read(cfd, &req_read, sizeof(request_read_t));

  int open_flags = O_RDONLY;
  int fd = open(complete_path, open_flags);

  struct stat sb;
  if (fstat(fd, &sb) == -1) {
    fprintf(stderr, "Couldn't get stat for %s:%s\n", complete_path, strerror(errno));
    exit(1);
  }

  log_debug("File should have %d bytes - trying to read %d at off %d",
      sb.st_size, req_read.size, req_read.offset);
  if (req_read.offset < sb.st_size && req_read.offset + req_read.size > sb.st_size) {
    req_read.size = sb.st_size - req_read.offset;
  } else {
    req_read.size = 0;
  }
  log_debug("Actually reading %lu", req_read.size);

  response_read_t resp_read;
  resp_read.ret = 0;
  resp_read.size = req_read.size;

  char* data = malloc(resp_read.size);
  if (read(fd, data, resp_read.size) != 0) {
    resp_read.ret = errno;
    log_trace("Read %s failed: %s", complete_path, strerror(errno));
  }

  write(cfd, &resp_read, sizeof(response_read_t));
  write(cfd, data, resp_read.size);
  free(data);
  close(fd);

  log_trace("End Handling Read %s", complete_path);
}

void handle_request_readdir(int cfd, char* complete_path) {
  log_trace("Handling Read Dir %s", complete_path);

  response_readdir_t resp_readdir;
  struct dirent* dp;
  DIR* dirp;

  if ((dirp = opendir(complete_path)) == NULL) {
    resp_readdir.ret = -ENOENT;
    resp_readdir.size = 0;
    write(cfd, &resp_readdir, sizeof(response_readdir_t));
    return;
  }

  int total_name_alloc_size = 0;

  // To much work to do it efficiently, so using two pass strategy.
  // One pass just to count, so that we can allocate the proper size.
  errno = 0;
  resp_readdir.size = 0;
  resp_readdir.ret = 0;
  while ((dp = readdir(dirp)) != NULL) {
    log_debug("Found path %s", dp->d_name);
    resp_readdir.size++;
    total_name_alloc_size += strlen(dp->d_name);
  }

  if (errno != 0) {
    resp_readdir.ret = -ENOENT;
    resp_readdir.size = 0;
    write(cfd, &resp_readdir, sizeof(response_readdir_t));
    return;
  }

  log_debug("Got %d entries with total name length of %d",
      resp_readdir.size, total_name_alloc_size);

  int total_resp_size =
      sizeof(response_readdir_t) +
      resp_readdir.size*sizeof(response_readdir_entry_t) +
      total_name_alloc_size;
  response_readdir_t* resp_readdir_ptr = malloc(total_resp_size);

  resp_readdir_ptr->ret = resp_readdir.ret;
  resp_readdir_ptr->size = resp_readdir.size;

  closedir(dirp);
  dirp = opendir(complete_path);

  errno = 0;
  response_readdir_entry_t* ent = (response_readdir_entry_t*) resp_readdir_ptr->data;
  log_trace("Response is at %p while entry at %p", resp_readdir_ptr, ent);
  while ((dp = readdir(dirp)) != NULL) {
    int complete_path_l = strlen(complete_path);
    int entry_name_l = strlen(dp->d_name);
    int entry_l = sizeof(response_readdir_entry_t) + entry_name_l;
    char* total_path = malloc(complete_path_l + entry_name_l + 1);
    total_path[0] = '\0';
    strncat(total_path, complete_path, complete_path_l);
    strncat(total_path, dp->d_name, entry_name_l);
    total_path[complete_path_l + entry_name_l] = '\0';

    log_trace("READDIR: Name length for %s is %d (tot %d)", dp->d_name, entry_name_l, entry_l);
    log_trace("READDIR: Getting Stat for %s", total_path);
    stat(total_path, &ent->sb);
    free(total_path);
    ent->name_l = entry_name_l;
    strncpy(ent->name, dp->d_name, entry_name_l);
    ent = (response_readdir_entry_t*) (((char*) ent) + entry_l);
    log_trace("Next Entry at %p", ent);
  }

  if (errno != 0) {
    free(resp_readdir_ptr);
    resp_readdir.ret = -ENOENT;
    resp_readdir.size = 0;
    write(cfd, &resp_readdir, sizeof(response_readdir_t));
    return;
  }

  write(cfd, resp_readdir_ptr, total_resp_size);
  free(resp_readdir_ptr);
  closedir(dirp);

  log_trace("End Handling Read Dir");
}

void handle_request_rmdir(int cfd, char* complete_path) {
  log_trace("Handling Rmdir. %s", complete_path);

  int ret = rmdir(complete_path);
  if (ret != 0) ret = errno;
  write(cfd, &ret, sizeof(int));

  log_trace("End Handling Rmdir.");
}

void handle_request_statvfs(int cfd, char* complete_path) {
  log_trace("Handling StatVFS %s", complete_path);

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

void handle_request_unlink(int cfd, char* complete_path) {
  log_trace("Handling Unlink. %s", complete_path);

  int ret = unlink(complete_path);
  if (ret != 0) ret = errno;
  write(cfd, &ret, sizeof(int));

  log_trace("End Handling Unlink.");
}

void handle_request_utimens(int cfd, char* complete_path) {
  log_trace("Handling Utimens. %s", complete_path);

  struct timespec tv[2];
  read(cfd, &tv, 2*sizeof(struct timespec));

  int access = O_WRONLY | O_TRUNC;
  int fd = open(complete_path, access);

  int ret = 0;
  if (fd == -1) {
    ret = errno;
  } else if (futimens(fd, tv) == -1) {
    ret = errno;
    return;
  }

  write(cfd, &ret, sizeof(int));

  log_trace("End Handling Utimens.");
}

void handle_request_write(int cfd, char* complete_path) {
  log_trace("Handling Write %s", complete_path);

  request_write_t req_write;
  read(cfd, &req_write.size, sizeof(req_write.size));
  char* data = malloc(req_write.size);
  read(cfd, data, req_write.size);

  log_trace("Got my data of length %d", req_write.size);
  int access = O_WRONLY | O_CREAT | O_TRUNC;
  int fd = open(complete_path, access, S_IRWXU);
  log_trace("Opened file");
  int ret = write(fd, data, req_write.size);
  log_trace("Wrote to file");
  free(data);
  close(fd);

  write(cfd, &ret, sizeof(int));

  log_trace("End Handling Write");
}

void handle_requests(int cfd) {
  while (1) {
    request_t* req = read_request(cfd);
    char* complete_path = make_complete_path(req->path, req->path_l);

    switch (req->type) {
      case NFS_FUSE_REQUEST_CREATE:  handle_request_create(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_CHMOD:   handle_request_chmod(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_CHOWN:   handle_request_chown(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_DESTROY: handle_request_destroy(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_GETATTR: handle_request_getattr(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_MKDIR:   handle_request_mkdir(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_READ:    handle_request_read(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_READDIR: handle_request_readdir(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_RMDIR:   handle_request_rmdir(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_STATVFS: handle_request_statvfs(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_UNLINK:  handle_request_unlink(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_UTIMENS: handle_request_utimens(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_WRITE:   handle_request_write(cfd, complete_path);
        break;
      default:
        log_error("Invalid request type or not properly formatted.");
        break;
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
    int cfd = accept_inet_stream_socket(
        sfd, src_host, 127, src_port, 6, LIBSOCKET_NUMERIC,0);
    if (cfd == -1) {
      perror("Couldn't accept connection");
      exit(1);
    }

    log_debug("Connection from %s port %s.", src_host, src_port);
    if (fork() == 0) {
      handle_requests(cfd);
      return 0;
    }
  }

  if (destroy_inet_socket(sfd) < 0) {
    perror(0);
    exit(1);
  }

  return 0;
}
