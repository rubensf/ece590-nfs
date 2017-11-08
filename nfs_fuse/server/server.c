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
  log_trace("Handling Request: Create %s", complete_path);

  request_create_t req_create;
  read(cfd, &req_create, sizeof(request_create_t));

  int ret = creat(complete_path, req_create.mode);
  if (ret == -1) {
    ret = errno;
    log_error("error create %s: %s", complete_path, strerror(errno));
  } else {
    ret = 0;
  }

  write(cfd, &ret, sizeof(int));

  log_trace("End Handling Create");
}

void handle_request_chmod(int cfd, char* complete_path) {
  log_trace("Handling Request: Chmod %s", complete_path);

  request_chmod_t req_mode;
  read(cfd, &req_mode, sizeof(request_chmod_t));

  int ret = 0;
  if (chmod(complete_path, req_mode.mode) != 0) {
    ret = errno;
    log_error("Error setting mod of %s: %s", complete_path, strerror(errno));
  }

  write(cfd, &ret, sizeof(int));

  log_trace("End Handling Chmod");
}

void handle_request_chown(int cfd, char* complete_path) {
  log_trace("Handling Request: Chown %s", complete_path);

  request_chown_t req_own;
  read(cfd, &req_own, sizeof(request_chown_t));

  int ret = 0;
  if (chown(complete_path, req_own.uid, req_own.gid) != 0) {
    ret = errno;
    log_error("Error setting own of %s: %s", complete_path, strerror(errno));
  }

  write(cfd, &ret, sizeof(int));

  log_trace("End Handling Chown");
}

void handle_request_destroy(int cfd, char* complete_path) {
  log_trace("Handling Request: Destroy %s");
  close(cfd);
  log_trace("End Handling Destroy");
}

void handle_request_getattr(int cfd, char* complete_path) {
  log_trace("Handling Request: GetAttr %s", complete_path);

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
    log_error("Failed to get stat for %s: %s", complete_path, strerror(errno));
  }

  write(cfd, &resp_getattr, sizeof(response_getattr_t));
  log_trace("End Handling GetAttr");
}

void handle_request_mkdir(int cfd, char* complete_path) {
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

void handle_request_open(int cfd, char* complete_path) {
  log_trace("Handling Request: Open %s", complete_path);

  // Every operation opens the file anyway, so no need to open file here.
  int ret = 0;
  write(cfd, &ret, sizeof(int));

  log_trace("End Handling Open");
}

void handle_request_read(int cfd, char* complete_path) {
  log_trace("Handling Request: Read %s", complete_path);
  request_read_t req_read;
  read(cfd, &req_read, sizeof(request_read_t));

  int open_flags = O_RDONLY;
  int fd = open(complete_path, open_flags);

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
    if (req_read.offset < sb.st_size && req_read.offset + req_read.size > sb.st_size) {
      req_read.size = sb.st_size - req_read.offset;
    } else {
      req_read.size = 0;
    }
    log_debug("Actually reading %lu", req_read.size);

    size_t resp_l = sizeof(response_read_t) + req_read.size;
    response_read_t* resp_read = malloc(resp_l);
    resp_read->ret = 0;
    resp_read->size = req_read.size;

    if (read(fd, resp_read->data, resp_read->size) != 0) {
      resp_read->ret = errno;
      log_error("Read %s failed: %s", complete_path, strerror(errno));
    }

    write(cfd, resp_read, resp_l);
    free(resp_read);
    close(fd);
  }

  log_trace("End Handling Read %s", complete_path);
}

void handle_request_readdir(int cfd, char* complete_path) {
  log_trace("Handling Request: Read Dir %s", complete_path);

  response_readdir_t resp_readdir;
  struct dirent* dp;
  DIR* dirp;

  if ((dirp = opendir(complete_path)) == NULL) {
    resp_readdir.ret = -ENOENT;
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

void handle_request_release(int cfd, char* complete_path) {
  log_trace("Handling Request: Release %s", complete_path);

  // Every operation opens the file anyway, so no need to open file here.
  int ret = 0;
  write(cfd, &ret, sizeof(int));

  log_trace("End Handling Release");
}

void handle_request_rmdir(int cfd, char* complete_path) {
  log_trace("Handling Request: Rmdir %s", complete_path);

  int ret = rmdir(complete_path);
  if (ret != 0) {
    log_error("Unable to Rmdir %s: %s", complete_path, strerror(errno));
    ret = errno;
  }
  write(cfd, &ret, sizeof(int));

  log_trace("End Handling Rmdir");
}

void handle_request_statvfs(int cfd, char* complete_path) {
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

void handle_request_truncate(int cfd, char* complete_path) {
  log_trace("Handling Request: Truncate %s", complete_path);

  request_truncate_t req_trunc;
  read(cfd, &req_trunc, sizeof(request_truncate_t));

  int ret = truncate(complete_path, req_trunc.offset);
  if (ret != 0) {
    log_error("Unable to truncate %s: %s", complete_path, strerror(errno));
    ret = errno;
  }
  write(cfd, &ret, sizeof(int));

  log_trace("End Handling Truncate");
}

void handle_request_unlink(int cfd, char* complete_path) {
  log_trace("Handling Request: Unlink %s", complete_path);

  int ret = unlink(complete_path);
  if (ret != 0) {
    log_error("Unable to unlink %s: %s", complete_path, strerror(errno));
    ret = errno;
  }
  write(cfd, &ret, sizeof(int));

  log_trace("End Handling Unlink");
}

void handle_request_utimens(int cfd, char* complete_path) {
  log_trace("Handling Request: Utimens %s", complete_path);

  struct timespec tv[2];
  read(cfd, &tv, 2*sizeof(struct timespec));

  int access = O_WRONLY | O_TRUNC;
  int fd = open(complete_path, access);

  int ret = 0;
  if (fd == -1) {
    log_error("Unable to set utimens for %s: %s", complete_path, strerror(errno));
    ret = errno;
  } else if (futimens(fd, tv) == -1) {
    ret = errno;
    return;
  }

  write(cfd, &ret, sizeof(int));

  log_trace("End Handling Utimens");
}

void handle_request_write(int cfd, char* complete_path) {
  log_trace("Handling Request: Write %s", complete_path);

  request_write_t req_write;
  read(cfd, &req_write.size, sizeof(req_write.size));
  char* data = malloc(req_write.size);
  read(cfd, data, req_write.size);
  log_debug("Write: Got data of length %d", req_write.size);

  response_write_t resp_write;

  int access = O_WRONLY | O_CREAT | O_TRUNC;
  int fd = open(complete_path, access, S_IRWXU);
  if (fd == -1) {
    log_error("Unable to open file %s with write, create, truncate: %s",
        complete_path, strerror(errno));
    resp_write.ret = errno;
    resp_write.size = 0;
  } else {
    log_trace("Opened file");

    resp_write.ret = write(fd, data, req_write.size);
    if (resp_write.ret == -1) {
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

void handle_requests(int cfd) {
  while (1) {
    request_t* req = read_request(cfd);
    char* complete_path = make_complete_path(req->path, req->path_l);

    switch (req->type) {
      case NFS_FUSE_REQUEST_CREATE:   handle_request_create(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_CHMOD:    handle_request_chmod(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_CHOWN:    handle_request_chown(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_DESTROY:  handle_request_destroy(cfd, complete_path);
                                      return;
        break;
      case NFS_FUSE_REQUEST_GETATTR:  handle_request_getattr(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_MKDIR:    handle_request_mkdir(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_OPEN:     handle_request_open(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_READ:     handle_request_read(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_READDIR:  handle_request_readdir(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_RELEASE:  handle_request_release(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_RMDIR:    handle_request_rmdir(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_STATVFS:  handle_request_statvfs(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_TRUNCATE: handle_request_truncate(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_UNLINK:   handle_request_unlink(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_UTIMENS:  handle_request_utimens(cfd, complete_path);
        break;
      case NFS_FUSE_REQUEST_WRITE:    handle_request_write(cfd, complete_path);
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
