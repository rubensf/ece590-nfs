gcc nfs_fuse.c sshlib.h sshlib.c -I/usr/local/include/fuse3 -L/usr/local/lib/x86_64-linux-gnu -lfuse3 -lpthread -lssh -o build/nfs_fuse
