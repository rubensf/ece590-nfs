sudo apt-get install -y libfuse-dev libsocket++ git
git clone https://github.com/rubenstoshiro/ece590-nfs.git
cd ece590-nfs/nfs_fuse
bash make_client.sh
bash make_server.sh
