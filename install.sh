# Some Prereqs
sudo apt-get install -y libfuse-dev git cmake

# Install libsocket
git clone https://github.com/dermesser/libsocket.git
cd libsocket
cmake CMakeLists.txt
make
sudo make install
cd ..
sudo rm -rf libsocket

# Install actual package
git clone https://github.com/rubenstoshiro/ece590-nfs.git
cd ece590-nfs/nfs_fuse
git submodule init
git submodule update
mkdir build
chmod 775 make_client.sh
bash make_client.sh
chmod 775 make_server.sh
bash make_server.sh
