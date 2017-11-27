# Some Prereqs
sudo apt-get install -y libfuse-dev git cmake redis-server libhiredis-dev gcc g++ pkg-config libssl-dev
echo "export LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu/" >> ~/.bashrc

# Configure redis
sudo echo "maxmemory 128mb" >> /etc/redis/redis.conf
sudo echo "maxmemory-policy allkeys-lru" >> /etc/redis/redis.conf

sudo systemctl restart redis-server.service
sudo systemctl enable redis-server.service

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

cd ../..
sudo chown -R $USER ece590-nfs
