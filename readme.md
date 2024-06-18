```bash
#!/bin/bash
sudo apt-get install zstd flex bison gcc build-essential python3-pip
sudo apt-get install python3-setuptools python3-dev libssl-dev

# conda # not python 3.8
conda create -n charm python=3.6  
conda activate charm
conda install -c anaconda pycrypto
conda install -c menpo opencv  
conda install -c conda-forge matplotlib
conda install conda-forge::sympy
conda install anaconda:pandas
pip install pyparsing==2.4.6

# openssl 
# https://www.openssl.org/source/gitrepo.html
conda activate charm
cd ~/alphabet/charm/
wget https://www.openssl.org/source/openssl-1.1.1n.tar.gz
tar -zxvf openssl-1.1.1n.tar.gz
cd ~/alphabet/charm/openssl-1.1.1n/
./config
make 
sudo make install
dpkg -l | grep openssl

# gmp-6.2.1
# https://gmplib.org/manual/Installing-GMP
conda activate charm
cd ~/alphabet/charm/
wget https://gmplib.org/download/gmp/gmp-6.2.1.tar.zst
tar -I zstd -xvf gmp-6.2.1.tar.zst
cd gmp-6.2.1/
./configure
make
make check
sudo make install
dpkg -l | grep gmp


# pbc-0.5.14
# https://crypto.stanford.edu/pbc/manual/ch01.html
conda activate charm
cd ~/alphabet/charm/
wget http://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar -xvf pbc-0.5.14.tar.gz
cd pbc-0.5.14/
./configure
make
sudo make install
sudo ldconfig
dpkg -l | grep pbc


# charm
# https://www.codeleading.com/article/27614243225/
# https://cxybb.com/article/qq_34018719/115007249
conda activate charm
cd ~/alphabet/charm/
git clone https://github.com/JHUISI/charm.git
cd charm/
sudo ./configure.sh
sudo ./configure.sh --python=~/anaconda3/envs/charm/bin/python # important to use conda python instead of /usr/bin/python
# tips raspberry pi 4 need to add following lines with various platform:  vim ./configure.sh  -> add lin 239-241  
# x86_64|amd64)
#   cpu='x86_64'
# ;;
# aarch64|armv7l)
#   cpu='aarch64'
# ;;
make
sudo make install
sudo ldconfig /usr/local/lib64/ 
sudo ldconfig /usr/local/lib/

cd ~/alphabet/charm/
rm -rf openssl-1.1.1n.tar.gz
rm -rf gmp-6.2.1.tar.zst
rm -rf pbc-0.5.14.tar.gz

```
