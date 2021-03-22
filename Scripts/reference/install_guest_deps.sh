#!/bin/bash -x
#
# Copyright (c) 2020-2021 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

mkdir -p dep_packages
pushd dep_packages

echo "Updating the system...."
sudo apt-get update
sudo apt-get upgrade -y

#Build tools
echo "Installing Build tools...."
sudo apt install -y build-essential automake libtool libssl-dev python3 python3-pip

#TSS
echo "Installing TPM Pacakages"
sudo apt-get install -y libjson-c-dev libcurl4-openssl-dev doxygen pkg-config uuid-dev
wget https://github.com/tpm2-software/tpm2-tss/releases/download/3.0.3/tpm2-tss-3.0.3.tar.gz
tar -xvzf tpm2-tss-3.0.3.tar.gz
pushd tpm2-tss-3.0.3
./configure  --with-udevrulesdir=/etc/udev/rules.d/ --prefix=/usr
if [ $? != 0 ];then
 echo "ERROR: Missing package dependencies for tss installation."
 echo "Please refer https://github.com/tpm2-software/tpm2-tss/blob/master/INSTALL.md"
 exit 1
fi
make -j8
if [ $? != 0 ];then
 echo "ERROR: Failed TSS build/install. Exiting."
 exit 1
fi
sudo make install
sudo ldconfig
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo mkdir -p /var/lib/tpm
sudo groupadd tss && sudo useradd -M -d /var/lib/tpm -s /bin/false -g tss tss
sudo pkill -HUP dbus-daemon
popd

#ABRMD
sudo apt-get install -y libglib2.0-dev
wget https://github.com/tpm2-software/tpm2-abrmd/releases/download/2.4.0/tpm2-abrmd-2.4.0.tar.gz
tar -xvzf tpm2-abrmd-2.4.0.tar.gz
pushd tpm2-abrmd-2.4.0
./configure --with-dbuspolicydir=/etc/dbus-1/system.d --prefix=/usr
if [ $? != 0 ];then
 echo "ERROR: Missing package dependencies for tpm2-abrmd installation."
 echo "Please refer https://github.com/tpm2-software/tpm2-abrmd/blob/master/INSTALL.md"
 exit 1
fi
make -j8
if [ $? != 0 ];then
 echo "ERROR: Failed ABRMD build. Exiting."
 exit 1
fi
sudo make install
sudo ldconfig
popd

#TOOLS
sudo apt-get install -y pandoc
wget https://github.com/tpm2-software/tpm2-tools/releases/download/5.0/tpm2-tools-5.0.tar.gz
tar -xvzf tpm2-tools-5.0.tar.gz
pushd tpm2-tools-5.0
./configure --prefix=/usr
if [ $? != 0 ];then
 echo "ERROR: Missing package dependencies for tpm2-tools installation."
 echo "Please refer https://github.com/tpm2-software/tpm2-tools/blob/master/INSTALL.md"
 exit 1
fi
make -j8
if [ $? != 0 ];then
 echo "ERROR: Failed tpm2-tools build/install. Exiting."
 exit 1
fi
sudo make install
sudo ldconfig
popd

echo "Installing Docker Pacakges...."
sudo apt-get remove docker docker-engine docker.io containerd runc
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

sudo add-apt-repository \
	   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
	      $(lsb_release -cs) \
	         stable"

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io

echo "Removing all the downloaded sources..."
popd
/bin/rm -rf dep_packages
