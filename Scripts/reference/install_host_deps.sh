#!/bin/bash -x
#
# Copyright (c) 2020 Intel Corporation
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

#Check for Ubuntu version 18.04 on host
data=`lsb_release -r`
readarray -d : -t strarr <<< "$data"
data=${strarr[1]}
data=`echo $data | sed 's/ *$//g'`
if [ $data != '18.04' ]; then
    echo "Ubuntu Version is not 18.04. The OVSA needs Ubuntu 18.04...."
    exit 1;
fi

#Check for presence of TPM module 
tpm_ret=`dmesg |grep -i TPM`
if [[ "$tpm_ret" == *"ima: No TPM chip found"* ]]; then
    echo "TPM Module not found.. Can not continue..."
    exit 1
fi

echo "Updating the system...."
sudo apt-get update
sudo apt-get upgrade -y

#Check for KVM acceleration
sudo apt-get install -y cpu-checker
ret=`kvm-ok`
if [[ "$ret" != *"/dev/kvm exists"* ]]; then
    echo "Virtualization support for KVM is not enabled in BIOS or your CPU does not support KVM acceleration. Please check...."
    exit 1
fi

#Build and install the required packages 
mkdir -p dep_packages
pushd dep_packages

#Build tools
echo "Installing Build tools...."
sudo apt install -y build-essential automake libtool libssl-dev python3 python3-pip

#Install the QEMU related packages for Ubuntu 20.04
echo "Installing Qemu packages...."
sudo apt install -y qemu qemu-kvm libvirt-bin  bridge-utils  virt-manager 

#Check QEMU Version and install from sources if needed.
ret=`qemu-system-x86_64 --version`
echo "QEMU Version on System is $ret"

ret=`echo $ret|awk 'NR==1{print $4}'`
readarray -d . -t strarr <<< "$ret"
maj_ver=${strarr[0]}
min_ver=${strarr[1]}

new_qemu_needed=0
if [ $maj_ver -lt 2 ]; then
    new_qemu_needed=1
fi

if [ $maj_ver -eq 2 ]; then
    if [ $min_ver -lt 12 ]; then
       new_qemu_needed=1
    fi
fi
if [ $new_qemu_needed -eq 1 ]; then
    echo "Qemu is not at required version..."
    echo "Downloading latest version 5.1.0 from www.qemu.org and installing after compilation"
    echo "New version of QEMU will be installed under /usr/local/bin...."
    echo "Adjust the path for new QEMU in your scripts...."
    sudo apt-get install -y libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev libnfs-dev libiscsi-dev
    wget https://download.qemu.org/qemu-5.1.0.tar.xz
    tar -xJf qemu-5.1.0.tar.xz
    pushd qemu-5.1.0
    ./configure --target-list=x86_64-softmmu
    if [ $? != 0 ];then
        echo "ERROR: Missing package dependencies for Qemu installation."
        exit 1
    fi
    make -j8
    sudo make install
    popd
else 
    echo "QEMU version requirements are met... Continuing...."
fi

#Install SWTPM for vTPM
echo "Installing software tpm for qemu......"
wget https://github.com/stefanberger/libtpms/archive/v0.7.7.tar.gz
tar -xzf v0.7.7.tar.gz
pushd libtpms-0.7.7/
./autogen.sh --with-tpm2 --with-openssl
if [ $? != 0 ];then
 echo "ERROR: Missing package dependencies for libtpms installation."
 echo "Please refer https://github.com/stefanberger/libtpms/blob/master/INSTALL"
 exit 1
fi

make 
if [ $? != 0 ];then
 echo "ERROR: Failed libtpms build/install. Exiting."
 exit 1
fi
sudo make install
popd

#Install known dependencies for swtpm
sudo apt-get install -y pkg-config libtasn1-6-dev gnutls-bin libgnutls28-dev expect socat libseccomp-dev selinux-policy-dev python3-setuptools
wget https://github.com/stefanberger/swtpm/archive/v0.5.2.tar.gz
tar -xzf v0.5.2.tar.gz
pushd swtpm-0.5.2/
./autogen.sh
./configure --prefix=/usr --with-gnutls
if [ $? != 0 ];then
 echo "ERROR: Missing package dependencies for lswtpm installation."
 echo "Please refer https://github.com/stefanberger/swtpm/blob/master/INSTALL"
 exit 1
fi
make
if [ $? != 0 ];then
 echo "ERROR: Failed swtpm build/install. Exiting."
 exit 1
fi
sudo make install
sudo ldconfig
popd

#TSS
echo "Installing TPM Packages"
sudo apt-get install -y libjson-c-dev libcurl4-openssl-dev doxygen
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
sudo apt-get install -y pandoc uuid-dev
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

echo "Installing Docker Packages...."
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
