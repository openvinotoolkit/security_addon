# Installing the Guest VM dependency packages for KVM

This is a step-by-step guide on how to install the required dependeny packages on the Guest VM to help you build and run the OpenVINO™ Security Add-on

Ensure you are logged in as the `root` user or user with `sudo` permission. Also ensure you have proper internet connectivity with required proxy settings to download the required packages

This document would guide you to steps to download, build and install the required packages as mentioned below:

1. Install the Build tools
2. Build and Install TPM Pacakages
3. Build and Install TPM2 ABRMD Pacakages
4. Build and Install TPM2 TOOLS
5. Install the Docker Pacakages

## Prepare the guest machine <a name="guest-prep"></a>

### Step 1: Install Build tools
```sh
sudo -E apt install -y build-essential automake libtool libssl-dev python3 python3-pip net-tools
```

### Step 2: Build and Install TPM Pacakages
```sh
sudo -E apt-get install -y libjson-c-dev libcurl4-openssl-dev doxygen pkg-config uuid-dev
wget https://github.com/tpm2-software/tpm2-tss/releases/download/3.0.3/tpm2-tss-3.0.3.tar.gz
tar -xvzf tpm2-tss-3.0.3.tar.gz
pushd tpm2-tss-3.0.3
./configure  --with-udevrulesdir=/etc/udev/rules.d/ --prefix=/usr
make -j8
sudo make install
sudo ldconfig
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo mkdir -p /var/lib/tpm
sudo groupadd tss && sudo useradd -M -d /var/lib/tpm -s /bin/false -g tss tss
sudo pkill -HUP dbus-daemon
popd
```

### Step 3: Build and Install tpm2-abrmd Pacakages
```sh
sudo -E apt-get install -y libglib2.0-dev
wget https://github.com/tpm2-software/tpm2-abrmd/releases/download/2.4.0/tpm2-abrmd-2.4.0.tar.gz
tar -xvzf tpm2-abrmd-2.4.0.tar.gz
pushd tpm2-abrmd-2.4.0
./configure --with-dbuspolicydir=/etc/dbus-1/system.d --prefix=/usr
make -j8
sudo make install
sudo ldconfig
popd
```

### Step 4: Build and Install tpm2-tools
```sh
sudo -E apt-get install -y pandoc
wget https://github.com/tpm2-software/tpm2-tools/releases/download/5.0/tpm2-tools-5.0.tar.gz
tar -xvzf tpm2-tools-5.0.tar.gz
pushd tpm2-tools-5.0
./configure --prefix=/usr
make -j8
sudo make install
sudo ldconfig
popd
```

### Step 5: Install Docker Pacakages
```sh
sudo -E apt-get remove docker docker-engine docker.io containerd runc
sudo -E apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

sudo add-apt-repository \
                  "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
                     $(lsb_release -cs) \
                        stable"

sudo -E apt-get update
sudo -E apt-get install -y docker-ce docker-ce-cli containerd.io
```
