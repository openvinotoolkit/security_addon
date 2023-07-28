# Installing the Host machine dependency packages for KVM

This is a step-by-step guide on how to install the required dependeny packages on the Host machine to help you build and run the OpenVINO™ Security Add-on

Ensure you are logged in as the `root` user or user with `sudo` permission. Also ensure you have proper internet connectivity with required proxy settings to download the required packages

This document would allow you to check for the required prerequisites and steps to download, build and install the required packages as mentioned below:

1. Check for the TPM support
2. Check for the Virtualization support
3. Install packages
4. Install the Kernel-based Virtual Machine (KVM) and QEMU packages
5. Build and install the Software TPM for vTPM
6. Build and install the Software TPM Emulator
7. Build and install the TPM2 Software Stack
8. Build and install TPM2 ABRMD
9. Build and install TPM2 Tools
10. Install the Docker package


## Prepare the host machine <a name="host-prep"></a>

### Step 1: Check for the TPM support
Test for Trusted Platform Module (TPM) support
   ```sh
   sudo dmesg | grep -i TPM
   ```
   The output indicates TPM availability in the kernel boot logs. Look for presence of the following devices to indicate TPM support is available:
   * `/dev/tpm0`
   * `/dev/tpmrm0`
   
   If you do not see this information, your system does not meet the <a href="#prerequisites">prerequisites</a>  to use the OpenVINO™ Security Add-on.

### Step 2: Check for the Virtualization support
Make sure hardware virtualization support is enabled in the BIOS:
   ```sh
   kvm-ok
   ```
   The output should show: <br>
   `INFO: /dev/kvm exists` <br>
   `KVM acceleration can be used`

   If your output is different, modify your BIOS settings to enable hardware virtualization.
   
   If the `kvm-ok` command is not present, install it:
   ```sh
   sudo -E apt install -y cpu-checker
   ```

### Step 3: Install dependent packages

Install the required basic packages

   ```sh
   sudo -E apt-get update
   sudo -E apt-get upgrade -y
   sudo -E apt install -y build-essential automake libtool libssl-dev python3 python3-pip net-tools
   ```

### Step 4: Install the Kernel-based Virtual Machine (KVM) and QEMU packages

Install the Kernel-based Virtual Machine (KVM) and QEMU packages.
   ```sh
   sudo -E apt install qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils
   ```

Check the QEMU version:
   ```sh
   qemu-system-x86_64 --version
   ```

If the response indicates a QEMU version lower than 2.12.0 download, compile and install the latest QEMU version from [https://www.qemu.org/download](https://www.qemu.org/download).   
   ```sh
   sudo -E apt-get install -y libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev libnfs-dev libiscsi-dev
   wget https://download.qemu.org/qemu-5.1.0.tar.xz
   tar -xJf qemu-5.1.0.tar.xz
   pushd qemu-5.1.0
   ./configure --target-list=x86_64-softmmu
   make -j8
   sudo make install 
   popd
   ```
**Note:** New version of QEMU is installed under `/usr/local/bin`. Set the path to the new QEMU binaries installed.

### Step 5. Build and install the Software TPM for vTPM
Build and install the [`libtpm` package](https://github.com/stefanberger/libtpms/).

   ```sh
   wget https://github.com/stefanberger/libtpms/archive/v0.9.6.tar.gz
   tar -xzf v0.9.6.tar.gz
   pushd libtpms-0.9.6/
   ./autogen.sh --with-tpm2 --with-openssl
   make
   sudo make install
   popd
   ```

### Step 6. Build and install the Software TPM Emulator
Build and install the [`software TPM Emulator` package](https://github.com/stefanberger/swtpm/blob/master/INSTALL/).
   ```sh
   sudo -E apt-get install -y pkg-config libtasn1-6-dev gnutls-bin libgnutls28-dev expect socat libseccomp-dev selinux-policy-dev python3-setuptools 
   wget https://github.com/stefanberger/swtpm/archive/v0.5.2.tar.gz     
   tar -xzf v0.5.2.tar.gz
   pushd swtpm-0.5.2/
   ./autogen.sh
   ./configure --prefix=/usr --with-gnutls
   make
   sudo make install
   sudo ldconfig
   popd
   ```

### Step 7. Build and install the TPM2 Software Stack
Build and install the  [`tpm2-tss` package]( https://github.com/tpm2-software/tpm2-tss/blob/master/INSTALL.md/).
   ```sh
   sudo -E apt-get install -y libjson-c-dev libcurl4-openssl-dev doxygen
   wget https://github.com/tpm2-software/tpm2-tss/releases/download/3.0.3/tpm2-tss-3.0.3.tar.gz
   tar -xvzf tpm2-tss-3.0.3.tar.gz
   pushd tpm2-tss-3.0.3/
   ./configure  --with-udevrulesdir=/etc/udev/rules.d/ --prefix=/usr
   make -j8
   sudo make install
   sudo ldconfig
   sudo udevadm control --reload-rules && sudo udevadm trigger
   sudo mkdir -p /var/lib/tpm
   sudo groupadd -f tss
   sudo useradd -M -d /var/lib/tpm -s /bin/false -g tss tss
   sudo pkill -HUP dbus-daemon
   popd
   ````

### Step 8. Build and install TPM2 ABRMD
Build and install the[`tpm2-abmrd` package](https://github.com/tpm2-software/tpm2-abrmd/blob/master/INSTALL.md/).
   ```sh
   sudo -E apt-get install -y libglib2.0-dev
   wget https://github.com/tpm2-software/tpm2-abrmd/releases/download/2.4.0/tpm2-abrmd-2.4.0.tar.gz
   tar -xvzf tpm2-abrmd-2.4.0.tar.gz
   pushd tpm2-abrmd-2.4.0/
   ./configure --with-dbuspolicydir=/etc/dbus-1/system.d --prefix=/usr
   make -j8
   sudo make install
   sudo ldconfig
   popd
   ```

### Step 9. Build and install TPM2 Tools
Buils and install the [`tpm2-tools` package]( https://github.com/tpm2-software/tpm2-tools/blob/master/INSTALL.md/).
   ```sh
   sudo -E apt-get install -y pandoc uuid-dev
   wget https://github.com/tpm2-software/tpm2-tools/releases/download/5.0/tpm2-tools-5.0.tar.gz
   tar -xvzf tpm2-tools-5.0.tar.gz
   pushd tpm2-tools-5.0/
   ./configure --prefix=/usr
   make -j8
   sudo make install
   sudo sed -i '2 i /usr/lib/' /etc/ld.so.conf.d/x86_64-linux-gnu.conf
   sudo ldconfig
   popd
   ```

### Step 10. Install the Docker package
Install the [Docker package](https://docs.docker.com/engine/install/ubuntu/).  
   ```sh
   sudo -E apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common
   curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
   sudo add-apt-repository \
          "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
          $(lsb_release -cs) \
          stable"
   sudo -E apt-get update
   sudo -E apt-get remove docker docker-engine docker.io containerd runc
   sudo -E apt-get install -y docker-ce docker-ce-cli containerd.io 
   ```


The following are installed and ready to use:
* Kernel-based Virtual Machine (KVM)
* QEMU
* SW-TPM
* HW-TPM support
* Docker

**NOTE:** As an alternative to manually following the above steps, you can also run the script `install_host_deps.sh` in the `Scripts/reference` directory under the OpenVINO™ Security Add-on repository.
