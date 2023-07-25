#!/bin/bash
#
# Copyright (c) 2020-2022 Intel Corporation
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

EXIT_CODE_SUCCESS=0
EXIT_CODE_ERROR=2
EXIT_CODE_CANCEL=4


print_info () {
    echo "$1" | sed 's/^/    /'
}

# 0 - ok
# 1 - not ok
check_total_memory () {
    echo
    echo -n "Checking for total memory..............................."
    mem=$(free -g | awk '/^Mem:/{print $2}');
    if [ "$mem" -lt "$required_memory" ]; then
        echo "Fail"
        print_info "Total memory is $mem GB. Required $required_memory GB."
        return $EXIT_CODE_ERROR
    fi
    echo "Done"
    print_info "Total memory is $mem GB. Required $required_memory GB."
    return $EXIT_CODE_SUCCESS
}

# 0 - ok
# 1 - not ok
check_free_memory () {
    echo
    echo -n "Checking for available memory..........................."
    free=$(free -g | awk '/^Mem:/{print $7}');
    #check_status ("Error - Something went wrong")
    if [ "$free" -lt "$required_free_memory" ]; then
        echo "Fail"
        print_info "Free memory is $free GB. Required $required_free_memory GB"
        return $EXIT_CODE_ERROR
    fi
    echo "Done"
    print_info "Free memory is $free GB. Required $required_free_memory GB"
    return $EXIT_CODE_SUCCESS
}

# 0 - ok
# 1 - not ok
check_free_diskspace () {
    echo
    echo -n "Checking for free disk space............................"
    free=$(df -k --output=avail "$PWD" | tail -n1)
    if [ "$free" -lt "$required_free_disk" ]; then
        echo "Fail"
        local freeg=$(df -BG --output=avail "$PWD" | tail -n1 | sed -e 's/^[[:space:]]*//')
        local reqg=$(($required_free_disk / 1048576))"G"
        print_info "Free disk space is $freeg. Required $reqg."
        return $EXIT_CODE_ERROR
    fi
    echo "Done"
    local freeg=$(df -BG --output=avail "$PWD" | tail -n1 | sed -e 's/^[[:space:]]*//')
    local reqg=$(($required_free_disk / 1048576))"G"
    print_info "Free disk space is $freeg. Required $reqg."
    return $EXIT_CODE_SUCCESS
}

# 0 - ok
# 1 - not ok
check_os () {
    echo
    echo -n "Checking for OS version................................."
    data=`lsb_release -r`
    readarray -d : -t strarr <<< "$data"
    data=${strarr[1]}
    data=`echo $data | sed 's/ *$//g'`
    if [ "$data" != "$required_os" ]; then
        echo "Fail"
        print_info "Current OS is Ubuntu $data. Required Ubuntu $required_os."
        return $EXIT_CODE_ERROR
    fi
    echo "Done"
    print_info "Current OS is Ubuntu $data. Required Ubuntu $required_os."
    return $EXIT_CODE_SUCCESS
}

# 0 - ok
# 1 - not ok
check_kvm_support () {
    echo
    echo -n "Checking for KVM support................................"
    if [ $(dpkg-query -W -f='${Status}' cpu-checker 2>/dev/null | grep -c "ok installed") -eq 0 ];
    then
        apt-get update >> $log_file 2>&1
        if [ "$?" != 0 ]; then
            echo "Fail";
            print_info "Error while installing packages to perform system checks."
            return $EXIT_CODE_ERROR;
        fi
        apt-get install -y cpu-checker >> $log_file 2>&1
        if [ "$?" != 0 ]; then
            echo "Fail";
            print_info "Error while installing packages to perform system checks."
            return $EXIT_CODE_ERROR;
        fi
    fi
    local ret=`kvm-ok`
    if [[ "$ret" != *"/dev/kvm exists"* ]]; then
        echo "Fail"
        print_info "Virtualization support for KVM is not enabled\nin BIOS or your CPU does not support KVM acceleration."
        return $EXIT_CODE_ERROR
    fi
    echo "Done"
    print_info "Virtualization support enabled."
    return $EXIT_CODE_SUCCESS
}

# 0 - ok
# 1 - not ok
check_tpm_support () {
    echo
    echo -n "Checking for TPM support................................"
    local ret=`dmesg |grep -i TPM`
    if [[ "$ret" == *"ima: No TPM chip found"* ]]; then
        tpm_support_response=""
        echo "Fail"
        print_info "TPM support not available."
        return $EXIT_CODE_ERROR
    fi
    echo "Done"
    print_info "TPM support available."
    return $EXIT_CODE_SUCCESS
}

install_build_tools () {
    #Build tools
    echo -n "Installing Build tools...."
    apt install -y build-essential automake libtool libssl-dev python3 python3-pip net-tools  >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while installing build tools packages."
        return $EXIT_CODE_ERROR
    fi
    echo "Done"
    return $EXIT_CODE_SUCCESS
}

# 0 - ok
# 1 - not ok
install_qemu () {
    #Install the QEMU related packages for Ubuntu 20.04
    echo
    echo -n "Installing Qemu packages...."
    apt install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while installing Qemu packages."
        return $EXIT_CODE_ERROR
    else
        echo "Done"
    fi

    #Check QEMU Version and install from sources if needed.
    ret=`qemu-system-x86_64 --version`
    print_info "QEMU version installed is $ret"

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
        print_info "Qemu is not at required version..."
        echo
        echo -n "Downloading, compiling and installing Qemu 5.1.0 from www.qemu.org...."

        apt-get install -y libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev libnfs-dev libiscsi-dev >> $log_file 2>&1
        if [ "$?" != 0 ]
        then
            echo "Fail"
            print_info "Error while installing Qemu build tools packages."
            return $EXIT_CODE_ERROR
        fi
        wget https://download.qemu.org/qemu-5.1.0.tar.xz >> $log_file 2>&1
        if [ "$?" != 0 ]
        then
            echo "Fail"
            print_info "Error while downloading the Qemu source."
            return $EXIT_CODE_ERROR
        fi
        tar -xJf qemu-5.1.0.tar.xz >> $log_file 2>&1
        if [ "$?" != 0 ]
        then
            echo "Fail"
            print_info "Error while unpacking the Qemu source."
            return $EXIT_CODE_ERROR
        fi
        pushd qemu-5.1.0>> $log_file 2>&1
        ./configure --target-list=x86_64-softmmu >> $log_file 2>&1
        if [ $? != 0 ];then
            echo "Fail"
            print_info "Missing package dependencies for Qemu build."
            return $EXIT_CODE_ERROR
        fi
        make -j8 >> $log_file 2>&1
        if [ $? != 0 ];then
            echo "Fail"
            print_info "Error while building Qemu."
            return $EXIT_CODE_ERROR
        fi
        make install >> $log_file 2>&1
        if [ $? != 0 ];then
            echo "Fail"
            print_info "Error installing Qemu."
            return $EXIT_CODE_ERROR
        fi

        echo "Done"
        print_info "New version of QEMU is installed under /usr/local/bin...."
        print_info "Adjust the path for new QEMU in your scripts...."
        popd >> $log_file 2>&1
    fi
}

# 0 - ok
# 1 - not ok
install_swtpm () {
    #Install SWTPM for vTPM
    echo
    echo -n "Installing Software TPM for vTPM......"
    wget https://github.com/stefanberger/libtpms/archive/v0.9.6.tar.gz >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while downloading the Libtpms source."
        return $EXIT_CODE_ERROR
    fi
    tar -xzf v0.9.6.tar.gz >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while unpacking the Libtpms source."
        return $EXIT_CODE_ERROR
    fi
    pushd libtpms-0.9.6/ >> $log_file 2>&1
    ./autogen.sh --with-tpm2 --with-openssl >> $log_file 2>&1
    if [ $? != 0 ];then
        echo "Fail"
        print_info "Missing package dependencies for Libtpms build."
        print_info "Please refer https://github.com/stefanberger/libtpms/blob/master/INSTALL"
        return $EXIT_CODE_ERROR
    fi
    make >> $log_file 2>&1
    if [ $? != 0 ];then
        echo "Fail"
        print_info "Error while building Libtpms."
        return $EXIT_CODE_ERROR
    fi
    make install >> $log_file 2>&1
    if [ $? != 0 ];then
        echo "Fail"
        print_info "Error installing Libtpms."
        return $EXIT_CODE_ERROR
    fi
    popd >> $log_file 2>&1
    echo "Done"

    #Install known dependencies for swtpm
    echo
    echo -n "Installing Software TPM Emulator......"
    apt-get install -y pkg-config libtasn1-6-dev gnutls-bin libgnutls28-dev expect socat libseccomp-dev selinux-policy-dev python3-setuptools >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while installing SWTPM build tools packages."
        return $EXIT_CODE_ERROR
    fi
    wget https://github.com/stefanberger/swtpm/archive/v0.5.2.tar.gz >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while downloading the SWTPM source."
        return $EXIT_CODE_ERROR
    fi
    tar -xzf v0.5.2.tar.gz >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while unpacking the SWTPM source."
        return $EXIT_CODE_ERROR
    fi
    pushd swtpm-0.5.2/ >> $log_file 2>&1
    ./autogen.sh >> $log_file 2>&1
    if [ $? != 0 ];then
        echo "Fail"
        print_info "Missing package dependencies for SWTPM build."
        print_info "Please refer https://github.com/stefanberger/swtpm/blob/master/INSTALL"
        return $EXIT_CODE_ERROR
    fi
    ./configure --prefix=/usr --with-gnutls >> $log_file 2>&1
    if [ $? != 0 ];then
        echo "Fail"
        print_info "Missing package dependencies for SWTPM build."
        print_info "Please refer https://github.com/stefanberger/swtpm/blob/master/INSTALL"
        return $EXIT_CODE_ERROR
    fi
    make >> $log_file 2>&1
    if [ $? != 0 ];then
        echo "Fail"
        print_info "Error while building SWTPM."
        return $EXIT_CODE_ERROR
    fi
    make install >> $log_file 2>&1
    if [ $? != 0 ];then
        echo "Fail"
        print_info "Error installing SWTPM."
        return $EXIT_CODE_ERROR
    fi

    ldconfig
    if [ $? != 0 ];then
        echo "Failed updating the ldconfig for SWTPM."
        return $EXIT_CODE_ERROR
    fi
    popd  >> $log_file 2>&1
    echo "Done"
    return $EXIT_CODE_SUCCESS
}

# 0 - ok
# 1 - not ok
install_tss () {
    #TSS
    echo
    echo -n "Installing TPM2 Software Stack...."

    apt-get install -y libjson-c-dev libcurl4-openssl-dev doxygen  >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while installing TPM2-TSS build tools packages."
        return $EXIT_CODE_ERROR
    fi
    wget https://github.com/tpm2-software/tpm2-tss/releases/download/3.0.3/tpm2-tss-3.0.3.tar.gz >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while downloading the TPM2-TSS source."
        return $EXIT_CODE_ERROR
    fi
    tar -xvzf tpm2-tss-3.0.3.tar.gz >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while unpacking the TPM2-TSS source."
        return $EXIT_CODE_ERROR
    fi
    pushd tpm2-tss-3.0.3 >> $log_file 2>&1
    ./configure  --with-udevrulesdir=/etc/udev/rules.d/ --prefix=/usr >> $log_file 2>&1
    if [ $? != 0 ];then
        echo "Fail"
        print_info "Missing package dependencies for TPM2-TSS build."
        print_info "Please refer https://github.com/tpm2-software/tpm2-tss/blob/master/INSTALL.md"
        return $EXIT_CODE_ERROR
    fi
    make -j8 >> $log_file 2>&1
    if [ $? != 0 ];then
        echo "Fail"
        print_info "Error while building TPM2-TSS."
        return $EXIT_CODE_ERROR
    fi
    make install >> $log_file 2>&1
    if [ $? != 0 ];then
        echo "Fail"
        print_info "Error installing TPM2-TSS."
        return $EXIT_CODE_ERROR
    fi
    ldconfig >> $log_file 2>&1
    if [ $? != 0 ];then
        echo "Failed updating the ldconfig for TPM2-TSS."
        return $EXIT_CODE_ERROR
    fi
    udevadm control --reload-rules && sudo udevadm trigger >> $log_file 2>&1
    if [ $? != 0 ];then
        echo "Failed configuring TPM2-TSS."
        return $EXIT_CODE_ERROR
    fi
    mkdir -p /var/lib/tpm >> $log_file 2>&1
    groupadd -f tss >> $log_file 2>&1
    useradd -M -d /var/lib/tpm -s /bin/false -g tss tss >> $log_file 2>&1
    pkill -HUP dbus-daemon >> $log_file 2>&1
    popd >> $log_file 2>&1

    echo "Done"
    return $EXIT_CODE_SUCCESS
}

# 0 - ok
# 1 - not ok
install_abrmd () {
    #ABRMD
    echo
    echo -n "Installing TPM2 ABRMD...."

    apt-get install -y libglib2.0-dev >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while installing TPM2 ABRMD build tools packages."
        return $EXIT_CODE_ERROR
    fi
    wget https://github.com/tpm2-software/tpm2-abrmd/releases/download/2.4.0/tpm2-abrmd-2.4.0.tar.gz >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while downloading the TPM2 ABRMD source."
        return $EXIT_CODE_ERROR
    fi
    tar -xvzf tpm2-abrmd-2.4.0.tar.gz >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while unpacking the TPM2 ABRMD source."
        return $EXIT_CODE_ERROR
    fi
    pushd tpm2-abrmd-2.4.0 >> $log_file 2>&1
    ./configure --with-dbuspolicydir=/etc/dbus-1/system.d --prefix=/usr >> $log_file 2>&1
    if [ $? != 0 ];then
        echo "Fail"
        print_info "Missing package dependencies for TPM2 ABRMD build."
        print_info "Please refer https://github.com/tpm2-software/tpm2-abrmd/blob/master/INSTALL.md"
        return $EXIT_CODE_ERROR
    fi
    make -j8 >> $log_file 2>&1
    if [ $? != 0 ];then
        echo "Fail"
        print_info "Error while building TPM2 ABRMD."
        return $EXIT_CODE_ERROR
    fi
    make install >> $log_file 2>&1
    if [ $? != 0 ];then
        echo "Fail"
        print_info "Error installing TPM2 ABRMD."
        return $EXIT_CODE_ERROR
    fi
    ldconfig >> $log_file 2>&1
    if [ $? != 0 ];then
        echo "Failed updating the ldconfig for SWTPM."
        return $EXIT_CODE_ERROR
    fi
    popd >> $log_file 2>&1

    echo "Done"
    return $EXIT_CODE_SUCCESS
}

# 0 - ok
# 1 - not ok
install_tpmtools () {
    #TOOLS
    echo
    echo -n "Installing TPM2 Tools..."

    apt-get install -y pandoc uuid-dev >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while installing TPM2 Tools build tools packages."
        return $EXIT_CODE_ERROR
    fi
    wget https://github.com/tpm2-software/tpm2-tools/releases/download/5.0/tpm2-tools-5.0.tar.gz >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while downloading the TPM2 Tools source."
        return $EXIT_CODE_ERROR
    fi
    tar -xvzf tpm2-tools-5.0.tar.gz >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while unpacking the TPM2 Tools source."
        return $EXIT_CODE_ERROR
    fi
    pushd tpm2-tools-5.0 >> $log_file 2>&1
    ./configure --prefix=/usr >> $log_file 2>&1
    if [ $? != 0 ];then
        echo "Fail"
        print_info "Missing package dependencies for TPM2 Tools build."
        print_info "Please refer https://github.com/tpm2-software/tpm2-tools/blob/master/INSTALL.md"
        return $EXIT_CODE_ERROR
    fi
    make -j8 >> $log_file 2>&1
    if [ $? != 0 ];then
        echo "Fail"
        print_info "Error while building TPM2 Tools."
        return $EXIT_CODE_ERROR
    fi
    make install >> $log_file 2>&1
    if [ $? != 0 ];then
        echo "Fail"
        print_info "Error installing TPM2 Tools."
        return $EXIT_CODE_ERROR
    fi
    sed -i '2 i /usr/lib/' /etc/ld.so.conf.d/x86_64-linux-gnu.conf >> $log_file 2>&1
    ldconfig >> $log_file 2>&1
    if [ $? != 0 ];then
        echo "Failed updating the ldconfig for TPM2 Tools."
        return $EXIT_CODE_ERROR
    fi
    popd >> $log_file 2>&1
    echo "Done"
    return $EXIT_CODE_SUCCESS
}

# 0 - ok
# 1 - not ok
install_docker () {
    echo
    echo -n "Installing Docker Packages...."

    apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while installing dependent packages for Docker installation."
        return $EXIT_CODE_ERROR
    fi

    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while adding Docker's official GPG key."
        return $EXIT_CODE_ERROR
    fi

    add-apt-repository \
      "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
         $(lsb_release -cs) \
            stable" >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while adding Docker repository."
        return $EXIT_CODE_ERROR
    fi

    apt-get update >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while installing Docker packages."
        return $EXIT_CODE_ERROR
    fi
    apt-get remove docker docker-engine docker.io containerd runc >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while removing existing docker packages."
        return $EXIT_CODE_ERROR
    fi
    apt-get install -y docker-ce docker-ce-cli containerd.io >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error while installing Docker packages."
        return $EXIT_CODE_ERROR
    fi

    echo "Done"
    return $EXIT_CODE_SUCCESS
}

install_host_packages () {
    #Build and install the required packages
    rm -rf dep_packages
    mkdir -p dep_packages
    pushd dep_packages > /dev/null
    local result=0

    clear
    echo -ne \
    "Install host dependency packages
    --------------------------------------------------------------------------------
    " | sed -e 's/^[[:space:]]*//'

    install_build_tools
    result=$(($result + $?))

    install_qemu
    result=$(($result + $?))

    install_swtpm
    result=$(($result + $?))

    install_tss
    result=$(($result + $?))

    install_abrmd
    result=$(($result + $?))

    install_tpmtools
    result=$(($result + $?))

    install_docker
    result=$(($result + $?))

    echo
    echo -n "Removing all the downloaded sources..."
    popd   >> $log_file 2>&1
    rm -rf dep_packages   >> $log_file 2>&1
    echo "Done"

    if  [ $result -eq 0 ]; then
        echo -ne \
        "Installed all the host dependency packages successfully.

        --------------------------------------------------------------------------------
        " | sed -e 's/^[[:space:]]*//'
        return $EXIT_CODE_SUCCESS
    else
        echo
        echo -ne \
        "Packages installation failed.
        Check the installation log $log_file for more details.
        You can resolve the issues, and then run the installation again.

        --------------------------------------------------------------------------------
        " | sed -e 's/^[[:space:]]*//'
        read -n 1 -s -r -p "Press any key to continue to quit:   "
        echo ""
        exit $EXIT_CODE_CANCEL
    fi
}

check_system_prerequisites ()
{
    required_memory=7
    required_free_memory=5
    required_free_disk=41943040   #40GBs
    required_os="20.04"
    local result=0

    clear
    echo -ne \
    "System Prerequisite Check
    --------------------------------------------------------------------------------
    " | sed -e 's/^[[:space:]]*//'

    check_total_memory
    result=$(($result + $?))

    check_free_memory
    result=$(($result + $?))

    check_free_diskspace
    result=$(($result + $?))

    check_os
    result=$(($result + $?))

    check_kvm_support
    result=$(($result + $?))

    check_tpm_support
    result=$(($result + $?))

    if  [ $result -eq 0 ]; then
        echo
        echo -ne \
        "Prerequisites check completed.
        --------------------------------------------------------------------------------
        " | sed -e 's/^[[:space:]]*//'
        return $EXIT_CODE_SUCCESS
    else
        echo
        echo -ne \
        "There are one or more unresolved issues based on your system configuration.
        You can resolve the issues, and then run the installation again.
        --------------------------------------------------------------------------------
        " | sed -e 's/^[[:space:]]*//'
        read -n 1 -s -r -p "Press any key to continue to quit:   "
        echo ""
        exit $EXIT_CODE_CANCEL
    fi
}

read_ek_cert_from_tpm () {
    # READ EK Cert
    # Location 1 - TPM2 NV Index 0x1c00002 is the TCG specified location for RSA-EK-certificate.
    RSA_EK_CERT_NV_INDEX=0x01C00002

    echo -n "Reading EK Certificate size from TPM2...."
    tpm2_nvreadpublic $RSA_EK_CERT_NV_INDEX  >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "Error running the TPM2 commands."
        return $EXIT_CODE_ERROR
    fi
    NV_SIZE=`tpm2_nvreadpublic $RSA_EK_CERT_NV_INDEX | grep size |  awk '{print $2}'` >> $log_file 2>&1
    if [ "$?" != 0 ]
    then
        echo "Fail"
        print_info "EK Certificate not provisioned."
        return $EXIT_CODE_ERROR
    fi
    echo "Done"

    if [ $NV_SIZE -eq  0 ]
    then
        echo
        echo -n "Reading EK Certificate from TPM2 - ECC EK Certificate...."
        tpm2_getekcertificate -u tpm_ek.pub -x -X -o tpm_hw_ek_cert.bin >> $log_file 2>&1
        if [ "$?" != 0 ]
        then
            echo "Fail"
            print_info "EK Certificate not provisioned."
            return $EXIT_CODE_ERROR
        fi
        echo "Done"
    else
        echo
        echo -n "Read EK Certificate from TPM2...."
        tpm2_nvread \
          --hierarchy owner \
          --size $NV_SIZE \
          --output tpm_ek_cert.bin \
          $RSA_EK_CERT_NV_INDEX  >> $log_file 2>&1
        if [ "$?" != 0 ]
        then
            echo "Fail"
            print_info "EK Certificate not provisioned."
            return $EXIT_CODE_ERROR
        fi
        echo "Done"
    fi

    return $EXIT_CODE_SUCCESS
}

check_tpm_provisioned () {
    local result=0

    clear
    echo -ne \
    "System Prerequisite Check
    --------------------------------------------------------------------------------
    " | sed -e 's/^[[:space:]]*//'

    read_ek_cert_from_tpm
    if  [ $? -eq 0 ]; then
        echo
        echo -ne \
        "TPM module has been provisioned
        --------------------------------------------------------------------------------
        " | sed -e 's/^[[:space:]]*//'
        return $EXIT_CODE_SUCCESS
    else
        echo
        echo -ne \
        "TPM module not provisioned and cannot be used.

        --------------------------------------------------------------------------------
        " | sed -e 's/^[[:space:]]*//'
        read -n 1 -s -r -p "Press any key to continue to quit:   "
        echo ""
        exit $EXIT_CODE_CANCEL
    fi
}


# script start


log_file=$PWD/log.txt
rm -f $log_file

clear
echo -ne \
"--------------------------------------------------------------------------------
Welcome to Intel® OpenVINO™ Security Add-on setup prerequisite wizard.

The setup prerequisite wizard will check the system requirements required to
install and run the OpenVINO™ Security Add-on tools and runtime components.

Please note that after the prerequisite setup is complete, additional
steps are still required to install the OpenVINO™ Security Add-on components.

For the complete documentation on the OpenVINO™ Security Add-on,
refer to the Installation guide:
https://docs.openvino.ai/latest/ovsa_get_started.html

The setup wizard will complete the following steps:
1. System Prerequisite check
2. Install host dependency packages
3. Verify TPM provision status

Note : Installation logs will be available in $log_file

--------------------------------------------------------------------------------"
echo
# check for sudo or root access
if [ $(id -u) -ne 0 ] ; then
    echo "Root or sudo permissions are required to run this script"
    echo "To continue, please run this script under root account or with sudo."
    echo
    read -s -p "Press ENTER key to exit."
    echo
    exit $EXIT_CODE_CANCEL
fi;

# check for internet
echo -n "Please wait... Checking internet connectivity..."
wget -T 3 -q --spider http://google.com
if [ $? -eq 0 ]; then
    echo "OK"
else
    echo "No Internet. "
    echo "Some packages need to be downloaded from the internet."
    echo "To continue, ensure you are able to connect to the internet."
    echo
    read -s -p "Press ENTER key to exit."
    echo
    exit $EXIT_CODE_CANCEL
fi

#echo "Press any key to continue or \"q\" to quit:  "
#read -r ans

read -rsp $'Press any key to continue or \"q\" to quit:  ' -n1 ans
case $ans in
q)
    exit $EXIT_CODE_CANCEL
    ;;
*)
    #echo "Checking for system prerequisites. This may take a while..."
    check_system_prerequisites
    echo "Next: Install host dependency packages"
    read -n 1 -s -r -p "Press any key to continue:   "

    install_host_packages
    echo "Next: Verify TPM provision status"
    read -n 1 -s -r -p "Press any key to continue:   "

    check_tpm_provisioned
    echo
    echo -ne \
    "Prerequisite checks completed and all the required packages have been installed.

    Next: Proceed with the following:
          1. Download and build OpenVINO™ Model Server
          2. Create VMs
          3. Build OpenVINO™ Security Add-on
          4. Install the OpenVINO™ Security Add-on Tools & Runtime to the VMs

    Refer the docs/ovsa_get_started_kvm.md for details on installation
    " | sed -e 's/^[[:space:]]*//'
    echo ""
    echo ""
    read -n 1 -s -r -p "Press any key to exit:   "

    echo
    ;;
esac

