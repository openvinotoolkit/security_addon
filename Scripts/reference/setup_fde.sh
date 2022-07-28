#!/bin/bash -x
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
set -x

EXIT_CODE_SUCCESS=0
EXIT_CODE_ERROR=2
EXIT_CODE_CANCEL=4

DIR=$(dirname $(readlink -f "$0"))
echo $DIR

# Check for sudo or root access
if [ $(id -u) -ne 0 ] ; then
    echo "Root or sudo permissions are required to run this script"
    echo "To continue, please run this script under root account or with sudo."
    echo
    read -s -p "Press ENTER key to exit."
    echo
    exit $EXIT_CODE_CANCEL
fi;

# Install TPM dependencies
/bin/bash "$DIR"/install_tpm_deps.sh
if [ "$?" != 0 ]
then
    echo "Error installing TPM dependencies."
    echo
    read -s -p "Press ENTER key to exit."
    echo
    exit $EXIT_CODE_ERROR
fi

# Setup /var/OVSA/FDE folder
mkdir -p /var/OVSA/FDE
cp -v "$DIR"/../host/FDE_Seal_Key_TPM_Policy_Authorize.sh /var/OVSA/FDE

# Provision TPM with FDE seal key
cd /var/OVSA/FDE && /bin/bash /var/OVSA/FDE/FDE_Seal_Key_TPM_Policy_Authorize.sh
if [ "$?" != 0 ]
then
    echo "Error provisioning TPM with the FDE seal key."
    echo
    read -s -p "Press ENTER key to exit."
    echo
    exit $EXIT_CODE_ERROR
fi

# Copy GetKey & DecryptKey scripts
cp -v "$DIR"/../host/FDE_tpm2_getkey.sh /var/OVSA/FDE
cp -v "$DIR"/../host/FDE_tpm2_decryptkey.sh /etc/initramfs-tools/hooks/

# Add Seal Key to the LUKS partition
cryptsetup luksAddKey /dev/sda3 /var/OVSA/FDE/Seal_data.bin

# Update /etc/crypttab
sed -i 's/$/,discard,keyscript=\/var\/OVSA\/FDE\/FDE_tpm2_getkey.sh/' /etc/crypttab

update-initramfs -u -k all
