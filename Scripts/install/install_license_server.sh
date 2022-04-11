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

#set -e

echo
echo "Installing OVSA License Server"
echo

echo "Copying files to /opt/ovsa/bin directory..."
mkdir -vp /opt/ovsa/bin 2>&1 | sed 's/^/    /'
cp -vR bin/* /opt/ovsa/bin/ 2>&1 | sed 's/^/    /'

echo "Copying files to /opt/ovsa/scripts directory..."
mkdir -vp /opt/ovsa/scripts 2>&1 | sed 's/^/    /'
cp -vR scripts/* /opt/ovsa/scripts/ 2>&1 | sed 's/^/    /'

echo "Copying files to /opt/ovsa/lib directory..."
mkdir -vp /opt/ovsa/lib 2>&1 | sed 's/^/    /'
cp -vR lib/* /opt/ovsa/lib/ 2>&1 | sed 's/^/    /'

echo "Copying files to /opt/ovsa/DB directory..."
mkdir -vp /opt/ovsa/DB 2>&1 | sed 's/^/    /'
cp -vR DB/* /opt/ovsa/DB/ 2>&1 | sed 's/^/    /'
if [ -e /opt/ovsa/DB/ovsa.db ]
then
    echo "OVSA DB already exists..."
else
    echo "Creating OVSA DB..."
    python3 /opt/ovsa/DB/ovsa_create_db.py /opt/ovsa/DB/ovsa.db 2>&1 | sed 's/^/    /'
fi

echo "Provisioning the License Server..."
if [ -e /opt/ovsa/certs/server.crt -a \
     -e /opt/ovsa/certs/server.csr -a \
     -e /opt/ovsa/certs/server.key ]
then
    echo "License Server already provisioned..."
else
    cd /opt/ovsa/scripts/ && ./OVSA_install_license_server_cert.sh gencert 2>&1 | sed 's/^/    /'
    cd -
fi

echo "Changing ownership to OVSA group/user..."
chown -R ovsa /opt/ovsa 2>&1 | sed 's/^/    /'
chown -R ovsa /var/OVSA 2>&1 | sed 's/^/    /'

echo "Creating /opt/ovsa/tmp_dir directory..."
mkdir -vp /opt/ovsa/tmp_dir 2>&1 | sed 's/^/    /'
echo "Remove stale files inside /opt/ovsa/tmp_dir directory..."
rm -rf /opt/ovsa/tmp_dir/*

echo "Changing ownership to OVSA user with RD/WR & execution permission"
chown ovsa:ovsa /opt/ovsa/tmp_dir 2>&1 | sed 's/^/    /'
chmod 700 /opt/ovsa/tmp_dir 2>&1 | sed 's/^/    /'

echo
echo "Installing OVSA License Server completed."
echo
echo "Open the .bashrc file in <user_directory>:"
echo "vi <user_directory>/.bashrc"
echo "Add this line to the end of the file:"
echo "source /opt/ovsa/scripts/setupvars.sh"
echo "Save and close the file: press the Esc key and type :wq."
echo "To test your change, open a new terminal. You will see [setupvars.sh] OVSA environment initialized."
echo
echo "To re-provision OVSA License Server use the below scripts:"
echo "DB - python3 /opt/ovsa/DB/ovsa_create_db.py /opt/ovsa/DB/ovsa.db"
echo "Generate certificate for License Server - /opt/ovsa/scripts/OVSA_install_license_server_cert.sh gencert"
echo
