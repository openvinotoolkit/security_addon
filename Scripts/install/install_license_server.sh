#!/bin/bash
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

#set -e

echo "Installing OVSA License Server"

mkdir -vp /opt/ovsa/bin
mkdir -vp /opt/ovsa/scripts
mkdir -vp /opt/ovsa/DB
mkdir -vp /opt/ovsa/lib

cp -vR bin/* /opt/ovsa/bin/
cp -vR scripts/* /opt/ovsa/scripts/
cp -vR DB/* /opt/ovsa/DB/
cp -vR lib/* /opt/ovsa/lib/

python3 /opt/ovsa/DB/ovsa_create_db.py /opt/ovsa/DB/ovsa.db

pushd /opt/ovsa/scripts/
./OVSA_install_license_server_cert.sh gencert
popd

echo "Open the .bashrc file in <user_directory>:"
echo "vi <user_directory>/.bashrc"
echo "Add this line to the end of the file:"
echo "source /opt/ovsa/scripts/setupvars.sh"
echo "Save and close the file: press the Esc key and type :wq."
echo "To test your change, open a new terminal. You will see [setupvars.sh] OVSA environment initialized."
