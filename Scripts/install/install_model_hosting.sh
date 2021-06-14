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

echo "Installing OVSA Model Hosting Packages"

sudo rm -vrf /opt/ovsa
sudo rm -vrf /var/OVSA

sudo mkdir -vp /opt/ovsa/bin
sudo mkdir -vp /opt/ovsa/scripts
sudo mkdir -vp /opt/ovsa/example_runtime
sudo mkdir -vp /opt/ovsa/example_client

sudo cp -vR bin/* /opt/ovsa/bin/
sudo cp -vR scripts/* /opt/ovsa/scripts/
sudo cp -vR example_runtime/* /opt/ovsa/example_runtime/
sudo cp -vR example_client/* /opt/ovsa/example_client/
sudo chown -R ovsa /opt/ovsa

sudo mkdir -vp /var/OVSA/Seal
sudo cp /opt/ovsa/scripts/OVSA_Seal_Key_TPM_Policy_Authorize.sh /var/OVSA/Seal
cd /var/OVSA/Seal && ./OVSA_Seal_Key_TPM_Policy_Authorize.sh
cd -

sudo mkdir -vp /var/OVSA/Quote
sudo cp /opt/ovsa/scripts/OVSA_create_ek_ak_keys.sh /var/OVSA/Quote
cd /var/OVSA/Quote && ./OVSA_create_ek_ak_keys.sh
cd -

cd /opt/ovsa/example_runtime/ && ./generate_certs.sh /var/OVSA/Modelserver
sudo chown -R ovsa /var/OVSA

if [[ "$(docker images -q ovsa/runtime-tpm-nginx:latest 2> /dev/null)" == "" ]]; then
        echo "Docker does not exist."
else
        sudo docker image rm -f ovsa/runtime-tpm-nginx:latest
fi

sudo docker load -i ovsa-runtime-tpm-nginx.tar.gz

echo "Open the .bashrc file in <user_directory>:"
echo "vi <user_directory>/.bashrc"
echo "Add this line to the end of the file:"
echo "source /opt/ovsa/scripts/setupvars.sh"
echo "Save and close the file: press the Esc key and type :wq."
echo "To test your change, open a new terminal. You will see [setupvars.sh] OVSA environment initialized."
