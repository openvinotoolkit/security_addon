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

#set -e

echo "Installing OVSA Model Hosting Packages"

rm -vrf /opt/ovsa
rm -vrf /var/OVSA

mkdir -vp /opt/ovsa/bin
mkdir -vp /opt/ovsa/scripts
mkdir -vp /opt/ovsa/example_runtime
mkdir -vp /opt/ovsa/example_client

cp -vR bin/* /opt/ovsa/bin/
cp -vR scripts/* /opt/ovsa/scripts/
cp -vR example_runtime/* /opt/ovsa/example_runtime/
cp -vR example_client/* /opt/ovsa/example_client/

mkdir -vp /var/OVSA/Seal
cp /opt/ovsa/scripts/OVSA_Seal_Key_TPM_Policy_Authorize.sh /var/OVSA/Seal
cd /var/OVSA/Seal && ./OVSA_Seal_Key_TPM_Policy_Authorize.sh
cd -

mkdir -vp /var/OVSA/Quote
cp /opt/ovsa/scripts/OVSA_create_ek_ak_keys.sh /var/OVSA/Quote
cd /var/OVSA/Quote && ./OVSA_create_ek_ak_keys.sh
cd -

if [[ "$(docker images -q ovsa/runtime-tpm-nginx:latest 2> /dev/null)" == "" ]]; then
        echo "Docker does not exist."
else
        docker image rm -f ovsa/runtime-tpm-nginx:latest
fi

docker load -i ovsa-runtime-tpm-nginx.tar.gz

echo "Open the .bashrc file in <user_directory>:"
echo "vi <user_directory>/.bashrc"
echo "Add this line to the end of the file:"
echo "source /opt/ovsa/scripts/setupvars.sh"
echo "Save and close the file: press the Esc key and type :wq."
echo "To test your change, open a new terminal. You will see [setupvars.sh] OVSA environment initialized."
