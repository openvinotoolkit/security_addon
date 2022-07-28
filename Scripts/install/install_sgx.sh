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
echo "Installing OVSA for SGX Packages"
echo

echo "Copying files to /opt/ovsa/bin directory..."
mkdir -vp /opt/ovsa/gramine/bin 2>&1 | sed 's/^/    /'
cp -vR bin/* /opt/ovsa/gramine/bin/ 2>&1 | sed 's/^/    /'

echo "Copying files to /opt/ovsa/lib directory..."
mkdir -vp /opt/ovsa/gramine/lib 2>&1 | sed 's/^/    /'
cp -vR lib/* /opt/ovsa/gramine/lib/ 2>&1 | sed 's/^/    /'

echo "Copying files to /opt/ovsa/scripts directory..."
mkdir -vp /opt/ovsa/gramine/scripts 2>&1 | sed 's/^/    /'
cp -vR scripts/* /opt/ovsa/gramine/scripts/ 2>&1 | sed 's/^/    /'

echo "Copying files to /opt/ovsa/example_runtime directory..."
mkdir -vp /opt/ovsa/gramine/example_runtime 2>&1 | sed 's/^/    /'
cp -vR example_runtime/* /opt/ovsa/gramine/example_runtime/ 2>&1 | sed 's/^/    /'

echo "Copying files to /opt/ovsa/example_client directory..."
mkdir -vp /opt/ovsa/gramine/example_client 2>&1 | sed 's/^/    /'
cp -vR example_client/* /opt/ovsa/gramine/example_client/ 2>&1 | sed 's/^/    /'

echo "Generating certificates for OpenVINO Model Server..."
if [ -e /var/OVSA/Modelserver/client_cert_ca.crl -a \
     -e /var/OVSA/Modelserver/client_cert_ca.key -a \
     -e /var/OVSA/Modelserver/client_cert_ca.pem -a \
     -e /var/OVSA/Modelserver/client_cert_ca.srl -a \
     -e /var/OVSA/Modelserver/client.csr -a \
     -e /var/OVSA/Modelserver/client.key -a \
     -e /var/OVSA/Modelserver/client.pem -a \
     -e /var/OVSA/Modelserver/dhparam.pem -a \
     -e /var/OVSA/Modelserver/openssl_ca.conf -a \
     -e /var/OVSA/Modelserver/server.key -a \
     -e /var/OVSA/Modelserver/server.pem ]
then
    echo "Certificates are present - no need to generate...."
else
    cd /opt/ovsa/gramine/example_runtime/ && ./generate_certs.sh -p /var/OVSA/Modelserver 2>&1 | sed 's/^/    /'
    cd -
fi

echo "Creating /opt/ovsa/gramine/keystore directory..."
mkdir -vp /opt/ovsa/gramine/keystore 2>&1 | sed 's/^/    /'

echo "Creating /opt/ovsa/gramine/artefacts directory..."
mkdir -vp /opt/ovsa/gramine/artefacts 2>&1 | sed 's/^/    /'

echo "Creating /opt/ovsa/certs directory..."
mkdir -vp /opt/ovsa/certs 2>&1 | sed 's/^/    /'

echo "Copying manifest files..."
cp -v ovsatool.* /opt/ovsa/gramine 2>&1 | sed 's/^/    /'
cp -v ovsaruntime.* /opt/ovsa/gramine 2>&1 | sed 's/^/    /'

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
chmod 700 /opt/ovsa/gramine/example_runtime/start_secure_ovsa_sgx_model_server.sh 2>&1 | sed 's/^/    /'

echo "Loading the docker image..."
if [[ "$(docker images -q gsc-openvino/model_server-ovsa_sgx-nginx-mtls 2> /dev/null)" == "" ]]; then
        echo "Docker does not exist."
else
        echo "Removing existing docker image..."
        docker image rm -f gsc-openvino/model_server-ovsa_sgx-nginx-mtls 2>&1 | sed 's/^/    /'
fi
docker load -i model_server-ovsa_sgx-nginx-mtls.tar.gz 2>&1 | sed 's/^/    /'
docker run -it \
        -v /opt/ovsa/gramine/artefacts:/opt/ovsa/gramine/artefacts/ \
        --entrypoint bash \
        gsc-openvino/model_server-ovsa_sgx-nginx-mtls \
        -c "cp /entrypoint.sig /opt/ovsa/gramine/artefacts"

echo "Generating tokens for Ovsa Tool & Runtime..."
if which gramine-sgx-get-token >/dev/null; then
gramine-sgx-get-token \
        --output /opt/ovsa/gramine/ovsatool.token --sig ovsatool.sig 2>&1 | sed 's/^/    /'
gramine-sgx-get-token \
	--output /opt/ovsa/gramine/ovsaruntime.token --sig ovsaruntime.sig  2>&1 | sed 's/^/    /'
else
    	echo "Error: Cannot generate token."
	echo "Required Gramine pre-requisites are not installed or"
	echo "may not be installed correctly."
	echo "Refer to the OVSA document for installing Gramine."
fi

echo
echo "Installing OVSA for SGX Packages completed."
echo
echo "Open the .bashrc file in <user_directory>:"
echo "vi <user_directory>/.bashrc"
echo "Add this line to the end of the file:"
echo "source /opt/ovsa/gramine/scripts/setupvars.sh"
echo "Save and close the file: press the Esc key and type :wq."
echo "To test your change, open a new terminal. You will see [setupvars.sh] OVSA environment initialized."
echo
echo "To re-provision OVSA use the below scripts:"
echo "Generate certificate for Model Server - /opt/ovsa/gramine/example_runtime/generate_certs.sh -p /var/OVSA/Modelserver"
echo
