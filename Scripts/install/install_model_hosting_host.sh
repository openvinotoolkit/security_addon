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
echo "Installing OVSA Runtime Packages"
echo

echo "Copying files to /opt/ovsa/host/example_runtime directory..."
mkdir -vp /opt/ovsa/host/example_runtime 2>&1 | sed 's/^/    /'
cp -vR example_runtime/* /opt/ovsa/host/example_runtime/ 2>&1 | sed 's/^/    /'

echo "Copying files to /opt/ovsa/host/example_client directory..."
mkdir -vp /opt/ovsa/host/example_client 2>&1 | sed 's/^/    /'
cp -vR example_client/* /opt/ovsa/host/example_client/ 2>&1 | sed 's/^/    /'

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
    cd /opt/ovsa/host/example_runtime/ && ./generate_certs.sh -p /var/OVSA/Modelserver 2>&1 | sed 's/^/    /'
    cd -
fi

echo "Creating /opt/ovsa/host/keystore directory..."
mkdir -vp /opt/ovsa/host/keystore 2>&1 | sed 's/^/    /'

echo "Creating /opt/ovsa/host/artefacts directory..."
mkdir -vp /opt/ovsa/host/artefacts 2>&1 | sed 's/^/    /'

echo "Creating $OPTDIR/certs directory..."
mkdir -vp /opt/ovsa/certs 2>&1 | sed 's/^/    /'

echo "Changing ownership to OVSA group/user..."
chown -R ovsa /opt/ovsa 2>&1 | sed 's/^/    /'
chown -R ovsa /var/OVSA 2>&1 | sed 's/^/    /'

echo "Creating $OPTDIR/tmp_dir directory..."
mkdir -vp /opt/ovsa/tmp_dir 2>&1 | sed 's/^/    /'
echo "Remove stale files inside $OPTDIR/tmp_dir directory..."
rm -rf $OPTDIR/tmp_dir/*

echo "Changing ownership to OVSA user with RD/WR & execution permission"
chown ovsa:ovsa /opt/ovsa/tmp_dir 2>&1 | sed 's/^/    /'
chmod 700 /opt/ovsa/tmp_dir 2>&1 | sed 's/^/    /'
chmod 700 /opt/ovsa/host/example_runtime/start_secure_ovsa_host_model_server.sh 2>&1 | sed 's/^/    /'

echo "Loading the docker image..."
if [[ "$(docker images -q openvino/model_server-ovsa_host-nginx-mtls 2> /dev/null)" == "" ]]; then
        echo "Docker does not exist."
else
        echo "Removing existing docker image..."
        docker image rm -f openvino/model_server-ovsa_host-nginx-mtls 2>&1 | sed 's/^/    /'
fi

docker load -i model_server-ovsa_host-nginx-mtls.tar.gz 2>&1 | sed 's/^/    /'

echo
echo "Installing OVSA Runtime Packages completed."
echo
echo "To re-provision OVSA use the below scripts:"
echo "Generate certificate for Model Server - /opt/ovsa/host/example_runtime/generate_certs.sh -p /var/OVSA/Modelserver"
echo
