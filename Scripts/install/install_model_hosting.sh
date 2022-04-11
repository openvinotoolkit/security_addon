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
echo "Installing OVSA Model Hosting Packages"
echo

echo "Copying files to /opt/ovsa/kvm/bin directory..."
mkdir -vp /opt/ovsa/kvm/bin 2>&1 | sed 's/^/    /'
cp -vR bin/* /opt/ovsa/kvm/bin/ 2>&1 | sed 's/^/    /'

echo "Copying files to /opt/ovsa/kvm/scripts directory..."
mkdir -vp /opt/ovsa/kvm/scripts 2>&1 | sed 's/^/    /'
cp -vR scripts/* /opt/ovsa/kvm/scripts/ 2>&1 | sed 's/^/    /'

echo "Copying files to /opt/ovsa/kvm/example_runtime directory..."
mkdir -vp /opt/ovsa/kvm/example_runtime 2>&1 | sed 's/^/    /'
cp -vR example_runtime/* /opt/ovsa/kvm/example_runtime/ 2>&1 | sed 's/^/    /'

echo "Copying files to /opt/ovsa/kvm/example_client directory..."
mkdir -vp /opt/ovsa/kvm/example_client 2>&1 | sed 's/^/    /'
cp -vR example_client/* /opt/ovsa/kvm/example_client/ 2>&1 | sed 's/^/    /'

echo "Setting up the Sealing data..."
mkdir -vp /var/OVSA/Seal 2>&1 | sed 's/^/    /'
echo "Changing ownership to OVSA user with RD/WR & execution permission"
chown ovsa:ovsa /var/OVSA/Seal 2>&1 | sed 's/^/    /'
chmod 700 /var/OVSA/Seal 2>&1 | sed 's/^/    /'
cp -vR /opt/ovsa/kvm/scripts/OVSA_Seal_Key_TPM_Policy_Authorize.sh /var/OVSA/Seal 2>&1 | sed 's/^/    /'
if [ -e /var/OVSA/Seal/Seal_data.bin -a \
     -e /var/OVSA/Seal/session.ctx -a \
     -e /var/OVSA/Seal/signing_key.ctx -a \
     -e /var/OVSA/Seal/signing_key.name -a \
     -e /var/OVSA/Seal/signing_key_private.pem -a \
     -e /var/OVSA/Seal/signing_key_public.pem -a \
     -e /var/OVSA/Seal/tpm_authorized.policy -a \
     -e /var/OVSA/Seal/tpm_auth_pcr_seal_key.ctx -a \
     -e /var/OVSA/Seal/tpm_auth_pcr_seal_key.name -a \
     -e /var/OVSA/Seal/tpm_auth_pcr_seal_key.priv -a \
     -e /var/OVSA/Seal/tpm_auth_pcr_seal_key.pub -a \
     -e /var/OVSA/Seal/tpm_pcr.policy -a \
     -e /var/OVSA/Seal/tpm_pcr.signature -a \
     -e /var/OVSA/Seal/tpm_prim.ctx ]
then
    echo "Sealing data already exists..."
else
    cd /var/OVSA/Seal && ./OVSA_Seal_Key_TPM_Policy_Authorize.sh 2>&1 | sed 's/^/    /'
    chmod 0600 /var/OVSA/Seal/*
    chmod 0700 /var/OVSA/Seal/OVSA_Seal_Key_TPM_Policy_Authorize.sh
    cd -
fi

echo "Setting up the Quote data..."
mkdir -vp /var/OVSA/Quote 2>&1 | sed 's/^/    /'
echo "Changing ownership to OVSA user with RD/WR & execution permission"
chown ovsa:ovsa /var/OVSA/Quote 2>&1 | sed 's/^/    /'
chmod 700 /var/OVSA/Quote 2>&1 | sed 's/^/    /'
cp -vR /opt/ovsa/kvm/scripts/OVSA_create_ek_ak_keys.sh /var/OVSA/Quote 2>&1 | sed 's/^/    /'
if [ -e /var/OVSA/Quote/tpm_ak.ctx -a \
     -e /var/OVSA/Quote/tpm_ak.name -a \
     -e /var/OVSA/Quote/tpm_ak.name.hex -a \
     -e /var/OVSA/Quote/tpm_ak.priv -a \
     -e /var/OVSA/Quote/tpm_ak.pub -a \
     -e /var/OVSA/Quote/tpm_ak.pub.pem -a \
     -e /var/OVSA/Quote/tpm_ek_cert.bin -a \
     -e /var/OVSA/Quote/tpm_ek_cert.pem -a \
     -e /var/OVSA/Quote/tpm_ek.ctx -a \
     -e /var/OVSA/Quote/tpm_ek.pub -a \
     -e /var/OVSA/Quote/tpm_ek.pub.pem ]
then
    echo "Quote data already exists..."
else
    cd /var/OVSA/Quote && ./OVSA_create_ek_ak_keys.sh 2>&1 | sed 's/^/    /'
    chmod 0600 /var/OVSA/Quote/*
    chmod 0700 /var/OVSA/Quote/OVSA_create_ek_ak_keys.sh
    cd -
fi

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
    cd /opt/ovsa/kvm/example_runtime/ && ./generate_certs.sh -p /var/OVSA/Modelserver 2>&1 | sed 's/^/    /'
    cd -
fi

echo "Creating /opt/ovsa/kvm/keystore directory..."
mkdir -vp /opt/ovsa/kvm/keystore 2>&1 | sed 's/^/    /'

echo "Creating /opt/ovsa/kvm/artefacts directory..."
mkdir -vp /opt/ovsa/kvm/artefacts 2>&1 | sed 's/^/    /'

echo "Creating /opt/ovsa/certs directory..."
mkdir -vp /opt/ovsa/certs 2>&1 | sed 's/^/    /'

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

echo "Loading the docker image..."
if [[ "$(docker images -q openvino/model_server-ovsa-nginx-mtls 2> /dev/null)" == "" ]]; then
        echo "Docker does not exist."
else
        echo "Removing existing docker image..."
        docker image rm -f openvino/model_server-ovsa-nginx-mtls 2>&1 | sed 's/^/    /'
fi

docker load -i model_server-ovsa-nginx-mtls.tar.gz 2>&1 | sed 's/^/    /'

echo
echo "Installing OVSA Model Hosting Packages completed."
echo
echo "Open the .bashrc file in <user_directory>:"
echo "vi <user_directory>/.bashrc"
echo "Add this line to the end of the file:"
echo "source /opt/ovsa/kvm/scripts/setupvars.sh"
echo "Save and close the file: press the Esc key and type :wq."
echo "To test your change, open a new terminal. You will see [setupvars.sh] OVSA environment initialized."
echo
echo "To re-provision OVSA use the below scripts:"
echo "Quote - /var/OVSA/Quote/OVSA_create_ek_ak_keys.sh"
echo "Seal - /var/OVSA/Seal/OVSA_Seal_Key_TPM_Policy_Authorize.sh"
echo "Generate certificate for Model Server - /opt/ovsa/kvm/example_runtime/generate_certs.sh -p /var/OVSA/Modelserver"
echo
