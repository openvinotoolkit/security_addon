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

#set -x

help_menu() {
	echo
	echo "Please follow the below usage:"
	echo "./k8-generate_certs.sh -s <server-machine-fqdn> -c <client-machine-fqdn>"
        echo	
}


while getopts c:s: flag
do
    case "${flag}" in
        c) client_dns=${OPTARG};;
        s) server_dns=${OPTARG};;
    esac
done

if [[ -z $client_dns || -z $server_dns ]]
then
    help_menu
    exit
fi

echo "Server DNS: $server_dns";
echo "Client DNS: $client_dns";

rm -rf /var/OVSA/k8
echo "Creating /var/OVSA/k8 directory..."
mkdir -vp /var/OVSA/k8 2>&1 | sed 's/^/    /'



echo "Generating certificates..."
echo "===================================================================================================================================================="
echo "WARNING: For development and testing only. Please follow your organization security practices on handling and distribution of cryptography material."
echo "===================================================================================================================================================="

#Generate the CA Key and Certificate:
openssl req -x509 -sha256 -newkey rsa:4096 -keyout /var/OVSA/k8/ca.key -out /var/OVSA/k8/ca.crt -days 356 -nodes -subj '/CN=My Cert Authority'

#Generate the Server Key, and Certificate and Sign with the CA Certificate:
openssl req -new -newkey rsa:4096 -keyout /var/OVSA/k8/server.key -out /var/OVSA/k8/server.csr -nodes -subj "/CN=$server_dns" -addext "subjectAltName = DNS:$server_dns"
openssl x509 -req -extfile <(printf "subjectAltName=DNS:$server_dns") -sha256 -days 365 -in /var/OVSA/k8/server.csr -CA /var/OVSA/k8/ca.crt -CAkey /var/OVSA/k8/ca.key -set_serial 01 -out /var/OVSA/k8/server.crt

#Generate the Client Key, and Certificate and Sign with the CA Certificate
openssl req -new -newkey rsa:4096 -keyout /var/OVSA/k8/client.key -out /var/OVSA/k8/client.csr -nodes -subj "/CN=$client_dns"
openssl x509 -req -sha256 -days 365 -in /var/OVSA/k8/client.csr -CA /var/OVSA/k8/ca.crt -CAkey /var/OVSA/k8/ca.key -set_serial 02 -out /var/OVSA/k8/client.crt

chmod 666 /var/OVSA/k8/*

echo "Key material is ready."
