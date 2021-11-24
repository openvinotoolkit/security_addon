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

INSTALL_DIR=/opt/ovsa/certs

usage() {
	echo ""
	echo "$0 gencert"
	echo -e "\t ==> Generate and install self-signed License server certificate to INSTALL_DIR\n"
	echo "$0 install-cert <path to cert> <path to key>"
	echo -e "\t ==> Install specified License server CA certificate and key to INSTALL_DIR\n"
	echo "$0 gencert-new"
	echo -e "\t ==> Generate and install future self-signed License server certificate to INSTALL_DIR\n"
	echo "$0 install-new-cert <path to cert> <path to key>"
	echo -e "\t ==> Install specified future License server CA certificate and key to INSTALL_DIR\n"
	echo "$0 provision-new-cert"
	echo -e "\t ==> Provision future certificate as current certificate in INSTALL_DIR\n"
}


generate_certificate() {
	echo "Generating License Server certificate..."
	echo "======================================================="
	echo "WARNING: For development and testing only."
	echo "Please follow your organization security practices"
	echo "on handling and distribution of cryptography material."
	echo "======================================================="

        local fsuffix=$1
        if [[ $1 == "future" ]]
        then
                fsuffix="_future"
        fi

	mkdir -p "$INSTALL_DIR"
	pushd "$INSTALL_DIR"
	openssl ecparam -name secp521r1 -genkey -out server"$fsuffix".key
	openssl req -new -out server"$fsuffix".csr -key server"$fsuffix".key -subj "/C=IN/CN=localhost"
	openssl x509 -signkey server"$fsuffix".key -in server"$fsuffix".csr -sha384 -req -days 365 -out server"$fsuffix".crt
	echo "Installed certifcate in $INSTALL_DIR"
	popd
}

install_certificate() {
        if [ -z "$1" ] || [ -z "$2" ]
        then
		echo "Invalid usage: missing certificate and key files"
        	usage
		return
        fi
	if [[ ! -f "$1" ]]; then
		echo "Certificate file ${1} does not exist"
	fi
        if [[ ! -f "$2" ]]; then
                echo "Key file ${2} does not exist"
        fi
        if [[ -f "$1" && -f "$2" ]]; then
		local fsuffix=$3
		if [[ $3 = "future" ]]
		then
			fsuffix="_future"
			echo $3
		fi
		mkdir -p "$INSTALL_DIR"
	        cp $1 $INSTALL_DIR/server"$fsuffix".crt
        	cp $2 $INSTALL_DIR/server"$fsuffix".key
	        echo "Installed $1, $2 to $INSTALL_DIR"
        fi
}

provision_certificate() {
        if [[ ! -f "$INSTALL_DIR/server_future.cert" && ! -f "$INSTALL_DIR/server_future.key" ]]; then
                echo "Future certificate files does not exist"
		return
        fi
        echo "Provisioning future certificate as current certificate in $INSTALL_DIR"
        mv $INSTALL_DIR/server_future.crt $INSTALL_DIR/server.crt
        mv $INSTALL_DIR/server_future.key $INSTALL_DIR/server.key
}

# Main
case "$1" in
      "gencert"          )
		generate_certificate
      ;;
      "install-cert"     )
		install_certificate $2 $3
      ;;
      "gencert-new" )
		generate_certificate future
      ;;
      "install-new-cert" )
		install_certificate $2 $3 future
      ;;
      "provision-new-cert" )
		provision_certificate
      ;;
      * ) 
		usage
      ;; # Print usage in case parameter is non-existent
esac

