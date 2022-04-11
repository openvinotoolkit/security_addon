#! /bin/bash
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

EXIT_STATUS=false

if [[ $1 == "SGX" ]]; then
	EXECUTION_PREFIX="gramine-sgx "
	FOLDER_NAME=gramine
	export OVSA_LICENSE_SERVER_PORT="4451"
else
	FOLDER_NAME=kvm
	export OVSA_LICENSE_SERVER_PORT="4452"
fi

export KEYSTORE_PATH="/opt/ovsa/$FOLDER_NAME/keystore"
export ARTEFACTS_PATH="/opt/ovsa/$FOLDER_NAME/artefacts"
export OVSA_LICENSE_SERVER_CERT_PATH="/opt/ovsa/certs"
if [[ -z $OVSA_LICENSE_SERVER_URL ]]; then
export OVSA_LICENSE_SERVER_URL="localhost"
fi

echo ""
echo "This sample script will generate artefacts for OVSA considering Host and Runtime on same machine"
echo ""
echo "Default values are exported as below:"
echo "		Artefacts Path : $KEYSTORE_PATH"
echo "		Artefacts Path : $ARTEFACTS_PATH"
echo "		License Server : $OVSA_LICENSE_SERVER_URL:$OVSA_LICENSE_SERVER_PORT"
echo "		License Server Cert Path : $OVSA_LICENSE_SERVER_CERT_PATH"
echo ""
echo "To change default URL setting, please exit and export the URL as shown below"
echo "		    export OVSA_LICENSE_SERVER_URL=10.10.10.10"

while read -e -t 1; do : ; done
# Get input from user
read -p "Do you want to continue the setup (y/n)" answer
if [[ $answer != [Yy] ]]; then
	exit 1
fi

#### DEVELOPER PROTECTS MODEL ####
echo "DEVELOPER PROTECTS MODEL........."
echo ""

# Setup artefact directory
echo "Setting up artefact directory..."
set -x
mkdir -p $ARTEFACTS_PATH/pd/1
cd $ARTEFACTS_PATH/pd
export OVSA_DEV_ARTEFACTS=$PWD
set +x
echo ""

set -x
if [[ $1 == "SGX" ]]; then
	cd /opt/ovsa/$FOLDER_NAME
else
	cd /opt/ovsa/$FOLDER_NAME/bin
fi
set +x

# Create keystore and add certificate
echo "Creating Keystore and adding certificate..."
echo ""
set -x
if [ ! -f $KEYSTORE_PATH/isv_keystore ]; then
#Key, CSR & Self-signed certificate generation:for person detection 
$EXECUTION_PREFIX ./ovsatool keygen -storekey -t ECDSA -n Intel -k $KEYSTORE_PATH/isv_keystore -r $ARTEFACTS_PATH/isv_keystore.csr -e "/C=IN/ST=KA/O=Intel, Inc./CN=intel.com/L=Bangalore/mail=xyz@intel.com"
#Store primary_certificate: for person detection 
$EXECUTION_PREFIX ./ovsatool keygen -storecert -c $ARTEFACTS_PATH/primary_isv_keystore.csr.crt -k  $KEYSTORE_PATH/isv_keystore
#Store secondary_certificate:person detection 
$EXECUTION_PREFIX ./ovsatool keygen -storecert -c $ARTEFACTS_PATH/secondary_isv_keystore.csr.crt -k  $KEYSTORE_PATH/isv_keystore
else
echo "Keystore files already exists, REUSING same set of files..."
fi
set +x
echo ""

# Downloading the model
echo "Downloading the model..."
set -x
curl --create-dirs \
     https://download.01.org/opencv/2021/openvinotoolkit/2021.1/open_model_zoo/models_bin/1/person-detection-retail-0013/FP32/person-detection-retail-0013.xml \
     https://download.01.org/opencv/2021/openvinotoolkit/2021.1/open_model_zoo/models_bin/1/person-detection-retail-0013/FP32/person-detection-retail-0013.bin \
     -o $ARTEFACTS_PATH/person-detection-retail-0013.xml -o $ARTEFACTS_PATH/person-detection-retail-0013.bin	 	 
set +x
echo ""

# Define access control for the model and create a master license
echo "Define access control for the model and create a master license..."
set -x
uuid=$(uuidgen)
$EXECUTION_PREFIX ./ovsatool controlAccess -i $ARTEFACTS_PATH/person-detection-retail-0013.xml $ARTEFACTS_PATH/person-detection-retail-0013.bin \
                                -n "person detection" -d "person detection retail" -v 0013 \
                                -p $OVSA_DEV_ARTEFACTS/person_detection_model.dat -m $OVSA_DEV_ARTEFACTS/person_detection_model.masterlic -k $KEYSTORE_PATH/isv_keystore \
                                -g $uuid
set +x
echo ""

# Create a Runtime Reference TCB
echo "Create a Runtime Reference TCB..."
set -x
if [[ $1 == "SGX" ]]; then
$EXECUTION_PREFIX ./ovsaruntime gen-tcb-signature -n "Person Detect Runtime TCB" -v "1.0" \
                                       -f $OVSA_DEV_ARTEFACTS/person_detect_runtime.tcb -k $KEYSTORE_PATH/isv_keystore \
									   -s $ARTEFACTS_PATH/entrypoint.sig
else
	./ovsaruntime gen-tcb-signature -n "Person Detect @ Runtime VM" -v "1.0" \
                                       -f $OVSA_DEV_ARTEFACTS/person_detect_runtime.tcb -k $KEYSTORE_PATH/isv_keystore
fi
set +x
echo ""


#### CUSTOMER SHARES CERTIFICATE TO REQUESTS FOR MODEL####
echo "CUSTOMER SHARES CERTIFICATE TO REQUEST FOR MODEL........."
echo ""

# Create keystore and add certificate
echo "Create keystore and add certificate..."
set -x
if [ ! -f $KEYSTORE_PATH/custkeystore ]; then
# Create Customer KS - for person detection 
$EXECUTION_PREFIX ./ovsatool keygen -storekey -t ECDSA -n Intel -k $KEYSTORE_PATH/custkeystore -r $ARTEFACTS_PATH/custkeystore.csr -e "/C=IN/ST=KA/O=Intel, Inc./CN=intel.com/L=Bangalore/mail=xyz@intel.com"
#store primary_cust_cert: for person detection 
$EXECUTION_PREFIX ./ovsatool keygen -storecert -c $ARTEFACTS_PATH/primary_custkeystore.csr.crt -k $KEYSTORE_PATH/custkeystore
#store secondary_cust_cert: for person detection 
$EXECUTION_PREFIX ./ovsatool keygen -storecert -c $ARTEFACTS_PATH/secondary_custkeystore.csr.crt -k $KEYSTORE_PATH/custkeystore
fi
set +x
echo ""

#### MODEL DEVELOPER RECEIVES USER REQUEST AND GENERATE CUSTOMER LICENSE ####
echo "MODEL DEVELOPER RECEIVES USER REQUEST AND GENERATE CUSTOMER LICENSE........."
echo ""

# Create a license configuration
echo "Create a license configuration..."
set -x
#Time limit license config: for person detection 
$EXECUTION_PREFIX ./ovsatool licgen -t TimeLimit -l30 -n "Time limit license" -v 1.0 -u "$OVSA_LICENSE_SERVER_URL:$OVSA_LICENSE_SERVER_PORT" $OVSA_LICENSE_SERVER_CERT_PATH/server.crt  -k $KEYSTORE_PATH/isv_keystore -o $OVSA_DEV_ARTEFACTS/30daylicense.config
set +x
echo ""

# Create the customer license
echo "Create the customer license..."
set -x
$EXECUTION_PREFIX ./ovsatool sale -m $OVSA_DEV_ARTEFACTS/person_detection_model.masterlic -k $KEYSTORE_PATH/isv_keystore -l $OVSA_DEV_ARTEFACTS/30daylicense.config -t $OVSA_DEV_ARTEFACTS/person_detect_runtime.tcb -p $ARTEFACTS_PATH/primary_custkeystore.csr.crt -c $OVSA_DEV_ARTEFACTS/person_detection_model.lic
set +x
echo ""

#### MODEL USER RECEIVES & LOADS ACCESS CONTROLLED MODEL TO OVMS ####
echo "MODEL USER RECEIVES & LOADS ACCESS CONTROLLED MODEL TO OVMS........."
echo ""

# Prepare artefacts for Model hosting
echo "Prepare artefacts for Model hosting..."
set -x
cp $OVSA_DEV_ARTEFACTS/person_detection_model.lic $OVSA_DEV_ARTEFACTS/1/person_detection_model.lic
cp $OVSA_DEV_ARTEFACTS/person_detection_model.dat $OVSA_DEV_ARTEFACTS/1/person_detection_model.dat

cat << EOF > $OVSA_DEV_ARTEFACTS/sample.json
{
"custom_loader_config_list":[
        {
                "config":{
                                "loader_name":"ovsa",
                                "library_path": "/ovsa-runtime/lib/libovsaruntime.so"
                }
        }
],
"model_config_list":[
        {
        "config":{
                "name":"controlled-access-model",
                "base_path":"$OVSA_DEV_ARTEFACTS",
                "custom_loader_options": {"loader_name":  "ovsa", "keystore":  "$KEYSTORE_PATH/custkeystore", "controlled_access_file": "person_detection_model"}
        }
        }
]
}
EOF
set +x
echo ""

echo "-------------------------------------------------------------------------------------------------"
echo "Runtime artefacts required are generated in below path:"
echo "1) $OVSA_DEV_ARTEFACTS/1/person_detection_model.lic"
echo "2) $OVSA_DEV_ARTEFACTS/1/person_detection_model.dat"
echo ""
echo "Json configuration for loading controlled access model from OVMS is generated in below path:"
echo "$OVSA_DEV_ARTEFACTS/sample.json"
echo ""
echo "Artefacts required to update License Server DB are generated in below path:"
echo "1) $OVSA_DEV_ARTEFACTS/person_detection_model.lic"
echo "2) $ARTEFACTS_PATH/secondary_custkeystore.csr.crt"
echo "-------------------------------------------------------------------------------------------------"

