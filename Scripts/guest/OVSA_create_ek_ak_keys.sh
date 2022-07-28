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


check_status()
{
if [ "$?" != 0 ]
then
  echo "$1"
  exit 1
fi
}

# Create EK and AK keys
echo "Generating EK & AK Keys"
tpm2_createek --ek-context tpm_ek.ctx --key-algorithm rsa --public tpm_ek.pub
check_status "EK Key generation failed"

tpm2_createak --ek-context tpm_ek.ctx --ak-context tpm_ak.ctx --key-algorithm rsa --hash-algorithm sha256 --signing-algorithm rsassa --public tpm_ak.pub --private tpm_ak.priv --ak-name tpm_ak.name
check_status "AK Key generation failed"

# Read keys to PEM Format
echo "Read EK & AK Keys in PEM Format"
tpm2_readpublic -c tpm_ak.ctx -o tpm_ak.pub.pem -f pem
check_status "Reading AK Key in PEM Format failed"
tpm2_readpublic -c tpm_ek.ctx -o tpm_ek.pub.pem -f pem
check_status "Reading EK Key in PEM Format failed"

# Create AK Name in HEX format
file_size=`stat -c"%s" tpm_ak.name`
loaded_key_name=`cat tpm_ak.name | xxd -p -c $file_size`

echo $loaded_key_name > tpm_ak.name.hex
# READ EK Cert
# Location 1 - TPM2 NV Index 0x1c00002 is the TCG specified location for RSA-EK-certificate.
RSA_EK_CERT_NV_INDEX=0x01C00002

echo "Read EK Certificate size from TPM2"
NV_SIZE=`tpm2_nvreadpublic $RSA_EK_CERT_NV_INDEX | grep size |  awk '{print $2}'`
check_status "Warning: EK Certificate not provisioned"

if [ $NV_SIZE -eq  0 ]
then
   echo "Read EK Certificate from TPM2 - ECC EK Certificate"
   tpm2 getekcertificate -u tpm_ek.pub -x -X -o tpm_hw_ek_cert.bin
   check_status "Warning: EK Certificate not provisioned"
else
   echo "Read EK Certificate from TPM2"
tpm2_nvread \
--hierarchy owner \
--size $NV_SIZE \
--output tpm_ek_cert.bin \
$RSA_EK_CERT_NV_INDEX
check_status "Warning: EK Certificate not provisioned"
fi
echo "Converting EK Certificate from DER to PEM Format"
openssl x509 -inform der -in tpm_ek_cert.bin -out tpm_ek_cert.pem
check_status "Converting EK Certificate to PEM format failed"

echo "Check for PTT ondie CA Cert"
EK_CERT_CHAIN_START_INDEX=0x1C00100
EK_CERT_CHAIN_END_INDEX=0x1C001ff
NV_INDEX=`printf "0x%X\n" $EK_CERT_CHAIN_START_INDEX`
EK_CERT_CHAIN_END_INDEX=`printf "0x%X\n" $EK_CERT_CHAIN_END_INDEX`
nv_start_index=`printf "%d\n" $EK_CERT_CHAIN_START_INDEX`
nv_end_index=`printf "%d\n" $EK_CERT_CHAIN_END_INDEX`
PTT_ondie_CA_cert=false
nv_index_val=$nv_start_index
cat /dev/null > tpm_ek_cert_chain.bin
while [ $nv_index_val -lt $nv_end_index ]
do
	tpm2_nvreadpublic | grep -i $NV_INDEX
	if [ "$?" == 0 ]
	then
		echo "Reading PTT ondie CA Cert from NVIndex"
		NV_SIZE=`tpm2_nvreadpublic $NV_INDEX | grep size |  awk '{print $2}'`
		tpm2_nvread --hierarchy owner --size $NV_SIZE --output tpm_ek_cert_chain_index.bin $NV_INDEX
		cat tpm_ek_cert_chain_index.bin >> tpm_ek_cert_chain.bin
		PTT_ondie_CA_cert=true
	else
		break
	fi
	NV_INDEX=$(( $NV_INDEX + 1 ))
	NV_INDEX=`printf "0x%X\n" $NV_INDEX`
	nv_index_val=`printf "%d\n" $NV_INDEX`
done

FILE=icert_ondie_ca.sh

if [ "$PTT_ondie_CA_cert" = true ] ; then
        echo "Reading intermediate files from chain"
        if [ -f "$FILE" ]; then
                echo "$FILE exists."
                ./icert_ondie_ca.sh tpm_ek_cert_chain.bin
                mv 0.pem ROM_cert.pem
                mv 1.pem Kernel_cert.pem
                mv 2.pem PTT_cert.pem
                echo "Storing the chain in PEM format"
                cat tpm_ek_cert.pem > Ondie_chain.pem
                cat PTT_cert.pem >> Ondie_chain.pem
                cat Kernel_cert.pem >> Ondie_chain.pem
        fi
fi
