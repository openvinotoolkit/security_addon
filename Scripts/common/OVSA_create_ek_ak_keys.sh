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
sudo tpm2_createek --ek-context tpm_ek.ctx --key-algorithm rsa --public tpm_ek.pub -T device:/dev/tpmrm0
check_status "EK Key generation failed"
sudo tpm2_createak --ek-context tpm_ek.ctx --ak-context tpm_ak.ctx --key-algorithm rsa --hash-algorithm sha256 --signing-algorithm rsassa --public tpm_ak.pub --private tpm_ak.priv --ak-name tpm_ak.name -T device:/dev/tpmrm0
check_status "AK Key generation failed"

# Read keys to PEM Format
echo "Read EK & AK Keys in PEM Format"
sudo tpm2_readpublic -c tpm_ak.ctx -o tpm_ak.pub.pem -f pem -T device:/dev/tpmrm0
check_status "Reading AK Key in PEM Format failed"
sudo tpm2_readpublic -c tpm_ek.ctx -o tpm_ek.pub.pem -f pem -T device:/dev/tpmrm0
check_status "Reading EK Key in PEM Format failed"

# Create AK Name in HEX format
file_size=`stat --printf="%s" tpm_ak.name`
loaded_key_name=`sudo cat tpm_ak.name | xxd -p -c $file_size`

sudo echo $loaded_key_name > tpm_ak.name.hex

sudo tpm2_getcap properties-fixed -T device:/dev/tpmrm0 | grep IBM
if [ "$?" == 0 ]
then
  echo "SW TPM, skipping reading EK Certificate"
  exit 1
fi

# READ EK Cert
# Location 1 - TPM2 NV Index 0x1c00002 is the TCG specified location for RSA-EK-certificate.
RSA_EK_CERT_NV_INDEX=0x01C00002

echo "Read EK Certificate size from TPM2"
NV_SIZE=`sudo tpm2_nvreadpublic $RSA_EK_CERT_NV_INDEX -T device:/dev/tpmrm0 | grep size |  awk '{print $2}'` 
check_status "Warning: EK Certificate not provisioned"

echo "Read EK Certificate from TPM2"
sudo tpm2_nvread \
--hierarchy owner \
--size $NV_SIZE \
--output tpm_ek_cert.bin \
$RSA_EK_CERT_NV_INDEX -T device:/dev/tpmrm0
check_status "Warning: EK Certificate not provisioned"

echo "Converting EK Certificate from DER to PEM Format"
openssl x509 -inform der -in tpm_ek_cert.bin -out tpm_ek_cert.pem
check_status "Converting EK Certificate to PEM format failed"

