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

echo "Generating Password, Salt using Openssl and SEAL to TPM"
#40 byte random number generated. First 8bytes would be Salt and next 32bytes would be Password
sudo openssl rand -base64 40 > Seal_data.bin
check_status "Password and Salt generation failed"

echo "Create Primary context under hierarchy: Owner"
sudo tpm2_createprimary -Q --hierarchy=o --key-context=tpm_prim.ctx -T device:/dev/tpmrm0
check_status "Primary key creation failed"

# Get the new set of PCR and sign the pcr policy with signer private key
echo "Get the new set of PCR and sign the pcr policy with signer private key"
sudo tpm2_startauthsession --session=session.ctx -T device:/dev/tpmrm0
check_status "Starting session with TPM failed"

sudo tpm2_policypcr -Q --session=session.ctx --pcr-list="sha256:0" --policy=tpm_pcr.policy -T device:/dev/tpmrm0
check_status "Creation of Policy withi PCR failed"

sudo tpm2_flushcontext session.ctx -T device:/dev/tpmrm0
check_status "Flusing context failed"

sudo openssl genrsa -out signing_key_private.pem 2048
check_status "Generation of key for Signing with Openssl failed"
sudo openssl rsa -in signing_key_private.pem -out signing_key_public.pem -pubout
check_status "Generation of key for Signing with Openssl failed"

# We now need the name which is a digest of the TCG public key format of the
# public key to include in the policy, use the loadexternal tool for this
sudo tpm2_loadexternal --key-algorithm=rsa --hierarchy=o --public=signing_key_public.pem --key-context=signing_key.ctx --name=signing_key.name -T device:/dev/tpmrm0
check_status "Loading object to TPM failed"

# Create the signer policy
echo "Create the signer policy"
sudo tpm2_startauthsession --session=session.ctx -T device:/dev/tpmrm0
check_status "Starting session with TPM failed"

sudo tpm2_policyauthorize --session=session.ctx --policy=tpm_authorized.policy --name=signing_key.name --input=tpm_pcr.policy -T device:/dev/tpmrm0
check_status "Policy Authorize failed"

sudo tpm2_flushcontext session.ctx -T device:/dev/tpmrm0
check_status "Flushing context failed"

# Create a new sealing object with the authorized policy which will also
# require the sealing secret.
echo "Create a new sealing object with the authorized policy"
sudo tpm2_create --hash-algorithm=sha256 --public=tpm_auth_pcr_seal_key.pub --private=tpm_auth_pcr_seal_key.priv --sealing-input=Seal_data.bin --parent-context=tpm_prim.ctx --policy=tpm_authorized.policy -T device:/dev/tpmrm0
check_status "Create a new sealing object with the authorized policy Failed"

# Replace the old persistent sealing object with the one we created above
# with policyauthorize policy associated with signer public key
echo "Seal newly created persistent sealing object"
context=`tpm2_getcap handles-persistent -T device:/dev/tpmrm0 | awk 'END{print $2}'`
if [ ! -z "$context" ] && [ $context = "0x81010001" ]
then
  sudo tpm2_evictcontrol --hierarchy=o --object-context=0x81010001 -T device:/dev/tpmrm0 
  check_status "Evicting persistent object failed"
fi

sudo tpm2_load -Q --parent-context=tpm_prim.ctx --public=tpm_auth_pcr_seal_key.pub --private=tpm_auth_pcr_seal_key.priv --name=tpm_auth_pcr_seal_key.name --key-context=tpm_auth_pcr_seal_key.ctx -T device:/dev/tpmrm0
check_status "Loading object into TPM failed"

sudo tpm2_evictcontrol --hierarchy=o --object-context=tpm_auth_pcr_seal_key.ctx 0x81010001 -T device:/dev/tpmrm0 
check_status "Evicting persistent object failed"

echo "Sealing of encryption key on PCR successful"

# sign the pcrpolicy with the signer private key
echo "Sign the pcrpolicy with the signer private key"
sudo openssl dgst -sha256 -sign signing_key_private.pem -out tpm_pcr.signature tpm_pcr.policy
check_status "Signing PCR Policy Failed"

echo "Signing PCR Policy successfully"
exit 0
