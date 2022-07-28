#!/bin/sh
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

if [ -f ".tpm2-getkey.tmp" ]; then
# tmp file exists, meaning we tried the TPM this boot, but it didn’t work for the drive and this must be the second
# or later pass for the drive. Either the TPM is failed/missing, or has the wrong key stored in it.
/lib/cryptsetup/askpass "Automatic disk unlock via TPM failed for  () Enter passphrase: "
exit
fi

# No tmp, so it is the first time trying the script. Create a tmp file and try the TPM
touch .tpm2-getkey.tmp

tpm2_loadexternal --key-algorithm=rsa --hierarchy=o --public=/signing_key_public.pem --key-context=signing_key.ctx --name=signing_key.name -Q
tpm2_verifysignature --key-context=signing_key.ctx --hash-algorithm=sha256 --message=/tpm_pcr.policy --signature=tpm_pcr.signature --ticket=verification.tkt --scheme=rsassa -Q
tpm2_startauthsession --policy-session --session=session.ctx -Q
tpm2_policypcr --pcr-list="sha256:0" --session=session.ctx --policy=tpm_pcr.policy -Q
tpm2_policyauthorize --session=session.ctx --input=tpm_pcr.policy --name=signing_key.name --ticket=verification.tkt -Q
tpm2_unseal --auth=session:session.ctx --object-context=0x81010002
