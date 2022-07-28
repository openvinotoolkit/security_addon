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

PREREQ=""
prereqs()
{
echo ""
}
case $1 in
prereqs)
prereqs
exit 0
;;
esac
. /usr/share/initramfs-tools/hook-functions

copy_file script /var/OVSA/FDE/tpm_pcr.policy /tpm_pcr.policy
copy_file script /var/OVSA/FDE/tpm_pcr.signature /tpm_pcr.signature
copy_file script /var/OVSA/FDE/signing_key_public.pem /signing_key_public.pem
copy_file script /var/OVSA/FDE/tpm2-getkey.sh

copy_exec /usr/bin/tpm2_loadexternal
copy_exec /usr/bin/tpm2_verifysignature
copy_exec /usr/bin/tpm2_startauthsession
copy_exec /usr/bin/tpm2_unseal
copy_exec /usr/bin/tpm2_policypcr
copy_exec /usr/bin/tpm2_policyauthorize
copy_exec /usr/lib/x86_64-linux-gnu/libtss2-tcti-device.so.0.0.0
copy_exec /usr/lib/x86_64-linux-gnu/libtss2-tcti-device.so.0
copy_exec /lib/cryptsetup/askpass
exit 0
