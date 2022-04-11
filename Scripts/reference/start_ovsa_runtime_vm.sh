#!/bin/bash -x
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

mkdir -p /var/OVSA/vtpm/vtpm_runtime
if [[ ! -f /var/OVSA/vtpm/vtpm_runtime/tpm2-00.permall ]]; then
    echo "Provisioning the SWTPM...."
    export XDG_CONFIG_HOME=~/.config
    /usr/share/swtpm/swtpm-create-user-config-files
    swtpm_setup --tpmstate /var/OVSA/vtpm/vtpm_runtime --create-ek-cert --create-platform-cert --overwrite --tpm2 --pcr-banks -
fi

swtpm socket --tpm2 --server port=8380 \
                  --ctrl type=tcp,port=8381 \
                  --flags not-need-init --tpmstate dir=/var/OVSA/vtpm/vtpm_runtime &

tpm2_startup --clear -T swtpm:port=8380
tpm2_startup -T swtpm:port=8380
python3 /var/OVSA/scripts/OVSA_write_hwquote_swtpm_nvram.py 8380
pkill -f vtpm_runtime

swtpm socket --tpmstate dir=/var/OVSA/vtpm/vtpm_runtime \
     --tpm2 \
     --ctrl type=unixio,path=/var/OVSA/vtpm/vtpm_runtime/swtpm-sock &

qemu-system-x86_64 -m 4096 -enable-kvm \
    -cpu host \
    -drive if=virtio,file=/var/OVSA/vm_images/ovsa_runtime_vm_disk.qcow2,cache=none \
    -device e1000,netdev=hostnet1,mac=52:54:00:d1:67:5f \
    -netdev tap,id=hostnet1,script=/var/OVSA/scripts/virbr0-qemu-ifup,downscript=/var/OVSA/scripts/virbr0-qemu-ifdown \
    -chardev socket,id=chrtpm,path=/var/OVSA/vtpm/vtpm_runtime/swtpm-sock \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 \
    -vnc :2
