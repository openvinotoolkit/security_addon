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


mkdir -p /var/OVSA/vtpm/vtpm_isv_dev
if [[ ! -f /var/OVSA/vtpm/vtpm_isv_dev/tpm2-00.permall ]]; then
    echo "Provisioning the SWTPM...."
    export XDG_CONFIG_HOME=~/.config
    /usr/share/swtpm/swtpm-create-user-config-files
    swtpm_setup --tpmstate /var/OVSA/vtpm/vtpm_isv_dev --create-ek-cert --create-platform-cert --overwrite --tpm2 --pcr-banks -
fi

swtpm socket --tpm2 --server port=8280 \
                  --ctrl type=tcp,port=8281 \
                  --flags not-need-init --tpmstate dir=/var/OVSA/vtpm/vtpm_isv_dev &

tpm2_startup --clear -T swtpm:port=8280
tpm2_startup -T swtpm:port=8280
python3 /var/OVSA/scripts/OVSA_write_hwquote_swtpm_nvram.py 8280
pkill -f vtpm_isv_dev

swtpm socket --tpmstate dir=/var/OVSA/vtpm/vtpm_isv_dev \
     --tpm2 \
     --ctrl type=unixio,path=/var/OVSA/vtpm/vtpm_isv_dev/swtpm-sock &

qemu-system-x86_64 -m 4096 -enable-kvm \
    -cpu host \
    -drive if=virtio,file=/var/OVSA/vm_images/ovsa_isv_dev_vm_disk.qcow2,cache=none \
    -device e1000,netdev=hostnet0,mac=52:54:00:d1:66:5f \
    -netdev tap,id=hostnet0,script=/var/OVSA/scripts/virbr0-qemu-ifup,downscript=/var/OVSA/scripts/virbr0-qemu-ifdown \
    -chardev socket,id=chrtpm,path=/var/OVSA/vtpm/vtpm_isv_dev/swtpm-sock \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 \
    -vnc :1
