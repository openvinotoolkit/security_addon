#!/bin/sh

#* ***************************************************************************
#*                                                                            *
#*  INTEL CONFIDENTIAL                                                        *
#*                                                                            *
#*  Copyright 2020 - 2022 Intel Corporation.                                  *
#*                                                                            *
#*  This software and the related documents are Intel copyrighted materials,  *
#*  and your use of them is governed by the express license under which they  *
#*  were provided to you (License). Unless the License provides otherwise,    *
#*  you may not use, modify, copy, publish, distribute, disclose or transmit  *
#*  this software or the related documents without Intel's prior written      *
#*  permission.                                                               *
#*                                                                            *
#*  This software and the related documents are provided as is, with no       *
#*  express or implied warranties, other than those that are expressly        *
#*  stated in the License.                                                    *
#*                                                                            *
#* ****************************************************************************/


PROG=OVSA_Ramdisk_Unseal_Secret
DESC="ovsa-ramdisk"


ovsa_ramdisk_start() {
    sudo umount /opt/ovsa/mnt
    sleep 2
    sudo mkdir -vp /opt/ovsa/mnt
    echo "OVSA:ovsa-ramdisk starting up..."
    echo "OVSA:Create ovsadisk and mount to mount point"
    echo "Changing ownership to OVSA user"
    echo "OVSA:Run tpm2 commands to Unseal the secret from TPM..."
    sudo mount -t tmpfs -o uid=ovsa,gid=ovsa,rw,mode=700,size=10M tmpfs /opt/ovsa/mnt 2>&1 | sed 's/^/    /' >> /opt/ovsa/mnt/log.txt
    sudo tpm2_loadexternal --key-algorithm=rsa --hierarchy=o --public=/var/OVSA/Seal/signing_key_public.pem --key-context=/opt/ovsa/tmp_dir/signing_key.ctx --name=/opt/ovsa/tmp_dir/signing_key.name 2>&1 | sed 's/^/    /' >> /opt/ovsa/mnt/log.txt

    tpm2_verifysignature --key-context=/opt/ovsa/tmp_dir/signing_key.ctx --hash-algorithm=sha256 --message=/var/OVSA/Seal/tpm_pcr.policy --signature=/var/OVSA/Seal/tpm_pcr.signature --ticket=/opt/ovsa/tmp_dir/verification.tkt --scheme=rsassa 2>&1 | sed 's/^/    /' >> /opt/ovsa/mnt/log.txt

    tpm2_startauthsession --policy-session --session=/opt/ovsa/tmp_dir/session.ctx 2>&1 | sed 's/^/    /' >> /opt/ovsa/mnt/log.txt

    tpm2_policypcr --pcr-list="sha256:0" --session=/opt/ovsa/tmp_dir/session.ctx --policy=/var/OVSA/Seal/tpm_pcr.policy 2>&1 | sed 's/^/    /' >> /opt/ovsa/mnt/log.txt

    tpm2_policyauthorize --session=/opt/ovsa/tmp_dir/session.ctx --input=/var/OVSA/Seal/tpm_pcr.policy --name=/opt/ovsa/tmp_dir/signing_key.name --ticket=/opt/ovsa/tmp_dir/verification.tkt 2>&1 | sed 's/^/    /' >> /opt/ovsa/mnt/log.txt

    tpm2_unseal --auth=session:/opt/ovsa/tmp_dir/session.ctx --object-context=0x81010001 -o /opt/ovsa/mnt/unseal_key.bin 2>&1 | sed 's/^/    /' >> /opt/ovsa/mnt/log.txt

    chown -R ovsa:ovsa /opt/ovsa/mnt 2>&1 | sed 's/^/    /' >> /opt/ovsa/mnt/log.txt
    sudo chmod -R 400 /opt/ovsa/mnt/* 2>&1 | sed 's/^/    /' >> /opt/ovsa/mnt/log.txt
    sleep 2
    cd /opt/ovsa/tmp_dir
    rm -rf signing_key.ctx signing_key.name verification.tkt session.ctx
    cd -
}
ovsa_ramdisk_stop() {

    echo "OVSA:unmount ovsadisk "
    sudo umount /opt/ovsa/mnt
    sleep 2
    sudo rm -rf /opt/ovsa/mnt
}

case "$1" in
   start|restart)
        echo -n "Starting $DESC ..."

        ovsa_ramdisk_start
        echo " done."
        ;;
   stop)
        echo -n "Stopping $DESC ..."
	ovsa_ramdisk_stop
        echo " done."
        ;;
   *)
        echo $"Usage: $0 {start|stop|restart|status}"
        exit 3
        ;;
esac

exit 0

