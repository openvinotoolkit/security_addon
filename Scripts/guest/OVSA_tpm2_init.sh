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

LD_CONF_FILE=/etc/ld.so.conf.d/ovsa.conf
echo "I am $(whoami)"

ALREADY_SET_ID="ovsa"
OVSA_UID=`ls -la /var/ | grep OVSA | awk '{print $3}'`
if [ $OVSA_UID != $ALREADY_SET_ID ]
then
	usermod -u $OVSA_UID ovsa
fi

chown -R ovsa /var/OVSA
dbus-daemon --config-file=/usr/share/dbus-1/system.conf --print-address &
sleep 1
./usr/sbin/tpm2-abrmd  --allow-root --tcti="device:/dev/tpmrm0" &
sleep 1
echo "/ovms/lib:/ovsa-runtime/lib/:/usr/lib/" >> $LD_CONF_FILE
ldconfig

echo "Calling ovms_wrapper $@"
sudo -u ovsa LD_LIBRARY_PATH=/ovms/lib:/ovsa-runtime/lib/:/ovsa-runtime/lib/:/usr/lib/ /ovms_wrapper "$@"
echo "Exit"
