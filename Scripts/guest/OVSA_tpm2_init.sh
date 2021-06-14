#!/bin/bash
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
