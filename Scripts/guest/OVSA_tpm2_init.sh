#!/bin/bash
LD_CONF_FILE=/etc/ld.so.conf.d/ovsa.conf
echo "I am $(whoami)"

ALREADY_SET_ID="ovsa"
OVSA_UID=`ls -la /var/ | grep OVSA | awk '{print $3}'`
if [ $OVSA_UID != $ALREADY_SET_ID ]
then
	usermod -u $OVSA_UID ovsa
fi

chown root:root -R anaconda-post.log
chown root:root -R bin
chown root:root -R boot
chown root:root -R etc
chown root:root -R home
chown root:root -R lib
chown root:root -R lib64
chown root:root -R media
chown root:root -R mnt
chown root:root -R model_server.conf.template
chown root:root -R opt
chown root:root -R ovms
chown ovsa:ovsa -R ovms_wrapper
chown ovsa:ovsa -R ovsa-runtime
chown root:root -R root
chown root:root -R run
chown root:root -R sbin
chown root:root -R srv
chown root:root -R tmp
chown root:root -R usr
chown root:root -R var

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
