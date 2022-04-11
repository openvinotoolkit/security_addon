# Configure global IP address for the VMs

This is a step-by-step guide to configure a global IP address for the VMs so they can be accessed from across the network.

In this step you prepare two network bridges:
* A global IP address that a KVM can access across the Internet. This is the address that the OpenVINO™ Security Add-on Run-time software on a user's machine uses to verify they have a valid license.
* A host-only local address to provide communication between the Guest VM and the QEMU host operating system.

## Set up Networking on the Host Machine <a name="setup-host"></a>

This example in this step uses the following names. Your configuration might use different names:
* `50-cloud-init.yaml` as an example configuration file name.
* `eno1` as an example network interface name. 
* `br0` as an example bridge name.
* `virbr0` as an example bridge name.

1. Open the network configuration file for editing. This file is in `/etc/netplan` with a name like `50-cloud-init.yaml`

2. Look for these lines in the file:
   ```sh	
   network:
     ethernets:
        eno1:
          dhcp4: true
          dhcp-identifier: mac
     version: 2
   ```

3. Change the existing lines and add the `br0` network bridge. These changes enable external network access:
   ```sh	
   network:
     ethernets:
        eno1:
          dhcp4: false
     bridges:
        br0:
          interfaces: [eno1]
          dhcp4: yes
		  dhcp-identifier: mac
     version: 2
   ```

4. Save and close the network configuration file.

5. Run two commands to activate the updated network configuration file. If you use ssh, you might lose network connectivity when issuing these commands. If so, reconnect to the network.
   ```sh
   sudo netplan generate
   ```
   
   ```sh
   sudo netplan apply
   ```	
   A bridge is created and an IP address is assigned to the new bridge.

6. Verify the new bridge:
   ```sh
   ip a | grep br0
   ```	
   The output looks similar to this and shows valid IP addresses:
   ```sh	
   4: br0:<br><BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000<br>inet 123.123.123.123/<mask> brd 321.321.321.321 scope global dynamic br0
   ```	

7. Create a script named `br0-qemu-ifup` to bring up the `br0` interface. Add the following script contents:
   ```sh
   (echo '#!/bin/sh'
   echo 'nic=$1'
   echo 'if [ -f /etc/default/qemu-kvm ]; then'
   echo '   . /etc/default/qemu-kvm'
   echo 'fi'
   echo 'switch=br0'
   echo 'ifconfig $nic 0.0.0.0 up'
   echo 'brctl addif ${switch} $nic'
   echo ' ') | sudo tee -a /var/OVSA/scripts/br0-qemu-ifup >/dev/null
   
   sudo chmod +x /var/OVSA/scripts/br0-qemu-ifup
   ```

8. Create a script named `br0-qemu-ifdown` to bring down the `br0` interface. Add the following script contents:
   ```sh
   (echo '#!/bin/sh'
   echo 'nic=$1'
   echo 'if [ -f /etc/default/qemu-kvm ]; then'
   echo '   . /etc/default/qemu-kvm'
   echo 'fi'
   echo 'switch=br0'
   echo 'brctl delif $switch $nic'
   echo 'ifconfig $nic 0.0.0.0 down'
   echo ' ') | sudo tee -a /var/OVSA/scripts/br0-qemu-ifdown >/dev/null
   
   sudo chmod +x /var/OVSA/scripts/br0-qemu-ifdown
   ```

9. Create a script named `virbr0-qemu-ifup` to bring up the `virbr0` interface. Add the following script contents:
   ```sh
   (echo '#!/bin/sh'
   echo 'nic=$1'
   echo 'if [ -f /etc/default/qemu-kvm ]; then'
   echo '   . /etc/default/qemu-kvm'
   echo 'fi'
   echo 'switch=virbr0'
   echo 'ifconfig $nic 0.0.0.0 up'
   echo 'brctl addif ${switch} $nic'
   echo ' ') | sudo tee -a /var/OVSA/scripts/virbr0-qemu-ifup >/dev/null

   sudo chmod +x /var/OVSA/scripts/virbr0-qemu-ifup
   ```

10. Create a script named `virbr0-qemu-ifdown` to bring down the `virbr0` interface. Add the following script contents:
    ```sh	
    (echo '#!/bin/sh'
    echo 'nic=$1'
    echo 'if [ -f /etc/default/qemu-kvm ]; then'
    echo '   . /etc/default/qemu-kvm'
    echo 'fi'
    echo 'switch=virbr0'
    echo 'brctl delif $switch $nic'
    echo 'ifconfig $nic 0.0.0.0 down'
    echo '') | sudo tee -a /var/OVSA/scripts/virbr0-qemu-ifdown >/dev/null

    sudo chmod +x /var/OVSA/scripts/virbr0-qemu-ifdown
    ```

See the QEMU documentation for more information about the QEMU network configuration.


## Starting the Guest VM

For each separate role, there would be a corresponding Guest VM. 

In this document, based on the example used, the Model Developer and Independent Software Vendor roles are combined, and would be using the Guest VM named `ovsa_isv_dev` (`/var/OVSA/vm_images/ovsa_isv_dev_vm_disk.qcow2`).

For the User role, use the Guest VM named `ovsa_runtime` (`/var/OVSA/vm_images/ovsa_runtime_vm_disk.qcow2`)

### Starting the Guest VM for the combined roles of Model Developer and Independent Software Vendor

In a new terminal window, start the vTPM, write the HW TPM data into its NVRAM and restart the vTPM for QEMU:

```sh
sudo swtpm socket --tpm2 --server port=8280 \
                  --ctrl type=tcp,port=8281 \
                  --flags not-need-init --tpmstate dir=/var/OVSA/vtpm/vtpm_isv_dev &

sudo tpm2_startup --clear -T swtpm:port=8280
sudo tpm2_startup -T swtpm:port=8280
sudo python3 ~/security_addon/Scripts/host/OVSA_write_hwquote_swtpm_nvram.py 8280
sudo pkill -f vtpm_isv_dev

sudo swtpm socket --tpmstate dir=/var/OVSA/vtpm/vtpm_isv_dev \
  --tpm2 \
  --ctrl type=unixio,path=/var/OVSA/vtpm/vtpm_isv_dev/swtpm-sock \
  --log level=20
```

Start the Guest VM:

```sh
sudo qemu-system-x86_64 \
 -cpu host \
 -enable-kvm \
 -m 4096 \
 -smp 8,sockets=1,cores=8,threads=1 \
 -drive if=virtio,file=/var/OVSA/vm_images/ovsa_isv_dev_vm_disk.qcow2,cache=none \
 -device e1000,netdev=hostnet0,mac=52:54:00:d1:66:5f \
 -netdev tap,id=hostnet0,script=/var/OVSA/scripts/br0-qemu-ifup,downscript=/var/OVSA/scripts/br0-qemu-ifdown \
 -device e1000,netdev=hostnet1,mac=52:54:00:d1:66:6f \
 -netdev tap,id=hostnet1,script=/var/OVSA/scripts/virbr0-qemu-ifup,downscript=/var/OVSA/scripts/virbr0-qemu-ifdown \
 -chardev socket,id=chrtpm,path=/var/OVSA/vtpm/vtpm_isv_dev/swtpm-sock \
 -tpmdev emulator,id=tpm0,chardev=chrtpm \
 -device tpm-tis,tpmdev=tpm0 \
 -vnc :1
```

### Starting the Guest VM for the User role

In a new terminal window, start the vTPM, write the HW TPM data into its NVRAM and restart the vTPM for QEMU:

```sh
sudo swtpm socket --tpm2 --server port=8380 \
                  --ctrl type=tcp,port=8381 \
                  --flags not-need-init --tpmstate dir=/var/OVSA/vtpm/vtpm_runtime &

sudo tpm2_startup --clear -T swtpm:port=8380
sudo tpm2_startup -T swtpm:port=8380
sudo python3 ~/security_addon/Scripts/host/OVSA_write_hwquote_swtpm_nvram.py 8380    
sudo pkill -f vtpm_runtime

sudo swtpm socket --tpmstate dir=/var/OVSA/vtpm/vtpm_runtime \
--tpm2 \
--ctrl type=unixio,path=/var/OVSA/vtpm/vtpm_runtime/swtpm-sock \
--log level=20
```

Start the Guest VM:

```sh
sudo qemu-system-x86_64 \
 -cpu host \
 -enable-kvm \
 -m 4096 \
 -smp 8,sockets=1,cores=8,threads=1 \
 -drive if=virtio,file=/var/OVSA/vm_images/ovsa_runtime_vm_disk.qcow2,cache=none \
 -device e1000,netdev=hostnet0,mac=52:54:00:d1:67:5f \
 -netdev tap,id=hostnet0,script=/var/OVSA/scripts/br0-qemu-ifup,downscript=/var/OVSA/scripts/br0-qemu-ifdown \
 -device e1000,netdev=hostnet1,mac=52:54:00:d1:67:6f \
 -netdev tap,id=hostnet1,script=/var/OVSA/scripts/virbr0-qemu-ifup,downscript=/var/OVSA/scripts/virbr0-qemu-ifdown \
 -chardev socket,id=chrtpm,path=/var/OVSA/vtpm/vtpm_runtime/swtpm-sock \
 -tpmdev emulator,id=tpm0,chardev=chrtpm \
 -device tpm-tis,tpmdev=tpm0 \
 -vnc :2
```

Use the QEMU runtime options in the command to change the memory amount or CPU assigned to this Guest VM.

Use a VNC client to log on to the Guest VM at <host-ip-address>:<x> where <x> corresponds to the vnc number used in the `qemu-system-x86_64` command to start the corresponding Guest VM. 
