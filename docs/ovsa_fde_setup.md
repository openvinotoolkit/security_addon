# Full Disk Encryption on Ubuntu 20.04 using LUKS with TPM
**LUKS**, short for Linux Unified Key Setup, is a standard hard drive encryption technology for major Linux systems including Ubuntu. It is used for encrypting entire block devices and is therefore ideal for encrypting hard disk drives, SSDs, and even removable storage drives.

This guide provides a step-by-step instruction to install Ubuntu 20.04 Server and create a LUKS encrypted volume that uses TPM to store the key for decryption. This guide is only to encrypt the non-bootable volume. The Secure Boot option would ensure the bootable volume is secure.

## Prerequisites <a name="prerequisites"></a>
**Hardware**
* Intel® Core™ or Xeon® processor<br>
* TPM version 2.0-conformant Discrete Trusted Platform Module (dTPM) or Firmware Trusted Platform Module (fTPM)
* Secure Boot is enabled in BIOS
* Virtualization support is enabled in BIOS<br>

**Bootable Device**
* [Ubuntu 20.04.3 LTS Server ISO](http://releases.ubuntu.com/focal/ubuntu-20.04.4-live-server-amd64.iso) copied to the installation media (generally a USB device).
  Refer https://ubuntu.com/tutorials/create-a-usb-stick-on-ubuntu#1-overview to create a bootable USB media.<br>

## How to setup Full Disk Encryption <a name="setup-fde"></a>
This section describes the step-by-step procedures to setup the FDE.

### Step 1: Boot from USB
To trigger the installation process, insert the USB media and restart your machine. Most machines will automatically boot from the USB media, though in some cases this feature would be disabled to improve the boot performance.

In case the boot message or the "Welcome" screen does not appear, enable the boot option from the USB media in the BIOS settings. If you are still having problems, check out the Ubuntu Community documentation on [booting from CD/DVD](https://help.ubuntu.com/community/BootFromCD?_ga=2.64254248.627105571.1655877712-1798859978.1650294439).

Once in the installation process, select your preferences in each installation screen. Continue until the **Guided storage configuration** screen.

### Step 2: Configure Storage
In the **Guided storage configuration** screen, select the drive where the Ubuntu Server needs to be installed. Select/Check **Set up this disk as an LVM group** option. 

To encrypt the LVM based partition, Select/Check the **Encrypt the LVM groups with LUKS** option. Enter the passphrase and complete the storage configuration.

### Step 3: Continue installation and Reboot
Continue with the installation process till the end and reboot the machine. During the bootup, enter the passphrase (entered earlier in the **Guided storage configuration** screen) when promted to continue booting.

### Step 4: Check for the Swap space
By default, it is common for the Ubuntu installation to create a swap partition. Check if there is an existing swap space created.
```
sudo swapon --show
```
If no swap space is configured, there would be no output. To create a swap space, follow the steps mentioned in <a href="#create_swapspace">**Create Swap space using a swapfile**</a>.

If the swap already space exists, the sample output of the above command would be as shown below. In this case, skip the steps to **Create Swap space using a swapfile**.
```
NAME      TYPE SIZE USED PRIO
/swap.img file   4G   0B   -2
```

### Step 5: Create Swap space using a swapfile <a name="create_swapspace"></a>
To add swap space, run the following command
```
sudo dd if=/dev/zero of=/swap.img bs=1MB count=$((1*2014))
```
The above command would create a swap space of **2GB**.

Make sure that your swapfile was created by issuing the following command.
```
ls -l /swap.img
```

Once the swapfile is created, ensure it is secured. The swapfiles are meant to be used for memory optimization purposes and should not be edited or modified in any way.

Change the permission of the swapfile only for the ```root``` user.
```
sudo chmod 600 /swap.img
```

The swapfile now needs to be enabled. To enable the swapfile run the ```mkswap``` and ```swapon``` commands.
```
sudo mkswap /swap.img
sudo swapon /swap.img
```

Finally the swap space need to be made permanent. To make the swap space permanent, edit the ```/etc/fstab``` file and add the below changes.
```
sudo nano /etc/fstab
```
```
/swap.img none swap defaults 0 0
```
Save the file and restart to make sure that the swap space is still mounted.
```
sudo reboot
```
```
sudo swapon --show
```

### Step 6: Seal Key to TPM and use Key to decrypt the LUKS partition
To complete the FDE setup, the following steps are required:

* Download and install the TPM dependency packages - To enable the TPM device on the machine
* Create a Key and store to TPM - Provision the TPM with a sealing key and authorize it with the PCR policy
* Add Key to decrypt the LUKS partition - The decrypt key that has been provisioned to the TPM needs to be added to the LUKS partition

> **_Note:_**  Ensure proxy environment variables are set if required.

The above steps can be done by running the ```/Script/reference/setup_fde.sh``` script 
```
git clone https://github.com/openvinotoolkit/security_addon.git ~/security_addon
cd ~/security_addon/Scripts/reference/setup_fde.sh
sudo -E ./setup_fde.sh
```
> **_Note:_**  While adding the key to the LUKS partition for decryption, the script would prompt the user to enter a passphrase. Enter the passphrase that was earlier provided during the **Guided storage configuration** sceen in the installation.

On successfully running the script, reboot the machine.
```
sudo reboot
```
The machine would now boot without asking for any passphrase.











