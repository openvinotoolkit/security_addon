# OpenVINO™ Security Add-On Example Demo - Quick Start Guide

This guide provides instructions to run an example using the instructions as provided in ovsa_get_started document. Scripts are provided for Independent Software Vendor / Model Developer VM (ovsa_isv_dev) and Model User VM (ovsa_runtime) to simplify running the example.

This example uses self-signed certificates where ever certificates are used. Use Certificate Authority signed certificates for production environment.


### Pre-requsites:
- Follow ovsa_get_started.md guide to 
	- setup Host and GuestVM (ovsa_isv_dev & ovsa_runtime)
 	- install OpenVINO Security Add-on.
- Steps to avoid issuing password while SCP the artefacts from ovsa_isv_dev to ovsa_runtime and vice-versa
	- Connect (SSH) to ovsa_isv_dev using any terminal software
	- Go to .ssh directory. If .ssh directory is not there create using `mkdir .ssh`
 	```shell
 	cd ~/.ssh
 	```
 	- Create new key pair inside .ssh as below
 	```shell
 	ssh-keygen -t rsa
 	```
 	As you can see from the output of this command:
 	Your private key is in a file named ~/.ssh/id_rsa
 	Your public key is in a file named ~/.ssh/id_rsa.pub

 	- Copy the public key to the remote machine (ovsa_runtime) as below
	Step 1: ssh to ovsa_runtime
	Step 2: Create .ssh directory if not there
	Step 3: Copy the public key from ovsa_isv_dev to the ovsa_runtime as below
	```shell
	scp id_rsa.pub <user-name>@<ip-address-of-ovsa-runtime>:<user-home-folder>/.ssh
	```
	Step 4: Switch to ovsa_runtime terminal and rename public key to authorized_keys
	```shell
	mv id_rsa.pub authorized_keys
	```
	Step 5: To test that you can log on to ovsa_runtime without a password, log on to the Host machine and from there ssh to ovsa_runtime. If everything is setup properly, you will be able to logon without having to enter the password.
	
	Step 6: Repeat the steps 1 to 5 on ovsa_runtime to log on to ovsa_isv_dev without prompting for password from ovsa_runtime side.

### Setup terminal sessions
Setup 5 terminal sessions as below:

##### Terminal 1: ovsa_isv_dev for create access controlled models
```shell
ssh <user-name>@<ip-address-of-ovsa-isv-dev>
```

##### Terminal 2: ovsa_isv_dev for running License server
```shell
ssh <user-name>@<ip-address-of-ovsa-isv-dev>
sudo -s
cd /opt/ovsa/bin
source /opt/ovsa/script/setupvars.sh
./license_server
```

##### Terminal 3: ovsa_runtime to request for license and to perform inferencing of access controlled models
```shell
ssh <user-name>@<ip-address-of-ovsa-runtime>
```
##### Terminal 4: To host the OpenVINO™ Model Server and to load the access controlled models
```shell
ssh <user-name>@<ip-address-of-ovsa-runtime>
```

##### Terminal 5: To start OVSA Host Server on the Host machine
```shell
ssh <user-name>@<ip-address-of-ovsa-runtime>
sudo -s
cd /opt/ovsa/bin
source /opt/ovsa/script/setupvars.sh
./ovsa_host_server
```

### Prepare ovsa_isv_dev & ovsa_runtime VMs and extract scripts for running the demo
- On the Terminal 1, create below directories.
```shell
cd <user-home-folder>
mkdir -vp demo/artefacts
mkdir -vp /var/OVSA/artefacts
cd <user-home-folder>/demo
sudo -s
export OVSA_DEV_ARTEFACTS=<user-home-folder>/demo/artefacts
export PATH=$PATH:/opt/ovsa/bin:<user-home-folder>/demo
```
Note: Ensure these directories are created with `user-name` credentials to SCP the License request file & Customer certificate from ovsa_runtime.

- Copy the scripts from the cloned `security_addon` repository from the host.
```shell
scp <path-to-security-addon-repo>/Scripts/demo/developer/*  <user-name>@<ip-address-of-ovsa-isv-dev>:<user-home-folder>/demo
```

- This would copy the following scripts.
  - Create_Keystore - Creates cryptographic material and stores into the specified kesytore file
  -  Download_Model - Downloads the specified model from Model Zoo to generate model with access control restrictions.
  -  Protect_Model - Creates the access control enabled model for the downloaded model using Download_Model
  -  License_Request_Watcher - Daemon to monitor the License request & Customer certificate sent by ovsa_runtime for purchasing the access controlled model
  -  Create_License - Creates Customer license for the access controlled model based on the info provided while requesting for license from ovsa_runtime
  -  Send_License - Sends the Customer license and access controlled model to ovsa_runtime.
  -  Clean - Clears the artefacts folder

Note: Change the IP addresses and username in scripts to reflect your setup.

- Log on to Terminal 3, and create below directories
```shell
cd <user-home-folder>
mkdir -vp demo/artefacts/1
cd <user-home-folder>/demo
mkdir results
sudo -s
export OVSA_DEV_ARTEFACTS=<user-home-folder>/demo/artefacts/1
export PATH=$PATH:/opt/ovsa/bin:<user-home-folder>/demo
source /opt/ovsa/script/setupvars.sh
```
Note: Ensure these directories are created with `user-name` credentials to SCP the License request file & Customer certificate from ovsa_runtime.

- Copy the scripts from the cloned `security_addon` repository from the host.
```shell
scp <path-to-security-addon-repo>/Scripts/demo/user/*  <user-name>@<ip-address-of-ovsa-runtime>:<user-home-folder>/demo
```

- This would copy the following scripts
  - Create_Keystore - Creates cryptographic material and stores into the specified kesytore file
  - Request_License - Request license for a particular access controlled model with ovsa_isv_dev
  - Start_Model_Server - Starts the OpenVINO™ Model Server at ovsa_runtime
  - generate_certs.sh - Generates cryptographic keys for user authentication based on nginx interface
  - sample_xx.json - Sample configuration file for OpenVINO™ Model Server to load the access controller model
  - Infer_XX - To perform inferencing with the loaded access controlled model.

  Note: Change the IP addresses and username in scripts to reflect your setup.
  Note: OpenVINO™ Security Add-On is tested with face-detection-retail-0004 (FD), person-detection-retail-0013 (PD) and vehicle-detection-adas-0002 (VD) from Model Zoo and hence sample configuration JSON and inferencing scripts for these models would also be extracted. The corresponding configuration jsons are sample_fd.json, sample_pd.json, sample_vd.json and the corresponding scripts to run inferencing are Infer_FD, Infer_PD, Infer_VD.

- Download the images for inferencing. Setup the required proxy environment variables to connect to the internet
```shell
curl --create-dirs https://raw.githubusercontent.com/openvinotoolkit/model_server/master/example_client/images/people/people1.jpeg -o images/people1.jpeg
```

- Log on to Terminal 4
```shell
cd <user-home-folder>/demo
sudo -s
source /opt/ovsa/script/setupvars.sh
```

### Run the script on ovsa_isv_dev and ovsa_runtime for creating access control enabled model and to load this model on OpenVINO™ Model Server for inferencing
- On the Terminal 1, start the License-Request-Watcher daemon and the scripts mentioned in (b)
```shell
License_Request_Watcher &
```
- Continue executing the below scripts on Terminal 1 to create the developer keystore, download model & create access control for the model
```shell
Create_Keystore AX_Keystore
Download_Model face-detection-retail-0004
Protect_Model AX_Keystore model/face-detection-retail-0004
```
- On the Terminal 3, proceed to create the model users' keystore and request 30 day license for face-detection-retail-0004 model from the developer
```shell
Create_Keystore Customer_Keystore
Request_License face-detection-retail-0004 30 Customer_Keystore <user-home-folder>/demo/artefacts/1
```
- On the Terminal 1, there would be a request for the license from the customer. Proceed to create and send the customer license
```shell
Create_License AX_Keystore model/face-detection-retail-0004.tcb model/face-detection-retail-0004.dat model/face-detection-retail-0004.m_lic /var/OVSA/artefacts/face-detection-retail-0004.txt
Send_License face-detection-retail-0004.c_lic model/face-detection-retail-0004.dat <model-user-home-folder>/demo/artefacts/1
```
- On Terminal 3, the customer license and the access controlled model files are received in the `<user-home-folder>/demo/artefacts/1`.

- On Terminal 4, prepare to host the access controlled face-detection-retail-0004 model
```shell
cp sample_fd.json sample.json
Start_Model_Server
```

- On Terminal 3, perform inferencing using the face-detection-retail-0004
```shell
Infer_FD
```





