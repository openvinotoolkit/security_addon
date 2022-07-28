# OpenVINO™ Security Add-on for Kubernetes

This guide provides instructions to run the OpenVINO™ Security Add-on in a Kubernetes environment.

## About the Installation
The Model Developer and the Independent Software Vendor each must prepare one physical hardware (Host Machine). The Model User would prepare multiple physical hardware to setup the Kubernetes cluster (with one master node and multiple worker nodes).

**Purpose of Each Machine**

| Machine      | Purpose |
| ----------- | ----------- |
| Host Machine      | The Model Developer uses the Host Machine to enable access control to the completed model.<br>The Independent Software Provider hosts the License Service. |
| Kubernetes Master Node | The Model User uses the Master Node to control the Kubernetes cluster which would run the orchestrated OpenVINO™ Security Add-on runtime |
|  Kubernetes Worker Nodes | The Model User deploys OpenVINO™ Security Add-on runtime to the Worker Nodes  |


## Prerequisites <a name="prerequisites"></a>

The hardware requirement listed below are the minimum configurations required for the Host Machine (Model Developer / Independent Software Vendor, Model User's Kubernetes Master Node and Model User's Kubernetes Worker Nodes). 

**Hardware**
* Intel® Core™ or Xeon® processor<br>
* 16GB RAM
* 1GB Ethernet NIC
* 20 GB Free Disk Space in the ```/``` partition 

**Operating system, firmware, and software**
* Ubuntu 20.04.3 LTS on the Host Machine.<br>
* TPM version 2.0-conformant Discrete Trusted Platform Module (dTPM) or Firmware Trusted Platform Module (fTPM)
* Secure Boot is enabled in BIOS<br>

**Other**
* The Independent Software Vendor must have access to a Certificate Authority (CA) that implements the Online Certificate Status Protocol (OCSP), supporting Elliptic Curve Cryptography (ECC) certificates for deployment.
* The example in this document uses self-signed certificates.

## How to Prepare a Host Machine <a name="setup-host"></a>

This section guides to prepare the host machines for all the roles. The Model Developer / Independent Software Vendors would setup their host machines to access control the model and host the License Server. The Model User would require to prepare multiple host machines to setup the Kubernetes cluster.

Begin this step on all the host machines that meets the <a href="#prerequisites">prerequisites</a>.

1. Download the [OpenVINO™ Security Add-on](https://github.com/openvinotoolkit/security_addon)
	```sh
	git clone https://github.com/openvinotoolkit/security_addon.git ~/security_addon
	cd ~/security_addon
	```
2. Install the TPM dependency packages on the host machine. Run the script `install_tpm_deps.sh` to install all the required packages.
	```sh
	cd ~/security_addon/Scripts/reference
	sudo -E ./install_tpm_deps.sh
	```
3. To setup the Full Disk Encryption, refer to  [Full Disk Encryption on Ubuntu 20.04 using LUKS with TPM](ovsa_fde_setup.md) 

4. Install Docker. 
The Docker packages is required to build the OpenVINO™ Security Add-on software components. Installation of Docker packages can be ignored for the Model Developer / Independent Software Vendor. In the case of Model Users, a container runtime is anyways required as a pre-requisite to setup the Kubernetes cluster.
    ```sh	
    sudo -E apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    sudo add-apt-repository \
           "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
           $(lsb_release -cs) \
           stable"
    sudo -E apt-get update
    sudo -E apt-get remove docker docker-engine docker.io containerd runc
    sudo -E apt-get install -y docker-ce docker-ce-cli containerd.io             
    ```	

5. Create `ovsa` user.
	```sh
	sudo useradd -m ovsa
	sudo passwd ovsa
	```
6. Setup the Kubernetes cluster to orchestrate the OpenVINO™ Security Add-on runtime.
	> **Note**:  This step is only for Model User

	The Model User would need to setup a Kubernetes cluster.  
	
	Starting Kubernetes v1.20, Kubernetes deprecated docker as a runtime. Ensure you setup a valid container runtime. Follow 		the [instructions](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/) to setup a Kubernetes cluster. For full features, please install Kubernetes v1.23.6 or later.

## How to Build and Install the OpenVINO™ Security Add-on Software <a name="ovsa-install"></a>

Follow the below steps to build and install OpenVINO™ Security Add-on.

### Step 1: Build the OpenVINO™ Model Server 
Building OpenVINO™ Security Add-on depends on OpenVINO™ Model Server docker containers. Download and build OpenVINO™ Model Server first on the host.

Download and build the [OpenVINO™ Model Server software](https://github.com/openvinotoolkit/model_server)
```sh
git clone https://github.com/openvinotoolkit/model_server.git ~/model_server
cd ~/model_server
git checkout v2022.1
sudo -E make docker_build
```
	
### Step 2: Build the OpenVINO™ Security Add-on for all roles
1. Download the [OpenVINO™ Security Add-on](https://github.com/openvinotoolkit/security_addon)
	```sh
	git clone https://github.com/openvinotoolkit/security_addon.git ~/security_addon
	cd ~/security_addon/deployment/kubernetes
	```

2. Build the OpenVINO™ Security Add-on:
	```sh
	sudo -E ./build.sh
	```

3. Go to the `release_files_k8` directory:
	```sh
    cd release_files_k8
	```
	The following packages are created under the `release_files_k8` directory:
	- `ovsa-tools.tar.gz`: OVSA Tools for the Model Developer and the Model User 
	- `ovsa-k8-master.tar.gz`: OVSA Runtime K8 master node components for Model User
	- `ovsa-k8-worker.tar.gz`: OVSA Runtime K8 worker node components for Model User
	- `ovsa-license-server.tar.gz`: License Server

4. Copy the below Model Developer packages to the designated Model Developer's host machine.
	- `ovsa-tools.tar.gz`

5. Copy the below License Server package to the designated ISV's host machine.
	- `ovsa-license-server.tar.gz`

6. Copy the below K8 Master Node packages to the designated Model User's master node host machine.
	- `ovsa-k8-master.tar.gz`

7. Copy the below K8 Worker Node packages to the designated Model User's worker node host machine.
	- `ovsa-tools.tar.gz`
	- `ovsa-k8-worker.tar.gz`

### Step 3: Install the OpenVINO™ Security Add-on Tools
The OpenVINO™ Security Add-on Tools would be required to be installed on the Model Developer and all the Model User's Worker Nodes

 Go to the location where the `ovsa-tools.tar.gz`  has been copied.
```sh
tar xvfz ovsa-tools.tar.gz
cd ovsa-tools
sudo ./install.sh
```
This would install the OpenVINO™ Security Add-on Software to `/opt/ovsa/host` folder. The below are the folder structure details:
- `/opt/ovsa/host/bin`- Contains all the binaries
- `/opt/ovsa/host/lib` - Contains all the dependent libraries
- `/opt/ovsa/host/scripts` - Contains scripts to setup path
- `/opt/ovsa/host/keystore` - This is the folder where all keystore files would be created and accessed
- `/opt/ovsa/host/artefacts` - This is the folder where all artefacts files would be created and accessed

### Step 4: Install the OpenVINO™ Security Add-on License Server
The OpenVINO™ Security Add-on License Server would be required to be installed on the ISV's host machine.

 Go to the location where the `ovsa-license-server.tar.gz`  has been copied.
```sh
tar xvfz ovsa-license-server.tar.gz
cd ovsa-license-server
sudo -E ./install.sh
```
This would install the OpenVINO™ Security Add-on License Server to `/opt/ovsa/` folder. The below are the folder structure details:
- `/opt/ovsa/bin`- Contains all the binaries
- `/opt/ovsa/lib`- Contains all the dependent libraries
- `/opt/ovsa/DB`- Contains the database & scripts to create and update the database
- `/opt/ovsa/scripts`- Contains scripts to setup path and generate certificates
- `/opt/ovsa/certs`- This is the folder where the License Server certificate are allowed to be present.

### Step 5: Install the OpenVINO™ Security Add-on K8 Master Node components 
The OpenVINO™ Security Add-on K8 master node components would be required to be installed on the Model User's Master Node.

1. Go to the location where the `ovsa-k8-master.tar.gz`  has been copied.

2. Install the master node components
	```sh
	tar xvfz ovsa-k8-master.tar.gz
	cd ovsa-k8-master
	sudo ./install.sh
	```
	This would install the OpenVINO™ Security Add-on K8 master node components to `/opt/ovsa/k8` folder. 
	The below are the folder structure details:
	- `/opt/ovsa/k8/*.yaml` - YAML files required for the deployment
	- `/opt/ovsa/k8/*.sh` - Start/Stop scripts to start/stop the deployment. Clean script to reset the custom cluster settings.

	The below containers are also loaded as part of the installation:
	- `openvino/model_server-ovsa_host-k8:latest` 
	- `squat/generic-device-plugin:amd64-latest` 

3. Install Istio

	Install Istio on the Kubernetes cluster to securely connect to your microservices. Install Istio on the designated master node. For more details refer to the  [Istio](https://istio.io/latest/docs/setup/getting-started/) documentations.
	
	Download Istio to the `/opt/ovsa/k8` folder.
	```sh
	cd /opt/ovsa/k8
	curl -L https://istio.io/downloadIstio | ISTIO_VERSION=1.14.1 TARGET_ARCH=x86_64 sh -
	```
	
4. Generate Server & Client Certificates

	To ensure to securely connect to the Kubernetes Istio gateway, it is required to have certificates generated for both the `server` (master node which exposes the gateway) and the `client` (client machine from where the inference is performed). To generate self-signed certificate, run the below script along with the domain name of the server as well as the client.

	> **Note**:  Ensure you have the Fully Qualified Domain Name (FQDN) of master node host machine and the client host machine from where inference would be peroformed.

	To get the FQDN
	```sh
	hostname --fqdn
	```
	
	To generate the certificates
	```sh
	cd /opt/ovsa/k8
	./k8-generate_certs.sh -s <server-machine-fqdn> -c <client-machine-fqdn>
	```


### Step 6: Install the OpenVINO™ Security Add-on K8 Worker Node components 
The OpenVINO™ Security Add-on K8 worker node components would be required to be installed on all the Model User's Worker Nodes.

 Go to the location where the `ovsa-k8-worker.tar.gz`  has been copied.
```sh
tar xvfz ovsa-k8-worker.tar.gz
cd ovsa-k8-worker
sudo ./install.sh
```
This would install the OpenVINO™ Security Add-on K8 worker node components to `/opt/ovsa/k8` folder. 
The below are the folder structure details:
- `/opt/ovsa/k8/*.sh` - Clean script to reset the custom cluster settings.
- `/opt/ovsa/host/example_runtime/sample.json` - Json configuration used for loading the model.

The below containers are also loaded as part of the installation:
- `openvino/model_server-ovsa_host-k8:latest` 
- `squat/generic-device-plugin:amd64-latest` 


## How to Use the OpenVINO™ Security Add-on

This section requires interactions between the Model Developer/Independent Software vendor and the Model User. All roles must complete all applicable <a href="#setup-host">set up steps</a> before beginning this section.

This document uses the face-detection-retail-0004 model as an example. 

### Model Developer - Publish Model
The Model Developer creates a model and defines access control, before publishing the model.

Log on to the Host Machine in a new terminal.

#### Step 1: Setup up the artefacts directory
```sh
mkdir -p /opt/ovsa/host/artefacts/fd
```
#### Step 2: Create a key store and add a certificate to it
1. Create files to request a certificate:
	This example uses a self-signed certificate for demonstration purposes. In a production environment, use CSR files to request for a CA-signed certificate. 
	```sh
	/opt/ovsa/host/bin/ovsatool keygen -storekey -t ECDSA -n Intel -k /opt/ovsa/host/keystore/isv_keystore -r  /opt/ovsa/host/artefacts/fd/isv_keystore.csr -e "/C=IN/CN=localhost"
 	```
	Below four files are created along with the keystore file:
	- `primary_isv_keystore.csr`- A Certificate Signing Request (CSR)  
	- `primary_isv_keystore.csr.crt` - A self-signed certificate
	- `secondary_isv_keystore.csr`- A Certificate Signing Request (CSR)  
	- `secondary_isv_keystore.csr.crt` - A self-signed certificate

	In a production environment, obtain CA-signed certificates using the `primary_isv_keystore.csr` and `secondary_isv_keystore.csr`.
		
	The above certificates must be inserted to the Trust Store using instructions specified in the [Inserting Trusted Certificate into the Trust Store](trusted_certificates.md)  document

3. Add the certificate to the key store
	```sh
	/opt/ovsa/host/bin/ovsatool keygen -storecert -c /opt/ovsa/host/artefacts/fd/primary_isv_keystore.csr.crt -k  /opt/ovsa/host/keystore/isv_keystore
	/opt/ovsa/host/bin/ovsatool keygen -storecert -c /opt/ovsa/host/artefacts/fd/secondary_isv_keystore.csr.crt -k  /opt/ovsa/host/keystore/isv_keystore
	```

#### Step 3: Download the model
This example uses `curl` to download the `face-detection-retail-004` model from the OpenVINO Model Zoo. If you are behind a firewall, check and set your proxy settings.

Download a model from the Model Zoo:
```sh
curl --create-dirs https://download.01.org/opencv/2021/openvinotoolkit/2021.1/open_model_zoo/models_bin/1/face-detection-retail-0004/FP32/face-detection-retail-0004.xml https://download.01.org/opencv/2021/openvinotoolkit/2021.1/open_model_zoo/models_bin/1/face-detection-retail-0004/FP32/face-detection-retail-0004.bin -o /opt/ovsa/host/artefacts/face-detection-retail-0004.xml -o /opt/ovsa/host/artefacts/face-detection-retail-0004.bin
```
The model is downloaded to the `/opt/ovsa/host/artefacts/` directory

#### Step 4: Define access control for  the model and create a master license for it
Define and enable the model access control and master license:
```sh	
uuid=$(uuidgen)
/opt/ovsa/host/bin/ovsatool controlAccess -i /opt/ovsa/host/artefacts/face-detection-retail-0004.xml /opt/ovsa/host/artefacts/face-detection-retail-0004.bin -n "face detection" -d "face detection retail" -v 0004 -p /opt/ovsa/host/artefacts/fd/face_detection_model.dat -m /opt/ovsa/host/artefacts/fd/face_detection_model.masterlic -k /opt/ovsa/host/keystore/isv_keystore -g $uuid
```
The Intermediate Representation files for the `face-detection-retail-0004` model are encrypted as `face_detection_model.dat` and a master license is generated as `face_detection_model.masterlic`

#### Step 5: Create a Runtime Reference TCB
Use the runtime reference TCB to create a customer license for the access controlled model and the specific runtime.

Generate the reference TCB for the runtime
```sh
/opt/ovsa/host/bin/ovsaruntime gen-tcb-signature -n "Face Detect @ Runtime VM Host" -v "1.0" -f /opt/ovsa/host/artefacts/fd/face_detect_runtime_vm.tcb -k /opt/ovsa/host/keystore/isv_keystore  -h 0xffffff
```

> **Note**:  If any of the PCR register needs to be excluded from validation with license server, it can be excluded while generating the reference TCB using "-s" & "-h" option. If any PCR registers from SW TPM needs to be excluded the corresponding bit needs to be cleared with "-s" option. Ex, if PCR0 needs to be excluded use -s 0xFFFFFE. Use "-h" option for exclduing any PCR registers from HW TPM. Use "tpm2_pcrread" command to read the PCR register values from TPM.

#### Step 6: Publish the access controlled Model and Runtime Reference TCB
The access controlled model is now ready to be shared. The Model Developer can publish the model, along with the reference TCB. 

The Model User can now request the access controlled model. 

### Model User - Request Access Controlled Model

Continue to generate the Model User artefacts.  In a new terminal window, the log on to the Model User's worker node. 

> **Note**:  This example shows how to generate the Model User artefacts on one of the worker node (referred as `workernode1`). The Model User need to repeat this step on all the worker nodes.

> **Note**:  This example refers to the Model User artefacts on the worker node 1, with `workernode1` specified in the respective artefact file names.

#### Step 1: Setup up the artefacts directory
To enable the corresponding artefacts are available to the OpenVINO™ Model Server, the below artefacts would need to be created under `/opt/ovsa/host/artefacts/fd/` directory.
```sh
mkdir -p /opt/ovsa/host/artefacts/fd/1
```

#### Step 2: Create a key store and add a certificate to it
1. Generate a Customer key store file:
	```sh
	/opt/ovsa/host/bin/ovsatool keygen -storekey -t ECDSA -n Intel -k /opt/ovsa/host/keystore/workernode1keystore -r  /opt/ovsa/host/artefacts/fd/1/workernode1keystore.csr -e "/C=IN/CN=localhost"
	```
	Below four files are created along with the workernode1keystore  file:
	* `primary_workernode1keystore.csr` - A Certificate Signing Request (CSR)
	* `primary_workernode1keystore.csr.crt` - A self-signed certificate
	* `secondary_workernode1keystore.csr` - A Certificate Signing Request (CSR)
	* `secondary_workernode1keystore.csr.crt` - A self-signed certificate
		
2. Obtain CA-signed certificate using `primary_workernode1keystore.csr` and `secondary_workernode1keystore.csr`.
		
   The above certificates must be inserted to the Trust Store using instructions specified in the [Inserting Trusted Certificate into the Trust Store](trusted_certificates.md)  document

3. Add the certificate to the key store:
	```sh
	/opt/ovsa/host/bin/ovsatool keygen -storecert -c /opt/ovsa/host/artefacts/fd/1/primary_workernode1keystore.csr.crt -k /opt/ovsa/host/keystore/workernode1keystore
	/opt/ovsa/host/bin/ovsatool keygen -storecert -c /opt/ovsa/host/artefacts/fd/1/secondary_workernode1keystore.csr.crt -k /opt/ovsa/host/keystore/workernode1keystore
	```
#### Step 3: Request an access controlled Model from the Model Developer

1. Communicate your need for a model to the Model Developer. The Developer will ask you to provide the certificate from your key store and other information. This example uses the length of time the model needs to be available. 
2. The model User's worker node primary and secondary certificates needs to be provided to the Model Developer.
3. Copy the `primary_workernode1keystore.csr.crt` and `secondary_workernode1keystore.csr.crt` to the Model Developer/ISV host machine's `/opt/ovsa/host/artefacts/fd` directory.

> **Note**:  Repeat steps 1 - 3 on all the worker nodes.

### Model Developer - Generate Customer License

#### Step 1: Receive a Model User Request
1. Obtain artefacts from the Model User who needs access to a access controlled model:
	* Primary certificate from the Model User's worker node  key store to be used for generating the customer license.
	* Secondary certificate from the Model User's worker node key store for validating the customer by the License Server.
	* Other information that apply to your licensing practices, such as the length of time the user needs access to the model

   The above customer certificates must be inserted to the Trust Store using instructions specified in the [Inserting Trusted Certificate into the Trust Store](trusted_certificates.md)  document

#### Step 2: Create Customer License Configuration
Create a customer license configuration
```sh
/opt/ovsa/host/bin/ovsatool licgen -t TimeLimit -l30 -n "Time Limit License Config" -v 1.0 -u "<isv-ip-address>:4452" /opt/ovsa/certs/server.crt -k /opt/ovsa/host/keystore/isv_keystore -o /opt/ovsa/host/artefacts/fd/30daylicense.config
```

> **Note**:<br>- Ensure you provide the correct `<isv-ip-address>` where the License Server is running.<br>- The parameter /opt/ovsa/certs/server.crt  contains the certificate used by the License Server. The server certificate will be added to the customer license and validated during use. Refer to [OpenVINO™ Security Add-on License Server Certificate Pinning](ovsa_license_server_cert_pinning.md)

#### Step 3: Create the customer license
```sh
/opt/ovsa/host/bin/ovsatool sale -m /opt/ovsa/host/artefacts/fd/face_detection_model.masterlic -k /opt/ovsa/host/keystore/isv_keystore -l /opt/ovsa/host/artefacts/fd/30daylicense.config -t /opt/ovsa/host/artefacts/fd/face_detect_runtime_vm.tcb -p /opt/ovsa/host/artefacts/fd/primary_workernode1keystore.csr.crt -c /opt/ovsa/host/artefacts/fd/face_detection_model_workernode1.lic
```
> **Note**: If new private keys are generated, a new customer license would need to be generated for the model.

#### Step 4: Update the license server database with the license.
> **Note**: If the License Server is hosted on a different machine, the customer license, customer primary and secondary certificates need to be copied to the machine hosting the License Server first and then updated to the DB.
```sh
python3 /opt/ovsa/DB/ovsa_store_customer_lic_cert_db.py /opt/ovsa/DB/ovsa.db /opt/ovsa/host/artefacts/fd/face_detection_model_workernode1.lic /opt/ovsa/host/artefacts/fd/primary_workernode1keystore.csr.crt /opt/ovsa/host/artefacts/fd/secondary_workernode1keystore.csr.crt
```

#### Step 5: Share the Access Controlled Model with Model User
Provide these files to the User:
	* `face_detection_model.dat`
	* `face_detection_model_workernode1.lic`

> **Note**:  Repeat steps 1 - 5 to generate the license for all the worker nodes.

### Model User's Worker Node - Load Access Controlled Model to OpenVINO™ Model Server

#### Step 1: Load the access controlled model into the OpenVINO™ Model Server
1. Receive the access controlled model and the customer license file from the Model Developer

2. Copy the access controlled model and the customer license to `/opt/ovsa/host/artefacts/fd/1`

3. Rename the customer license.
	```sh
	mv /opt/ovsa/host/artefacts/fd/1/face_detection_model_workernode1.lic /opt/ovsa/host/artefacts/fd/1/face_detection_model.lic 
	```

4.  Prepare to load the model:
	```sh
	cd /opt/ovsa/host/example_runtime
	```

5. Edit the `sample.json` to include the names of the access controlled model artefacts you received from the Model Developer. The file looks like this:
	```sh
	{
	"custom_loader_config_list":[
		{
			"config":{
					"loader_name":"ovsa",
					"library_path": "/ovsa-runtime/lib/libovsaruntime.so"
			}
		}
	],
	"model_config_list":[
		{
		"config":{
			"name":"controlled-access-model",
			"base_path":"/opt/ovsa/host/artefacts/fd",
			"custom_loader_options": {"loader_name":  "ovsa", "keystore":  "/opt/ovsa/host/keystore/workernode1keystore", "controlled_access_file": "face_detection_model"}
		}
		}
	]
	}
	```

> **Note**:  Repeat steps 1 - 5 to load the access controlled model on all the worker nodes.

#### Step 2: Start the OpenVINO™ Security Add-on License Server 
In a new terminal, connect to the ISV machine where the License Server has been installed as `ovsa` user.

```sh
source /opt/ovsa/scripts/setupvars.sh
cd /opt/ovsa/bin
./license_server
```
> **Note**: If you are behind a firewall, check and set your proxy settings to ensure the license server is able to validate the certificates.


#### Step 3: Start the OpenVINO™ Security Add-on Runtime 
Deploy the OpenVINO™ Security Add-on Runtime on the Model User's master node.

> **Note**:  Ensure you have the Fully Qualified Domain Name (FQDN) of master node host machine to start the deployment.

To get the FQDN
```sh
hostname --fqdn
```
```sh
cd /opt/ovsa/k8/
./k8-start.sh <master-node-fqdn>
```
The above commands would deploy the OpenVINO™ Security Add-on Runtime application, application gateway and the virtual service.

We are now ready to test access to the application. To do this, we will need the external IP associated with our istio-ingressgateway Service, which is a LoadBalancer Service type.

Get the external IP for the istio-ingressgateway Service with the following command:
```sh
kubectl get svc istio-ingressgateway -n istio-system
```
You will see output like the following:
```sh
NAME                   TYPE           CLUSTER-IP       EXTERNAL-IP   PORT(S)                                      AGE
istio-ingressgateway   LoadBalancer   10.108.107.171   <pending>     15021:30966/TCP,80:31417/TCP,443:30392/TCP   20h
```

> **Note**: From the above output sample, use the FQDN of the master node as the `grpc_address` and `30392` as the `grpc_port` to perform inference


#### Step 3: Prepare to run Inference

1. Log on to the designated client machine from where inference would be performed.

2. Go to the location where you would want to download the required files for performing the inference. The below command would setup the files required for inferencing under `~/` directory.
	```sh
	mkdir -p ~/example_client
	```
3. Download the scripts required for inferencing.
	```sh
	cd ~/example_client
	curl --create-dirs https://raw.githubusercontent.com/openvinotoolkit/security_addon/master/Example/client/client_utils.py -o client_utils.py
	curl --create-dirs https://raw.githubusercontent.com/openvinotoolkit/security_addon/master/Example/client/face_detection.py -o face_detection.py
	```

4. Download the sample images for inferencing. An image directory is created that includes a sample image for inferencing.
	```sh
	cd ~/example_client
	curl --create-dirs https://raw.githubusercontent.com/openvinotoolkit/model_server/master/example_client/images/people/people1.jpeg -o images/people1.jpeg
	```

5. Copy the Server & Client certificates. 

	`Model User's master node`:`/var/OVSA/k8` => `Client machine`:`~/example_client`
	
	The following certificate files are required to be copied:
	- server.crt
	- client.crt
	- client.key 

6. Install the Python dependencies for your set up. For example:
	```sh
	# before install
	pip3 install --upgrade pip
	sudo apt-get install python3-venv

	# first time install
	cd ~/example_client
	python3 -m venv .env 
	source .env/bin/activate
	python -m pip install --upgrade pip
	pip install futures==3.1.1
	pip install opencv-python==4.4.0.46
	pip install tensorflow-serving-api==2.*
	```

#### Step 4:  Run Inference

Run the `face_detection.py` script.
```sh
cd ~/example_client/
source .env/bin/activate
python3 face_detection.py --grpc_address <server-machine-fqdn> --grpc_port <server-machine-gateway-port> --batch_size 1 --width 300 --height 300 --input_images_dir images --output_dir results --model_name controlled-access-model --tls --server_cert ~/example_client/server.crt --client_cert ~/example_client/client.crt --client_key ~/example_client/client.key
```


## Summary
You have completed these tasks:
- Set up one or more computers (Host Machines) as Host Machines
- Installed the OpenVINO™ Security Add-on 
- Used the OpenVINO™ Model Server to work with OpenVINO™ Security Add-on.
- As a Model Developer or Independent Software Vendor, you access controlled a model and prepared a license for it using the OpenVINO™ Security Add-on for Host.
- As a Model Developer or Independent Software Vendor, you prepared and ran a License Server and used the License Server to verify a User had a valid license to use a access controlled model.
- As a Model User, you provided information to a Model Developer or Independent Software Vendor to get a access controlled model and the license for the model.
- As a Model User, you set up and launched the OpenVINO™ Security Add-on runtime in the Kubernetes cluster on which you can run licensed and access controlled models.
- As a User, you loaded a access controlled model, validated the license for the model, and used the model to run inference.

## References
Use these links for more information:
- [OpenVINO&trade; toolkit](https://software.intel.com/en-us/openvino-toolkit)
- [OpenVINO Model Server Quick Start Guide](https://github.com/openvinotoolkit/model_server/blob/main/docs/ovms_quickstart.md)
- [Model repository](https://github.com/openvinotoolkit/model_server/blob/main/docs/models_repository.md)

