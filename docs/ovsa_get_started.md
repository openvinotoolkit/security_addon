
# OpenVINO™ Security Add-on

This guide provides instructions for people who use the OpenVINO™ Security Add-on to create, distribute, and use models that are created with the OpenVINO™ toolkit:

* **Model Developer**: The Model Developer interacts with the Independent Software Vendor to control the User access to models. This document shows you how to setup hardware and different software components to use the OpenVINO™ Security Add-on to define access control to your OpenVINO™ models and then provide the access controlled models to the users. 
* **Independent Software Vendor**: Use this guide for instructions to use the OpenVINO™ Security Add-on to validate license for access controlled models that are provided to your customers (users). 
* **User**: This document includes instructions for end users who need to access and run access controlled models through the OpenVINO™ Security Add-on.

In this release, one person performs the role of both the Model Developer and the Independent Software Vendor. Therefore, this document provides instructions to configure one system for these two roles and one system for the User role. This document also provides a way for the same person to play the role of the Model Developer, Independent Software Vendor, and User to let you see how the OpenVINO™ Security Add-on functions from the User perspective.


## Overview

The OpenVINO™ Security Add-on works with the [OpenVINO™ Model Server](@ref openvino_docs_ovms) on Intel® architecture. Together, the OpenVINO™ Security Add-on and the OpenVINO™ Model Server provide a way for Model Developers and Independent Software Vendors to use secure packaging and secure model execution to enable access control to the OpenVINO™ models, and for model Users to run inference within assigned limits.

The OpenVINO™ Security Add-on consists of three components. A brief description of the three components are as follows. Click each triangled line for more information about each. 

<details>
    <summary><strong>OpenVINO™ Security Add-on Tool</strong>: As a Model Developer or Independent Software Vendor, install and use the OpenVINO™ Security Add-on Tool(`ovsatool`) in a Trusted Execution Environment (TEE) to generate a access controlled model and master license. </summary>

- The Model Developer generates a access controlled model from the OpenVINO™ toolkit output. The access controlled model uses the model's Intermediate Representation (IR) files to create a access controlled output file archive that are distributed to Model Users. The Developer can also put the archive file in long-term storage or back it up without additional security. 

- The Model Developer uses the OpenVINO™ Security Add-on Tool(`ovsatool`) to generate and manage cryptographic keys and related collateral for the access controlled models. Cryptographic material is only made available inside a Trusted Execution Environment (TEE). The OpenVINO™ Security Add-on key management system lets the Model Developer to get external Certificate Authorities to generate certificates to add to a key-store. 

- The Model Developer generates user-specific licenses in a JSON format file for the access controlled model. The Model Developer can define global or user-specific licenses and attach licensing policies to the licenses. For example, the Model Developer can add a time limit for a model or limit the number of times a user can run a model.
</details>

<details>
    <summary><strong>OpenVINO™ Security Add-on Runtime</strong>: Users install and use the OpenVINO™ Security Add-on Runtime inside a Trusted Execution Environment (TEE). </summary>

Users host the OpenVINO™ Security Add-on Runtime component inside a Trusted Execution Environment (TEE) to provide a way to run security-sensitive opeerations in an isolated environment. 

Externally from the OpenVINO™ Security Add-on, the User adds the access controlled model to the OpenVINO™ Model Server startup configuration file. The OpenVINO™ Model Server attempts to load the model in memory. At this time, the OpenVINO™ Security Add-on Runtime component validates the user's license for the access controlled model against information stored in the License Service provided by the Independent Software Vendor. 

After the license is successfully validated, the OpenVINO™ Model Server loads the model and services the inference requests. 
</details>

<details>
    <summary><strong>OpenVINO™ Security Add-on License Service</strong>: Use the OpenVINO™ Security Add-on License Service to verify user parameters.</summary>

- The Independent Software Vendor hosts the OpenVINO™ Security Add-on License Service, which responds to license validation requests when a user attempts to load a access controlled model in a model server. The licenses are registered with the OpenVINO™ Security Add-on License Service.

- When a user loads the model, the OpenVINO™ Security Add-on Runtime contacts the License Service to make sure the license is valid and within the parameters that the Model Developer defined with the OpenVINO™ Security Add-on Tool(`ovsatool`). The user must be able to reach the Independent Software Vendor's License Service over the Internet. 
</details>


## Getting Started with OpenVINO™ Security Add-on

OpenVINO™ Security Add-on can be installed and run within Kernel-based Virtual Machines (KVMs) or an Intel® SGX enabled CPU running inside SGX Enclave as a Trusted Execution Environment. OpenVINO™ Security Add-on can also be installed and run in the Kubernetes environment however, Trusted Execution Environment runtime isolation (virtualization) is absent: when OpenVINO™ Security Add-on is installed and run in the Kubernetes environment.

Refer the below guides to install and run OpenVINO™ Security Add-on:
- [OpenVINO™ Security Add-on for KVM](ovsa_get_started_kvm.md)
- [OpenVINO™ Security Add-on for SGX](ovsa_get_started_sgx.md)
- [OpenVINO™ Security Add-on for Kubernetes](../deployment/kubernetes/README.md)
