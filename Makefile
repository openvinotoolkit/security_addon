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

PLATFORM ?= x86_64

VERSION = 1.0
MAJOR = 1
MINOR = 0

TOPDIR := $(PWD)
export TOPDIR

HTTP_PROXY := "$(http_proxy)"
HTTPS_PROXY := "$(https_proxy)"
NO_PROXY := "$(no_proxy)"

SGX ?= 

DEBUG ?= 1
export DEBUG=1

BASE_IMAGE := openvino/model_server-build
ifeq ($(SGX),1)
export ENABLE_SGX_GRAMINE=1
endif

DEV_DIR := ovsa-developer
MODEL_HOSTING_DIR := ovsa-model-hosting
HOST_DIR := ovsa-kvm-host
LICSVR_DIR := ovsa-license-server
CLIENT_DIR := ovms-client
RUNTIME_DOCKER_DIR := ovsa-runtime-docker
SGX_DIR := ovsa-sgx
DIST_DIR := release_files
DIST_DEV_DIR := $(DIST_DIR)/$(DEV_DIR)/
DIST_MODEL_HOSTING_DIR := $(DIST_DIR)/$(MODEL_HOSTING_DIR)/
DIST_HOST_DIR := $(DIST_DIR)/$(HOST_DIR)/
DIST_LICSVR_DIR := $(DIST_DIR)/$(LICSVR_DIR)/
DIST_SGX_DIR := $(DIST_DIR)/$(SGX_DIR)/

SRC_BUILD_DIR  := $(PWD)
MV             := mv

export MV

.PHONY: all
all: ovsatool_build ovsaruntime_build license_service_build

ovsatool_build:
	$(MAKE) all -C $(SRC_BUILD_DIR)/Ovsa_tool

ovsaruntime_build:
	$(MAKE) all -C $(SRC_BUILD_DIR)/Ovsa_runtime

license_service_build:
	$(MAKE) all -C $(SRC_BUILD_DIR)/License_service

.PHONY: clean
clean:
	$(MAKE) -C $(SRC_BUILD_DIR)/Ovsa_tool clean
	$(MAKE) -C $(SRC_BUILD_DIR)/Ovsa_runtime clean
	$(MAKE) -C $(SRC_BUILD_DIR)/License_service clean
	rm -vrf $(DIST_DIR)

.PHONY: format
format:
	$(MAKE) -C $(SRC_BUILD_DIR)/Ovsa_tool format
	$(MAKE) -C $(SRC_BUILD_DIR)/Ovsa_runtime format
	$(MAKE) -C $(SRC_BUILD_DIR)/License_service format

.PHONY: distclean
distclean: clean
	$(MAKE) -C $(SRC_BUILD_DIR)/Ovsa_tool distclean
	$(MAKE) -C $(SRC_BUILD_DIR)/Ovsa_runtime distclean
	$(MAKE) -C $(SRC_BUILD_DIR)/License_service distclean

.PHONY: package
package: runtime_pkg developer_pkg sgx_pkg lic_server_pkg

.PHONY: docker_build
docker_build: ovsatool_build ovsaruntime_build
ifneq ($(SGX), 1)
	docker build -f Dockerfile-build-tpm . \
                --build-arg http_proxy=$(HTTP_PROXY)  \
                --build-arg https_proxy=$(HTTPS_PROXY) \
                --build-arg no_proxy=$(NO_PROXY) \
                --build-arg BASE_IMAGE=$(BASE_IMAGE) \
                -t openvino/model_server-ovsa-build:latest
	$(eval BASE_IMAGE = openvino/model_server-ovsa-build:latest)
endif
ifeq ($(SGX), 1)
	docker image rm -f gsc-openvino/model_server-ovsa-nginx-mtls:latest 2>&1
	docker image rm -f gsc-openvino/model_server-ovsa-nginx-mtls:latest-unsigned 2>&1

	mkdir -p  $(SRC_BUILD_DIR)/Ovsa_runtime/src/gramine/Pal/src/host/Linux-SGX/tools/ra-tls
	cp $(GRAMINE_DIR)/Pal/src/host/Linux-SGX/tools/ra-tls/ra_tls.h \
               $(SRC_BUILD_DIR)/Ovsa_runtime/src/gramine/Pal/src/host/Linux-SGX/tools/ra-tls
	cp $(GRAMINE_DIR)/Pal/src/host/Linux-SGX/sgx_arch.h \
               $(SRC_BUILD_DIR)/Ovsa_runtime/src/gramine/Pal/src/host/Linux-SGX
	cp $(GRAMINE_DIR)/Pal/src/host/Linux-SGX/sgx_attest.h \
               $(SRC_BUILD_DIR)/Ovsa_runtime/src/gramine/Pal/src/host/Linux-SGX
	cp $(GRAMINE_DIR)/build/Pal/src/host/Linux-SGX/tools/ra-tls/libra_tls_attest.so \
               $(SRC_BUILD_DIR)/Ovsa_runtime/lib
	rm -rf $(SRC_BUILD_DIR)/Ovsa_runtime/mbedtls_gramine
	mkdir -p $(SRC_BUILD_DIR)/Ovsa_runtime/mbedtls_gramine
	cp -r \
	   $(GRAMINE_DIR)/subprojects/mbedtls-mbedtls-2.26.0-1/mbedtls-mbedtls-2.26.0/include/mbedtls \
	   $(SRC_BUILD_DIR)/Ovsa_runtime/mbedtls_gramine/
	cp -r \
	   $(GRAMINE_DIR)/subprojects/mbedtls-mbedtls-2.26.0-1/mbedtls-mbedtls-2.26.0/include/psa \
	   $(SRC_BUILD_DIR)/Ovsa_runtime/mbedtls_gramine/
	mkdir -p $(SRC_BUILD_DIR)/Ovsa_runtime/lib_gramine
	cp \
	   $(GRAMINE_DIR)/build/subprojects/mbedtls-mbedtls-2.26.0-1/libmbedcrypto_gramine.a \
	   $(SRC_BUILD_DIR)/Ovsa_runtime/lib_gramine/libmbedcrypto.a
	cp \
	   $(GRAMINE_DIR)/build/subprojects/mbedtls-mbedtls-2.26.0-1/libmbedtls_gramine.a \
	   $(SRC_BUILD_DIR)/Ovsa_runtime/lib_gramine/libmbedtls.a
	cp \
	   $(GRAMINE_DIR)/build/subprojects/mbedtls-mbedtls-2.26.0-1/libmbedx509_gramine.a \
	   $(SRC_BUILD_DIR)/Ovsa_runtime/lib_gramine/libmbedx509.a
	cp $(SRC_BUILD_DIR)/Ovsa_runtime/lib/libra_tls_attest.so \
	   $(SRC_BUILD_DIR)/Ovsa_runtime/lib_gramine/
endif
	docker build -f Dockerfile-build-ovsa . \
                --build-arg http_proxy=$(HTTP_PROXY)  \
                --build-arg https_proxy=$(HTTPS_PROXY) \
                --build-arg no_proxy=$(NO_PROXY) \
                --build-arg BASE_IMAGE=$(BASE_IMAGE) \
                --build-arg use_sgx=$(SGX) \
                -t openvino/model_server-ovsa-build:latest

	mkdir -vp $(DIST_DIR)/ && cd $(DIST_DIR)/ && \
                docker run openvino/model_server-ovsa-build:latest bash -c \
                        "tar -c -C / ovsa-runtime.tar* ; sleep 2" | tar -x

	cd $(DIST_DIR) && tar -xzvf ovsa-runtime.tar.gz && rm ovsa-runtime.tar.gz

ifeq ($(SGX), 1)
	docker build --no-cache -f Dockerfile-pkg-ovsa-nginx-sgx . \
                --build-arg http_proxy=$(HTTP_PROXY) \
                --build-arg https_proxy=$(HTTPS_PROXY) \
                --build-arg no_proxy=$(NO_PROXY) \
                --build-arg use_sgx=$(SGX) \
                -t openvino/model_server-ovsa-nginx-mtls:latest

	cd $(GRAMINE_DIR)/gsc && \
                ./gsc build --no-cache --insecure-args \
                --build-arg http_proxy=$(HTTP_PROXY) \
                --build-arg https_proxy=$(HTTPS_PROXY) \
                --build-arg no_proxy=$(NO_PROXY) \
                -c $(SRC_BUILD_DIR)/Ovsa_runtime/gsc-ovms-config.yaml \
                openvino/model_server-ovsa-nginx-mtls:latest \
                $(SRC_BUILD_DIR)/Ovsa_runtime/gsc-ovms.manifest.template

	cd $(GRAMINE_DIR)/gsc && \
                ./gsc sign-image \
                -c $(SRC_BUILD_DIR)/Ovsa_runtime/gsc-ovms-config.yaml \
                openvino/model_server-ovsa-nginx-mtls:latest \
                $(GRAMINE_DIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

	docker save -o $(DIST_DIR)/model_server-ovsa-nginx-mtls.tar.gz \
		gsc-openvino/model_server-ovsa-nginx-mtls:latest
else
	docker build --no-cache -f Dockerfile-pkg-ovsa-nginx . \
                --build-arg http_proxy=$(HTTP_PROXY) \
                --build-arg https_proxy=$(HTTPS_PROXY) \
                --build-arg no_proxy=$(NO_PROXY) \
                --build-arg use_sgx=$(SGX) \
		-t openvino/model_server-ovsa-nginx-mtls:latest

	docker save -o $(DIST_DIR)/model_server-ovsa-nginx-mtls.tar.gz \
                openvino/model_server-ovsa-nginx-mtls:latest
endif
	cd $(DIST_DIR) && rm -rf ovsa-runtime

.PHONY: runtime_docker_pkg
runtime_docker_pkg: docker_build
	mkdir -p $(DIST_DIR)/$(RUNTIME_DOCKER_DIR)
	cp -vR $(DIST_DIR)/model_server-ovsa-nginx-mtls.tar.gz $(DIST_DIR)/$(RUNTIME_DOCKER_DIR)
	cp -vR Example/runtime/sample.json $(DIST_DIR)/$(RUNTIME_DOCKER_DIR)
	cp -vR Example/runtime/start_secure_ovsa_model_server.sh $(DIST_DIR)/$(RUNTIME_DOCKER_DIR)
	cp -vR Scripts/install/load_ovsa_runtime_docker.sh $(DIST_DIR)/$(RUNTIME_DOCKER_DIR)
	cd $(DIST_DIR) && tar cvzf $(RUNTIME_DOCKER_DIR).tar.gz $(RUNTIME_DOCKER_DIR)
	cd $(DIST_DIR) && rm -rf $(RUNTIME_DOCKER_DIR) model_server-ovsa-nginx-mtls.tar.gz

.PHONY: runtime_pkg
runtime_pkg: docker_build
ifneq ($(SGX), 1)
	mkdir -vp $(DIST_MODEL_HOSTING_DIR)
	cd $(DIST_MODEL_HOSTING_DIR) && \
		mkdir -vp bin && \
		mkdir -vp scripts && \
		mkdir -vp example_client && \
		mkdir -vp example_runtime
	mv $(DIST_DIR)/model_server-ovsa-nginx-mtls.tar.gz $(DIST_MODEL_HOSTING_DIR)
	cp -vR Ovsa_tool/bin/* $(DIST_MODEL_HOSTING_DIR)/bin
	cp -vR Example/client/* $(DIST_MODEL_HOSTING_DIR)/example_client/
	cp -vR Example/runtime/* $(DIST_MODEL_HOSTING_DIR)/example_runtime/
	cp -vR Scripts/guest/OVSA_create_ek_ak_keys.sh $(DIST_MODEL_HOSTING_DIR)/scripts/
	cp -vR Scripts/guest/OVSA_Seal_Key_TPM_Policy_Authorize.sh $(DIST_MODEL_HOSTING_DIR)/scripts/
	cp -vR Scripts/install/setupvars_kvm.sh  $(DIST_MODEL_HOSTING_DIR)/scripts/setupvars.sh
	cp -vR Scripts/install/install_model_hosting.sh $(DIST_MODEL_HOSTING_DIR)/install.sh
	cd $(DIST_DIR) && tar cvzf $(MODEL_HOSTING_DIR).tar.gz $(MODEL_HOSTING_DIR)
	cd $(DIST_DIR) && rm -rf $(MODEL_HOSTING_DIR)
endif

.PHONY: developer_pkg
developer_pkg: all
ifneq ($(SGX), 1)
	mkdir -vp $(DIST_DEV_DIR)
	cd $(DIST_DEV_DIR) && \
		mkdir -vp bin && \
		mkdir -vp lib && \
		mkdir -vp scripts
	cp -vR Ovsa_tool/bin/* $(DIST_DEV_DIR)/bin
	cp -vR Ovsa_runtime/bin/* $(DIST_DEV_DIR)/bin/
	cp -vR Ovsa_runtime/lib/* $(DIST_DEV_DIR)/lib
	cp -vR Scripts/guest/OVSA_create_ek_ak_keys.sh $(DIST_DEV_DIR)/scripts/
	cp -vR Scripts/guest/OVSA_Seal_Key_TPM_Policy_Authorize.sh $(DIST_DEV_DIR)/scripts/
	cp -vR Scripts/install/setupvars_kvm.sh $(DIST_DEV_DIR)/scripts/setupvars.sh
	cp -vR Scripts/install/install_developer.sh $(DIST_DEV_DIR)/install.sh
	cd $(DIST_DIR) && tar cvzf $(DEV_DIR).tar.gz $(DEV_DIR)
	cd $(DIST_DIR) && rm -rf $(DEV_DIR)
endif

.PHONY: lic_server_pkg
lic_server_pkg: license_service_build
	mkdir -vp $(DIST_LICSVR_DIR)
	cd $(DIST_LICSVR_DIR) && mkdir -vp bin && mkdir -vp DB && mkdir -vp lib && mkdir -vp scripts
	cp -vR License_service/bin/* $(DIST_LICSVR_DIR)/bin
	cp -vR License_service/lib/* $(DIST_LICSVR_DIR)/lib
	cp -vR DB/* $(DIST_LICSVR_DIR)/DB
	cp -vR Scripts/install/install_license_server.sh $(DIST_LICSVR_DIR)/install.sh
	cp -vR Scripts/guest/OVSA_install_license_server_cert.sh $(DIST_LICSVR_DIR)/scripts/
	cp -vR Scripts/install/setupvars_license_server.sh $(DIST_LICSVR_DIR)/scripts/setupvars.sh
	cd $(DIST_DIR) && tar cvzf $(LICSVR_DIR).tar.gz $(LICSVR_DIR)
	cd $(DIST_DIR) && rm -rf $(LICSVR_DIR)

.PHONY: client_pkg
client_pkg: 
	mkdir -p $(DIST_DIR)/$(CLIENT_DIR)
	cp -vR Example/client/* $(DIST_DIR)/$(CLIENT_DIR)
	cd $(DIST_DIR) && tar cvzf $(CLIENT_DIR).tar.gz $(CLIENT_DIR)
	cd $(DIST_DIR) && rm -rf $(CLIENT_DIR)

	echo "Done"

.PHONY: sgx_pkg
sgx_pkg:
ifeq ($(SGX), 1)
	mkdir -vp $(DIST_SGX_DIR)
	cd $(DIST_SGX_DIR) && \
		mkdir -vp bin && \
		mkdir -vp lib && \
		mkdir -vp scripts && \
		mkdir -vp example_client && \
		mkdir -vp example_runtime
	mv $(DIST_DIR)/model_server-ovsa-nginx-mtls.tar.gz $(DIST_SGX_DIR)
	cp -vR Ovsa_tool/bin/* $(DIST_SGX_DIR)/bin
	cp -vR Ovsa_tool/ovsatool.manifest.sgx $(DIST_SGX_DIR)/
	cp -vR Ovsa_tool/ovsatool.sig $(DIST_SGX_DIR)/
	cp -vR Ovsa_runtime/bin/* $(DIST_SGX_DIR)/bin/
	cp -vR Ovsa_runtime/ovsaruntime.manifest.sgx $(DIST_SGX_DIR)/
	cp -vR Ovsa_runtime/ovsaruntime.sig $(DIST_SGX_DIR)/
	cp -vR Ovsa_runtime/lib/* $(DIST_SGX_DIR)/lib
	cp -vR Example/client/* $(DIST_SGX_DIR)/example_client/
	cp -vR Example/runtime/* $(DIST_SGX_DIR)/example_runtime/
	cp -vR Scripts/install/setupvars_sgx.sh $(DIST_SGX_DIR)/scripts/setupvars.sh
	cp -vR Scripts/install/install_sgx.sh $(DIST_SGX_DIR)/install.sh
	cd $(DIST_DIR) && tar cvzf $(SGX_DIR).tar.gz $(SGX_DIR)
	cd $(DIST_DIR) && rm -rf $(SGX_DIR)
endif

