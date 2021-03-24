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

PLATFORM ?= x86_64

VERSION = 1.0
MAJOR = 1
MINOR = 0

TOPDIR := $(PWD)
export TOPDIR

ifeq ($(DEBUG),2)
CFLAGS += -O0 -ggdb3
else
CFLAGS += -O2
endif


DEV_DIR := ovsa-developer
MODEL_HOSTING_DIR := ovsa-model-hosting
HOST_DIR := ovsa-kvm-host
DIST_DIR := release_files
DIST_DEV_DIR := $(DIST_DIR)/$(DEV_DIR)/
DIST_MODEL_HOSTING_DIR := $(DIST_DIR)/$(MODEL_HOSTING_DIR)/
DIST_HOST_DIR := $(DIST_DIR)/$(HOST_DIR)/

SRC_BUILD_DIR  := $(PWD)
MV             := mv
DEBUG ?=
export DEBUG=1

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
package:
	docker build -f Dockerfile-build-ovsa . \
                --build-arg http_proxy="http://proxy-chain.intel.com:911"  \
                --build-arg https_proxy="http://proxy-chain.intel.com:911" \
                --build-arg no_proxy="localhost" \
                -t ovsa/modelserver-build-tpm:latest

	rm -vrf $(DIST_DIR)/ && mkdir -vp $(DIST_DIR)/ && cd $(DIST_DIR)/ && \
                docker run ovsa/modelserver-build-tpm:latest bash -c \
                        "tar -c -C / ovsa-runtime.tar* ; sleep 2" | tar -x

	cd $(DIST_DIR) && tar -xzvf ovsa-runtime.tar.gz && rm ovsa-runtime.tar.gz

#docker rm -v $(docker ps -a -q -f status=exited -f ancestor=ovsa/modelserver-build-tpm:latest )
	docker build -f Dockerfile-pkg-ovsa-nginx . \
                --build-arg http_proxy="http://proxy-chain.intel.com:911" \
                --build-arg https_proxy="http://proxy-chain.intel.com:911" \
                --build-arg no_proxy="localhost" \
                -t ovsa/runtime-tpm-nginx:latest

	docker save -o $(DIST_DIR)/ovsa-runtime-tpm-nginx.tar.gz \
                ovsa/runtime-tpm-nginx:latest

	cd $(DIST_DIR) && rm -rf ovsa-runtime

	mkdir -vp $(DIST_MODEL_HOSTING_DIR)
	cd $(DIST_MODEL_HOSTING_DIR) && mkdir -vp bin && mkdir -vp scripts && mkdir -vp example_client && mkdir -vp example_runtime
	mv $(DIST_DIR)/ovsa-runtime-tpm-nginx.tar.gz $(DIST_MODEL_HOSTING_DIR)
	cp -vR Ovsa_tool/bin/* $(DIST_MODEL_HOSTING_DIR)/bin
	cp -vR Example/client/* $(DIST_MODEL_HOSTING_DIR)/example_client/
	cp -vR Example/runtime/* $(DIST_MODEL_HOSTING_DIR)/example_runtime/
	cp -vR Scripts/guest/OVSA_create_ek_ak_keys.sh $(DIST_MODEL_HOSTING_DIR)/scripts/
	cp -vR Scripts/guest/OVSA_Seal_Key_TPM_Policy_Authorize.sh $(DIST_MODEL_HOSTING_DIR)/scripts/
	cp -vR Scripts/install/setupvars.sh  $(DIST_MODEL_HOSTING_DIR)/scripts/
	cp -vR Scripts/install/install_model_hosting.sh $(DIST_MODEL_HOSTING_DIR)/install.sh
	cd $(DIST_DIR) && tar cvzf $(MODEL_HOSTING_DIR).tar.gz $(MODEL_HOSTING_DIR)
	cd $(DIST_DIR) && rm -rf $(MODEL_HOSTING_DIR)

	mkdir -vp $(DIST_DEV_DIR)
	cd $(DIST_DEV_DIR) && mkdir -vp bin && mkdir -vp DB && mkdir -vp lib && mkdir -vp scripts
	cp -vR License_service/bin/* $(DIST_DEV_DIR)/bin
	cp -vR Ovsa_tool/bin/* $(DIST_DEV_DIR)/bin
	cp -vR Ovsa_runtime/bin/* $(DIST_DEV_DIR)/bin/
	cp -vR Ovsa_runtime/lib/* $(DIST_DEV_DIR)/lib
	cp -vR License_service/lib/* $(DIST_DEV_DIR)/lib
	cp -vR DB/* $(DIST_DEV_DIR)/DB
	cp -vR Scripts/guest/generate_server_license_cert.sh $(DIST_DEV_DIR)/scripts/
	cp -vR Scripts/guest/OVSA_create_ek_ak_keys.sh $(DIST_DEV_DIR)/scripts/
	cp -vR Scripts/guest/OVSA_Seal_Key_TPM_Policy_Authorize.sh $(DIST_DEV_DIR)/scripts/
	cp -vR Scripts/install/setupvars.sh $(DIST_DEV_DIR)/scripts/
	cp -vR Scripts/install/install_developer.sh $(DIST_DEV_DIR)/install.sh
	cd $(DIST_DIR) && tar cvzf $(DEV_DIR).tar.gz $(DEV_DIR)
	cd $(DIST_DIR) && rm -rf $(DEV_DIR)

	mkdir -vp $(DIST_HOST_DIR)
	cd $(DIST_HOST_DIR) && mkdir -vp scripts
	cp -vR Scripts/host/OVSA_provision_ekcert_swtpm.sh $(DIST_HOST_DIR)/scripts/
	cp -vR Scripts/host/OVSA_write_hwquote_swtpm_nvram.py  $(DIST_HOST_DIR)/scripts/
	cp -vR Scripts/install/install_host.sh $(DIST_HOST_DIR)/install.sh
	cd $(DIST_DIR) && tar cvzf $(HOST_DIR).tar.gz $(HOST_DIR)
	cd $(DIST_DIR) && rm -rf $(HOST_DIR)

	echo "Done"
