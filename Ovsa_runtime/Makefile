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

ifndef TOPDIR
TOPDIR := $(PWD)
OVSARUNTIME_DIR ?= $(TOPDIR)
else
OVSARUNTIME_DIR ?= $(TOPDIR)/Ovsa_runtime
endif
export OVSARUNTIME_DIR

ifeq ($(SGX),1)
export ENABLE_SGX_GRAMINE=1
# Relative path to Gramine root and key for enclave signing
SGX_SIGNER_KEY ?= $(GRAMINE_DIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem
ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)
endif

SRC_BUILD_DIR  := $(OVSARUNTIME_DIR)
MV             := mv

export MV

ifeq ($(DEBUG),2)
	ifeq ($(SGX),1)
	GRAMINE_DEBUG = all
	endif
	CFLAGS += -O0 -ggdb3
else ifeq ($(DEBUG),1)
	ifeq ($(SGX),1)
	GRAMINE_DEBUG = error
	endif
	CFLAGS += -O2
else
	ifeq ($(SGX),1)
	GRAMINE_DEBUG = error
	endif
	CFLAGS += -O2
endif

.PHONY : all
ifeq ($(SGX),1)
ifndef GRAMINE_DIR
$(error GRAMINE_DIR not set. Please set before compilation)
endif
endif
all: create_dirs build_mbedtls rapidjson ovsaruntime_build

ifeq ($(SGX),1)
all: ovsaruntime.manifest.sgx ovsaruntime.sig ovsaruntime.token
endif
############################# MBEDTLS DEPENDENCY ##############################

MBEDTLS_VERSION ?= 3.1.0
MBEDTLS_SRC ?= mbedtls-$(MBEDTLS_VERSION).tar.gz
MBEDTLS_URI ?= https://github.com/ARMmbed/mbedtls/archive/
MBEDTLS_CHECKSUM ?= 64d01a3b22b91cf3a25630257f268f11bc7bfa37981ae6d397802dd4ccec4690

# mbedTLS uses a submodule mbedcrypto, need to download it and move under mbedtls/crypto
MBEDCRYPTO_VERSION ?= 3.1.0
MBEDCRYPTO_SRC ?= mbedcrypto-$(MBEDCRYPTO_VERSION).tar.gz
MBEDCRYPTO_URI ?= https://github.com/ARMmbed/mbed-crypto/archive/
MBEDCRYPTO_CHECKSUM ?= 7e171df03560031bc712489930831e70ae4b70ff521a609c6361f36bd5f8b76b

ifeq ($(DEBUG),1)
MBED_BUILD_TYPE=Debug
else
MBED_BUILD_TYPE=Release
endif

$(MBEDTLS_SRC):
ifeq ($(wildcard  $(SRC_BUILD_DIR)/mbedtls),)
	$(SRC_BUILD_DIR)/download.sh --output $@ --url $(MBEDTLS_URI)/$(MBEDTLS_SRC) \
                --sha256 $(MBEDTLS_CHECKSUM)
endif

$(MBEDCRYPTO_SRC):
ifeq ($(wildcard  $(SRC_BUILD_DIR)/mbedtls),)
	$(SRC_BUILD_DIR)/download.sh --output $@ --url $(MBEDCRYPTO_URI)/$(MBEDCRYPTO_SRC) \
                --sha256 $(MBEDCRYPTO_CHECKSUM)
endif

build_mbedtls: $(MBEDTLS_SRC) $(MBEDCRYPTO_SRC)
ifeq ($(wildcard  $(SRC_BUILD_DIR)/mbedtls),)
	tar -mxzf $(MBEDTLS_SRC)
	tar -mxzf $(MBEDCRYPTO_SRC)
	$(RM) -r mbedtls/mbedtls-mbedtls-$(MBEDTLS_VERSION)
	mv mbedtls-mbedtls-$(MBEDTLS_VERSION) mbedtls
	$(RM) -r mbedtls/crypto
	mv mbed-crypto-mbedcrypto-$(MBEDCRYPTO_VERSION) mbedtls
	mv mbedtls/mbed-crypto-mbedcrypto-$(MBEDCRYPTO_VERSION) mbedtls/crypto
	$(RM) -r mbedtls/install
	mkdir mbedtls/install
	cd mbedtls && ./scripts/config.pl set MBEDTLS_CMAC_C && make SHARED=1 DESTDIR=install install .
	cp mbedtls/install/lib/*.a lib
	$(RM) *.tar.gz
endif

############################# RAPIDJSON DEPENDENCY ##############################

RAPID_JSON_URI ?= https://github.com/Tencent/rapidjson.git
rapidjson:
ifeq ($(wildcard  $(SRC_BUILD_DIR)/include/rapidjson),)
	cd $(SRC_BUILD_DIR) && git clone $(RAPID_JSON_URI)
	cd $(SRC_BUILD_DIR) && cp -r rapidjson/include/rapidjson $(SRC_BUILD_DIR)/include
	cd $(SRC_BUILD_DIR) && rm -rf rapidjson
endif
####################

create_dirs:
	mkdir -p  $(SRC_BUILD_DIR)/lib  $(SRC_BUILD_DIR)/bin

ovsaruntime_build:
	echo $(SRC_BUILD_DIR)
	$(MAKE) -C $(SRC_BUILD_DIR)/src
	$(MV) src/ovsaruntime $(SRC_BUILD_DIR)/bin


	CC=$(TARGET_CC)

ifeq ($(SGX),1)
ovsaruntime.manifest: ovsaruntime.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_DEBUG) \
		-Dgramine_dir=$(GRAMINE_DIR) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< > $@

# Generating the SGX-specific manifest, the enclave signature,
# and the token for enclave initialization.
ovsaruntime.manifest.sgx: ovsaruntime.manifest
	gramine-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest $< \
		--output $@

ovsaruntime.sig: ovsaruntime.manifest.sgx

ovsaruntime.token: ovsaruntime.sig
	gramine-sgx-get-token \
		--output ovsaruntime.token --sig ovsaruntime.sig
endif

################################## CLEANUP ####################################

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest
	$(MAKE) -C $(SRC_BUILD_DIR)/src/ clean
	$(RM) $(SRC_BUILD_DIR)/bin/ovsaruntime
	
.PHONY: format
format:
	clang-format-9 -i $(shell find . -path ./include/rapidjson -prune -o \
                                     -path ./mbedtls -prune -o \
                                   \( -name '*.h' -o -name '*.c' \) -print)

.PHONY: distclean
distclean: clean
	$(RM) -rf mbedtls $(SRC_BUILD_DIR)/include/rapidjson $(SRC_BUILD_DIR)/lib/*.so.* $(SRC_BUILD_DIR)/bin
