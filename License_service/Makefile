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
TOPDIR := $(shell pwd)/..
endif
export TOPDIR

SRC_BUILD_DIR  := $(TOPDIR)/License_service
DEPSDIR := $(SRC_BUILD_DIR)/../deps

ifeq ($(SGX),1)
export ENABLE_SGX_GRAMINE=1
endif

MV             := mv
DEBUG ?=
export DEBUG=1

export MV

PHONY: all
ifeq ($(SGX),1)
ifndef GRAMINE_DIR
$(error GRAMINE_DIR not set. Please set before compilation)
endif
all:  create_dirs install_ratls_lib ovsa_dependency_build ovsa_license_service_build
else
all:  create_dirs ovsa_dependency_build ovsa_license_service_build
endif

ifeq ($(SGX),1)
.PHONY: install_ratls_lib
install_ratls_lib: 
	cp $(GRAMINE_DIR)/build/Pal/src/host/Linux-SGX/tools/ra-tls/libra_tls_verify_dcap.so $(SRC_BUILD_DIR)/lib
	cp $(GRAMINE_DIR)/build/Pal/src/host/Linux-SGX/tools/common/libsgx_util.so $(SRC_BUILD_DIR)/lib
endif

.PHONY: ovsa_dependency_build
ovsa_dependency_build: sqlite openssl_build tls_build
ifeq ($(wildcard  $(DEPSDIR)/safestringlib),)
	cd $(DEPSDIR) && git clone https://github.com/intel/safestringlib
	$(MAKE) -C $(DEPSDIR)/safestringlib directories libsafestring.a
endif
	cp $(DEPSDIR)/safestringlib/libsafestring.a $(SRC_BUILD_DIR)/lib

ifeq ($(wildcard  $(DEPSDIR)/cJSON),)
	cd $(DEPSDIR) && git clone https://github.com/DaveGamble/cJSON
	cd $(DEPSDIR)/cJSON && git checkout --quiet v1.7.12
	$(MAKE) -C $(DEPSDIR)/cJSON
endif
	cp $(DEPSDIR)/cJSON/libcjson.a $(SRC_BUILD_DIR)/lib

.PHONY: openssl_build
openssl_build: openssl/libcrypto.a

openssl/libcrypto.a:
ifeq ($(wildcard  $(DEPSDIR)/openssl),)
	cd $(DEPSDIR) && git clone https://github.com/openssl/openssl.git
	cd $(DEPSDIR)/openssl && git checkout --quiet OpenSSL_1_1_1q
	cd $(DEPSDIR)/openssl && ./config --prefix=$(shell readlink -f $(DEPSDIR)/crypto/) no-tests shared -fPIC
	cd $(DEPSDIR)/openssl && $(MAKE) -j1 install_sw
endif
	cp $(DEPSDIR)/openssl/libcrypto.a $(SRC_BUILD_DIR)/lib
	cp $(DEPSDIR)/openssl/libssl.a $(SRC_BUILD_DIR)/lib

.PHONY: tls_build
tls_build: mbedtls/CMakeLists.txt

ovsa_license_service_build:
	$(MAKE) -C $(SRC_BUILD_DIR)/src/app
	$(MV) src/app/license_server $(SRC_BUILD_DIR)/bin
	
	CC=$(TARGET_CC)

create_dirs:
	mkdir -p $(SRC_BUILD_DIR)/lib $(SRC_BUILD_DIR)/bin $(SRC_BUILD_DIR)/src/lib $(DEPSDIR)
	
############################# SQLITE DEPENDENCY ##############################

SQLITE_VERSION ?= 3350500
SQLITE_SRC ?= sqlite-autoconf-$(SQLITE_VERSION).tar.gz
SQLITE_URI ?= https://www.sqlite.org/2021/
SQLITE_CHECKSUM ?= f52b72a5c319c3e516ed7a92e123139a6e87af08a2dc43d7757724f6132e6db0

$(SQLITE_SRC):
	echo $(SRC_BUILD_DIR)
	echo $(DEPSDIR)
ifeq ($(wildcard  $(DEPSDIR)/sqlite),)
	cd $(DEPSDIR) && $(SRC_BUILD_DIR)/download.sh --output $@ --url $(SQLITE_URI)/$(SQLITE_SRC) \
            --sha256 $(SQLITE_CHECKSUM)
endif

sqlite: $(SQLITE_SRC)
ifeq ($(wildcard  $(DEPSDIR)/sqlite),)
	cd $(DEPSDIR) && tar -mxzf $(SQLITE_SRC)
	$(MV) $(DEPSDIR)/sqlite-autoconf-$(SQLITE_VERSION) $(DEPSDIR)/sqlite
	cd $(DEPSDIR)/sqlite && autoreconf -f -i
	cd $(DEPSDIR)/sqlite && ./configure
	cd $(DEPSDIR)/sqlite && make
endif
	cp $(DEPSDIR)/sqlite/.libs/libsqlite3.a $(SRC_BUILD_DIR)/lib

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
ifeq ($(wildcard  $(DEPSDIR)/mbedtls),)
	cd $(DEPSDIR) && $(SRC_BUILD_DIR)/download.sh --output $@ --url $(MBEDTLS_URI)/$(MBEDTLS_SRC) \
                --sha256 $(MBEDTLS_CHECKSUM)
endif

$(MBEDCRYPTO_SRC):
ifeq ($(wildcard  $(DEPSDIR)/mbedtls),)
	cd $(DEPSDIR) && $(SRC_BUILD_DIR)/download.sh --output $@ --url $(MBEDCRYPTO_URI)/$(MBEDCRYPTO_SRC) \
		--sha256 $(MBEDCRYPTO_CHECKSUM)
endif

mbedtls/CMakeLists.txt: $(MBEDTLS_SRC) $(MBEDCRYPTO_SRC)
ifeq ($(wildcard  $(DEPSDIR)/mbedtls),)
	cd $(DEPSDIR) && tar -mxzf $(MBEDTLS_SRC)
	cd $(DEPSDIR) && tar -mxzf $(MBEDCRYPTO_SRC)
	mv $(DEPSDIR)/mbedtls-mbedtls-$(MBEDTLS_VERSION) $(DEPSDIR)/mbedtls
	mv $(DEPSDIR)/mbed-crypto-mbedcrypto-$(MBEDCRYPTO_VERSION) $(DEPSDIR)/mbedtls
	mv $(DEPSDIR)/mbedtls/mbed-crypto-mbedcrypto-$(MBEDCRYPTO_VERSION) $(DEPSDIR)/mbedtls/crypto
	mkdir $(DEPSDIR)/mbedtls/install
	cd $(DEPSDIR)/mbedtls && ./scripts/config.pl set MBEDTLS_CMAC_C && make SHARED=1 DESTDIR=install install .
endif
	cp $(DEPSDIR)/mbedtls/install/lib/*.a $(SRC_BUILD_DIR)/lib



.PHONY : clean
clean:
	$(MAKE) -C $(SRC_BUILD_DIR)/src/app clean
	rm -f $(SRC_BUILD_DIR)/bin/license_server

.PHONY: format
format:
	clang-format-9 -i $(shell find . -path ./../deps/safestringlib -prune -o \
                                     -path ./../deps/cJSON -prune -o \
				     -path ./../deps/sqlite -prune -o \
                                     -path ./../deps/safestringlib -prune -o \
                                     -path ./../deps/mbedtls -prune -o \
				     -path ./../deps/openssl -prune -o \
				     -path ./crypto -prune -o \
                                   \( -name '*.h' -o -name '*.c' \) -print)

.PHONY: distclean
distclean: clean
	$(RM) -r $(DEPSDIR)
	$(RM) -r $(SRC_BUILD_DIR)/src/lib
	$(RM) -r $(SRC_BUILD_DIR)/lib
	$(RM) -r $(SRC_BUILD_DIR)/bin
