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

ifndef TOPDIR
TOPDIR := $(PWD)/..
endif
export TOPDIR

SRC_BUILD_DIR  := $(TOPDIR)/License_service

MV             := mv
DEBUG ?=
export DEBUG=1

export MV

PHONY: all
all:  create_dirs ovsa_dependency_build ovsa_license_service_build

.PHONY: ovsa_dependency_build
ovsa_dependency_build: sqlite openssl_build tls_build
	echo $(SRC_BUILD_DIR)
ifeq ($(wildcard  $(SRC_BUILD_DIR)/src/lib/safestringlib),)
	$(RM) -R $(SRC_BUILD_DIR)/src/lib/safestringlib
	cd $(SRC_BUILD_DIR)/src/lib && git clone https://github.com/intel/safestringlib
	$(MAKE) -C $(SRC_BUILD_DIR)/src/lib/safestringlib
	$(MV) $(SRC_BUILD_DIR)/src/lib/safestringlib/libsafestring.a $(SRC_BUILD_DIR)/lib
	$(RM) -R $(SRC_BUILD_DIR)/src/lib/safestringlib/unittests
endif
ifeq ($(wildcard  $(SRC_BUILD_DIR)/src/lib/cJSON),)
	$(RM) -R $(SRC_BUILD_DIR)/src/lib/cJSON
	cd $(SRC_BUILD_DIR)/src/lib && git clone https://github.com/DaveGamble/cJSON
	cd $(SRC_BUILD_DIR)/src/lib/cJSON && git checkout --quiet v1.7.12
	$(MAKE) -C $(SRC_BUILD_DIR)/src/lib/cJSON
	$(MV) $(SRC_BUILD_DIR)/src/lib/cJSON/libcjson.a $(SRC_BUILD_DIR)/lib
endif

.PHONY: openssl_build
openssl_build: openssl/libcrypto.a

openssl/libcrypto.a:
ifeq ($(wildcard  $(SRC_BUILD_DIR)/src/lib/openssl),)
	cd $(SRC_BUILD_DIR)/src/lib && git clone https://github.com/openssl/openssl.git
	cd $(SRC_BUILD_DIR)/src/lib/openssl && git checkout --quiet OpenSSL_1_1_1k
	cd $(SRC_BUILD_DIR)/src/lib/openssl && ./config --prefix=$(shell readlink -f crypto/) shared -fPIC
	cd $(SRC_BUILD_DIR)/src/lib/openssl && $(MAKE) && $(MAKE) -j1 install
	cd $(SRC_BUILD_DIR)/src/lib/openssl && mv libcrypto.a ../../../lib
	cd $(SRC_BUILD_DIR)/src/lib/openssl && mv libssl.a ../../../lib
endif

.PHONY: tls_build
tls_build: mbedtls/CMakeLists.txt

ovsa_license_service_build:
	$(MAKE) -C $(SRC_BUILD_DIR)/src/app
	$(MV) src/app/license_server $(SRC_BUILD_DIR)/bin
	
	CC=$(TARGET_CC)

create_dirs:
	mkdir -p  $(SRC_BUILD_DIR)/lib  $(SRC_BUILD_DIR)/bin  $(SRC_BUILD_DIR)/src/lib
	
############################# SQLITE DEPENDENCY ##############################

SQLITE_VERSION ?= 3350500
SQLITE_SRC ?= sqlite-autoconf-$(SQLITE_VERSION).tar.gz
SQLITE_URI ?= https://www.sqlite.org/2021/
SQLITE_CHECKSUM ?= f52b72a5c319c3e516ed7a92e123139a6e87af08a2dc43d7757724f6132e6db0

$(SQLITE_SRC):
ifeq ($(wildcard  $(SRC_BUILD_DIR)/src/lib/sqlite),)
	$(SRC_BUILD_DIR)/download.sh --output $@ --url $(SQLITE_URI)/$(SQLITE_SRC) \
            --sha256 $(SQLITE_CHECKSUM)
endif

sqlite: $(SQLITE_SRC)
ifeq ($(wildcard  $(SRC_BUILD_DIR)/src/lib/sqlite),)
	tar -mxzf $(SQLITE_SRC)
	$(RM) -rf $(SRC_BUILD_DIR)/src/lib/sqlite
	$(MV) sqlite-autoconf-$(SQLITE_VERSION) src/lib/sqlite
	$(RM) sqlite-autoconf-$(SQLITE_VERSION).tar.gz
	cd $(SRC_BUILD_DIR)/src/lib/sqlite && ./configure
	cd $(SRC_BUILD_DIR)/src/lib/sqlite && make
	$(MV) $(SRC_BUILD_DIR)/src/lib/sqlite/.libs/libsqlite3.a $(SRC_BUILD_DIR)/lib
	$(MV) $(SRC_BUILD_DIR)/src/lib/sqlite/sqlite3.h $(SRC_BUILD_DIR)/include
endif



############################# MBEDTLS DEPENDENCY ##############################
MBEDTLS_VERSION ?= 2.26.0
MBEDTLS_SRC ?= mbedtls-$(MBEDTLS_VERSION).tar.gz
MBEDTLS_URI ?= https://github.com/ARMmbed/mbedtls/archive/
MBEDTLS_CHECKSUM ?= 35d8d87509cd0d002bddbd5508b9d2b931c5e83747d087234cc7ad551d53fe05

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
ifeq ($(wildcard  $(SRC_BUILD_DIR)/src/lib/mbedtls),)
	$(SRC_BUILD_DIR)/download.sh --output $@ --url $(MBEDTLS_URI)/$(MBEDTLS_SRC) \
		--sha256 $(MBEDTLS_CHECKSUM)
endif

$(MBEDCRYPTO_SRC):
ifeq ($(wildcard  $(SRC_BUILD_DIR)/src/lib/mbedtls),)
	$(SRC_BUILD_DIR)/download.sh --output $@ --url $(MBEDCRYPTO_URI)/$(MBEDCRYPTO_SRC) \
		--sha256 $(MBEDCRYPTO_CHECKSUM)
endif

mbedtls/CMakeLists.txt: $(MBEDTLS_SRC) $(MBEDCRYPTO_SRC)
ifeq ($(wildcard  $(SRC_BUILD_DIR)/src/lib/mbedtls),)
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
	$(RM) -r $(SRC_BUILD_DIR)/src/lib/mbedtls
	mv mbedtls $(SRC_BUILD_DIR)/src/lib/mbedtls
	$(RM) $(MBEDTLS_SRC) $(MBEDCRYPTO_SRC)
	cp $(SRC_BUILD_DIR)/src/lib/mbedtls/install/lib/libmbedcrypto.so.* lib
	cp $(SRC_BUILD_DIR)/src/lib/mbedtls/install/lib/libmbedtls.so.* lib
	cp $(SRC_BUILD_DIR)/src/lib/mbedtls/install/lib/libmbedx509.so.* lib
	cd lib && ln -s libmbedcrypto.so.* libmbedcrypto.so && ln -s libmbedtls.so.* libmbedtls.so && ln -s libmbedx509.so.* libmbedx509.so
	cd ../
    
endif


 
.PHONY : clean
clean:
	$(MAKE) -C $(SRC_BUILD_DIR)/src/app clean
	rm -f $(SRC_BUILD_DIR)/bin/license_server

.PHONY: format
format:
	clang-format-9 -i $(shell find . -path ./src/lib/safestringlib -prune -o \
                                     -path ./src/lib/cJSON -prune -o \
				     -path ./src/lib/sqlite -prune -o \
                                     -path ./src/lib/safestringlib -prune -o \
                                     -path ./src/lib/mbedtls -prune -o \
				     -path ./src/lib/openssl -prune -o \
				     -path ./crypto -prune -o \
                                   \( -name '*.h' -o -name '*.c' \) -print)

.PHONY: distclean
distclean: clean
	$(RM) $(SRC_BUILD_DIR)/include/sqlite3.h
	$(RM) -r $(SRC_BUILD_DIR)/src/lib
	$(RM) -r $(SRC_BUILD_DIR)/crypto
	$(RM) -r $(SRC_BUILD_DIR)/lib
	$(RM) -r $(SRC_BUILD_DIR)/bin
