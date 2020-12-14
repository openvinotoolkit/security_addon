#
# Copyright (c) 2020 Intel Corporation
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
else
TOPDIR := $(PWD)/Ovsa_kvm_host
endif
export TOPDIR

#.PHONY : all clean install

SRC_BUILD_DIR  := $(TOPDIR)

MV             := mv
DEBUG ?=
export DEBUG=1

export MV


PHONY: all
all: create_dirs openssl_build safestringlib cJSON ovsa_tpm_host_server_build

create_dirs:
	mkdir -p  $(SRC_BUILD_DIR)/lib  $(SRC_BUILD_DIR)/bin $(SRC_BUILD_DIR)/src/lib

safestringlib:
ifeq ($(wildcard  $(SRC_BUILD_DIR)/src/lib/safestringlib),)
	$(RM) -R $(SRC_BUILD_DIR)/src/lib/safestringlib
	cd $(SRC_BUILD_DIR)/src/lib && git clone https://github.com/intel/safestringlib
	$(MAKE) -C $(SRC_BUILD_DIR)/src/lib/safestringlib
	$(MV) $(SRC_BUILD_DIR)/src/lib/safestringlib/libsafestring.a $(SRC_BUILD_DIR)/lib
	$(RM) -R $(SRC_BUILD_DIR)/src/lib/safestringlib/unittests
endif
cJSON:
ifeq ($(wildcard  $(SRC_BUILD_DIR)/src/lib/cJSON),)
	$(RM) -R $(SRC_BUILD_DIR)/src/lib/cJSON
	cd $(SRC_BUILD_DIR)/src/lib && git clone https://github.com/DaveGamble/cJSON
	cd $(SRC_BUILD_DIR)/src/lib/cJSON && git checkout --quiet v1.7.12
	$(MAKE) -C $(SRC_BUILD_DIR)/src/lib/cJSON
	$(MV) $(SRC_BUILD_DIR)/src/lib/cJSON/libcjson.a $(SRC_BUILD_DIR)/lib
endif

openssl_build: openssl/libcrypto.a
openssl/libcrypto.a:
ifeq ($(wildcard  $(SRC_BUILD_DIR)/src/lib/openssl),)
	cd $(SRC_BUILD_DIR)/src/lib && git clone https://github.com/openssl/openssl.git
	cd $(SRC_BUILD_DIR)/src/lib/openssl && git checkout --quiet OpenSSL_1_1_1h
	cd $(SRC_BUILD_DIR)/src/lib/openssl && ./config --prefix=$(shell readlink -f crypto/) shared -fPIC
	cd $(SRC_BUILD_DIR)/src/lib/openssl && $(MAKE) && $(MAKE) -j1 install
	cd $(SRC_BUILD_DIR)/src/lib/openssl && mv libcrypto.a ../../../lib
	#cd $(SRC_BUILD_DIR)/src/lib/openssl && mv libssl.a ../../../lib
endif
ovsa_tpm_host_server_build:
	$(MAKE) -C $(SRC_BUILD_DIR)/src/app
	$(MV) src/app/ovsa_host_server $(SRC_BUILD_DIR)/bin
	
	CC=$(TARGET_CC)
	
.PHONY : clean
clean:
	$(MAKE) -C $(SRC_BUILD_DIR)/src/app clean
	rm -f $(SRC_BUILD_DIR)/bin/ovsa_host_server

.PHONY: format
format:
	clang-format-9 -i $(shell find . -path ./src/lib/safestringlib -prune -o \
                                     -path ./src/lib/cJSON -prune -o \
                                     -path ./src/lib/openssl -prune -o \
                                     -path ./crypto -prune -o \
                                   \( -name '*.h' -o -name '*.c' \) -print)

.PHONY: distclean
distclean: clean
	$(RM) -r $(SRC_BUILD_DIR)/src/lib
	$(RM) -r $(SRC_BUILD_DIR)/crypto
	$(RM) -r $(SRC_BUILD_DIR)/lib 
	$(RM) -r $(SRC_BUILD_DIR)/bin

    


