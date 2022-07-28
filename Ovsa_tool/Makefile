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
TOPDIR := $(shell pwd)
OVSATOOL_DIR ?= $(TOPDIR)
else
OVSATOOL_DIR ?= $(TOPDIR)/Ovsa_tool
endif
export OVSATOOL_DIR
SGX ?= 0

DEBUG ?=
export DEBUG=1

ifeq ($(SGX),1)
export ENABLE_SGX_GRAMINE=1
# Relative path to Gramine root and key for enclave signing
SGX_SIGNER_KEY ?= $(GRAMINE_DIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem
ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)
endif

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

SRC_BUILD_DIR  := $(OVSATOOL_DIR)
DEPSDIR := $(SRC_BUILD_DIR)/../deps
MV             := mv

export MV

.PHONY: all
ifeq ($(SGX),1)
ifndef GRAMINE_DIR
$(error GRAMINE_DIR not set. Please set before compilation)
endif
endif

all: create_dirs ovsatool_build

ifeq ($(SGX),1)
all: ovsatool.manifest.sgx ovsatool.sig ovsatool.token
endif

create_dirs:
	mkdir -p  $(SRC_BUILD_DIR)/lib  $(SRC_BUILD_DIR)/bin $(DEPSDIR)

ovsatool_build:
ifeq ($(wildcard  $(DEPSDIR)/safestringlib),)
	cd $(DEPSDIR)/ && git clone https://github.com/intel/safestringlib
	$(MAKE) -C $(DEPSDIR)/safestringlib directories libsafestring.a
endif
	cp $(DEPSDIR)/safestringlib/libsafestring.a $(SRC_BUILD_DIR)/lib

ifeq ($(wildcard  $(DEPSDIR)/cJSON),)
	cd $(DEPSDIR) && git clone https://github.com/DaveGamble/cJSON
	cd $(DEPSDIR)/cJSON && git checkout --quiet v1.7.12
	$(MAKE) -C $(DEPSDIR)/cJSON
endif
	cp $(DEPSDIR)/cJSON/libcjson.a $(SRC_BUILD_DIR)/lib

ifeq ($(wildcard  $(DEPSDIR)/curl),)
	cd $(DEPSDIR) && git clone https://github.com/curl/curl.git
	cd $(DEPSDIR)/curl && autoreconf -fi && ./configure --without-zlib --without-ssl --without-libidn2
	$(MAKE) -C $(DEPSDIR)/curl
endif
	cp $(DEPSDIR)/curl/lib/.libs/libcurl.a $(SRC_BUILD_DIR)/lib

ifeq ($(wildcard  $(DEPSDIR)/openssl),)
	cd $(DEPSDIR) && git clone https://github.com/openssl/openssl.git
	cd $(DEPSDIR)/openssl && git checkout --quiet OpenSSL_1_1_1q
	cd $(DEPSDIR)/openssl && ./config --prefix=$(shell readlink -f $(DEPSDIR)/crypto/) no-tests shared -fPIC
	cd $(DEPSDIR)/openssl && $(MAKE) -j1 install_sw
endif
	cp $(DEPSDIR)/openssl/libcrypto.a $(SRC_BUILD_DIR)/lib
	cp $(DEPSDIR)/openssl/libssl.a $(SRC_BUILD_DIR)/lib

	$(MAKE) all -C $(SRC_BUILD_DIR)/src/lib/libovsa
	$(MV) src/lib/libovsa/libovsa.*  $(SRC_BUILD_DIR)/lib
	$(MAKE) -C $(SRC_BUILD_DIR)/src/app
	$(MV) src/app/ovsatool $(SRC_BUILD_DIR)/bin
	CC=$(TARGET_CC)

ifeq ($(SGX),1)
ovsatool.manifest: ovsatool.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_DEBUG) \
		-Dgramine_dir=$(GRAMINE_DIR) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< > $@

# Generating the SGX-specific manifest, the enclave signature,
# and the token for enclave initialization.
ovsatool.manifest.sgx: ovsatool.manifest
	gramine-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest $< \
		--output $@

ovsatool.sig: ovsatool.manifest.sgx

ovsatool.token: ovsatool.sig
	gramine-sgx-get-token \
			--output ovsatool.token --sig ovsatool.sig

endif

.PHONY: clean
clean:
	$(MAKE) -C $(SRC_BUILD_DIR)/src/app clean
	$(MAKE) -C $(SRC_BUILD_DIR)/src/lib/libovsa clean
	$(RM) $(SRC_BUILD_DIR)/bin/ovsatool
	$(RM) $(SRC_BUILD_DIR)/lib/libovsa.*

	$(RM) *.manifest *.manifest.sgx *.token *.sig
	
.PHONY: format
format:
	clang-format-9 -i $(shell find . -path ./../deps/safestringlib -prune -o \
					-path ./../deps/openssl -prune -o \
					-path ./../deps/curl -prune -o \
					-path ./../deps/cJSON -prune -o \
					-path ./crypto -prune -o \
                                   \( -name '*.h' -o -name '*.c' \) -print)

.PHONY: distclean
distclean: clean
	$(RM) -r $(SRC_BUILD_DIR)/lib
	$(RM) -r $(DEPSDIR)
	$(RM) -r $(SRC_BUILD_DIR)/bin
