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
TOPDIR := $(PWD)
OVSATOOL_DIR ?= $(TOPDIR)
else
OVSATOOL_DIR ?= $(TOPDIR)/Ovsa_tool
endif
export OVSATOOL_DIR

ifeq ($(DEBUG),2)
CFLAGS += -O0 -ggdb3
else
CFLAGS += -O2
endif

#SRC_BUILD_DIR  := $(TOPDIR)
SRC_BUILD_DIR  := $(OVSATOOL_DIR)
MV             := mv
DEBUG ?=
export DEBUG=1

export MV

.PHONY: all

all: create_dirs ovsatool_build

create_dirs:
	mkdir -p  $(SRC_BUILD_DIR)/lib  $(SRC_BUILD_DIR)/bin

ovsatool_build:
	echo $(SRC_BUILD_DIR)
ifeq ($(wildcard  $(SRC_BUILD_DIR)/src/lib/safestringlib),)
	cd $(SRC_BUILD_DIR)/src/lib && git clone https://github.com/intel/safestringlib
	$(MAKE) -C $(SRC_BUILD_DIR)/src/lib/safestringlib
	$(MV) $(SRC_BUILD_DIR)/src/lib/safestringlib/libsafestring.a $(SRC_BUILD_DIR)/lib
	$(RM) -R $(SRC_BUILD_DIR)/src/lib/safestringlib/unittests
endif

ifeq ($(wildcard  $(SRC_BUILD_DIR)/src/lib/cJSON),)
	cd $(SRC_BUILD_DIR)/src/lib && git clone https://github.com/DaveGamble/cJSON
	cd $(SRC_BUILD_DIR)/src/lib/cJSON && git checkout --quiet v1.7.12
	$(MAKE) -C $(SRC_BUILD_DIR)/src/lib/cJSON
	$(MV) $(SRC_BUILD_DIR)/src/lib/cJSON/libcjson.a $(SRC_BUILD_DIR)/lib
	$(MV) $(SRC_BUILD_DIR)/src/lib/cJSON/cJSON.h $(SRC_BUILD_DIR)/include

endif
ifeq ($(wildcard  $(SRC_BUILD_DIR)/src/lib/curl),)
	$(RM) -R $(SRC_BUILD_DIR)/src/lib/curl
	cd $(SRC_BUILD_DIR)/src/lib && git clone https://github.com/curl/curl.git
	cd $(SRC_BUILD_DIR)/src/lib/curl && autoreconf -fi && ./configure --without-zlib --without-ssl --without-libidn2
	$(MAKE) -C $(SRC_BUILD_DIR)/src/lib/curl
	$(MV) $(SRC_BUILD_DIR)/src/lib/curl/lib/.libs/libcurl.a $(SRC_BUILD_DIR)/lib
endif
ifeq ($(wildcard  $(SRC_BUILD_DIR)/src/lib/openssl),)
	cd $(SRC_BUILD_DIR)/src/lib && git clone https://github.com/openssl/openssl.git
	cd $(SRC_BUILD_DIR)/src/lib/openssl && git checkout --quiet OpenSSL_1_1_1k
	cd $(SRC_BUILD_DIR)/src/lib/openssl && ./config --prefix=$(shell readlink -f crypto/) shared -fPIC
	cd $(SRC_BUILD_DIR)/src/lib/openssl && $(MAKE) && $(MAKE) -j1 install_sw
	cd $(SRC_BUILD_DIR)/src/lib/openssl && mv libcrypto.a ../../../lib
	cd $(SRC_BUILD_DIR)/src/lib/openssl && mv libssl.a ../../../lib
endif
	$(MAKE) all -C $(SRC_BUILD_DIR)/src/lib/libovsa
	$(MV) src/lib/libovsa/libovsa.*  $(SRC_BUILD_DIR)/lib
	$(MAKE) -C $(SRC_BUILD_DIR)/src/app
	$(MV) src/app/ovsatool $(SRC_BUILD_DIR)/bin
	CC=$(TARGET_CC)

.PHONY: clean
clean:
	$(MAKE) -C $(SRC_BUILD_DIR)/src/app clean
	$(MAKE) -C $(SRC_BUILD_DIR)/src/lib/libovsa clean
	$(RM) $(SRC_BUILD_DIR)/bin/ovsatool
	$(RM) $(SRC_BUILD_DIR)/lib/libovsa.*
	
.PHONY: format
format:
	clang-format-9 -i $(shell find . -path ./src/lib/safestringlib -prune -o \
					-path ./src/lib/openssl -prune -o \
					-path ./src/lib/curl -prune -o \
					-path ./src/lib/cJSON -prune -o \
					-path ./crypto -prune -o \
                                   \( -name '*.h' -o -name '*.c' \) -print)

.PHONY: distclean
distclean: clean
	$(RM) -r $(SRC_BUILD_DIR)/lib
	$(RM) -r $(SRC_BUILD_DIR)/bin
	$(RM) $(SRC_BUILD_DIR)/include/cJSON.h
	$(RM) -r $(SRC_BUILD_DIR)/src/lib/safestringlib
	$(RM) -r $(SRC_BUILD_DIR)/src/lib/cJSON
	$(RM) -R $(SRC_BUILD_DIR)/src/lib/curl
	$(RM) -r $(SRC_BUILD_DIR)/src/lib/openssl
	 $(RM) -r $(SRC_BUILD_DIR)/crypto
