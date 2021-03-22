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

SRC_BUILD_DIR  := $(OVSATOOL_DIR)

OVSALIB_EXT = .so.$(VERSION)
IDIR = $(SRC_BUILD_DIR)/src/lib/safestringlib/include -I$(SRC_BUILD_DIR)/include -I$(SRC_BUILD_DIR)/src/lib/openssl/include -I$(SRC_BUILD_DIR)/src/lib/curl/include
OVSA_LIB_OBJ = $(SRC_BUILD_DIR)/src/lib/libovsa

ifeq ($(DEBUG),2)
CFLAGS += -O0 -ggdb3
else
CFLAGS += -O2
endif

CC = gcc
CFLAGS = -I$(IDIR) -g -Wall -DENABLE_SELF_SIGNED_CERT -DENABLE_OCSP_CHECK -fstack-protector-strong -fPIE -fPIC -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security -D_GNU_SOURCE -DDEBUG=$(DEBUG)
CNF_CFLAGS := -pthread -m64 -Wa,--noexecstack
CNF_EX_LIBS := -ldl -lpthread
LIB_CFLAGS := -fPIC -Wno-attributes $(CNF_CFLAGS) $(CFLAGS)
LIB_EX_LIBS := $(CNF_EX_LIBS)
LIB_PATH := -Wl, -Bstatic -L$(SRC_BUILD_DIR)/lib/ -lcjson

LIBS = libovsa.a #libovsa$(OVSALIB_EXT) 

_CLIB = asymmetric.c symmetric.c cert_verify.c utils.c tpm.c

_CLIST = $(addprefix $(OVSA_LIB_OBJ)/,$(_CLIB))
OBJ = $(patsubst %.c,%.o,$(_CLIST))

$(OVSA_LIB_OBJ)/%.o: %.c 
	$(CC) $(LIB_CFLAGS) $(LIB_PATH) -c $< -o $@
	
libovsa.a: $(OBJ)
	@ar rcs $@ $^
	@echo "LINK =>  $@"	      
 

.PHONY: all
all: ${OVSA_LIB_OBJ} $(LIBS)


.PHONY: clean
clean: 
	rm -f $(OVSA_LIB_OBJ)/*.o $(LIBS)
	-@rm -f `find . -name '*.d' \! -name '.*' \! -type d -print`
	-@rm -f `find . -name '*.o' \! -name '.*' \! -type d -print`
	-@rm -f `find . -type l \! -name '.*' -print`
