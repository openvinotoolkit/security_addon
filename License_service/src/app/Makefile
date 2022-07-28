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

SRC_BUILD_DIR  := $(TOPDIR)/License_service
DEPSDIR := $(SRC_BUILD_DIR)/../deps

ifeq ($(DEBUG),2)
CFLAGS += -O0 -ggdb3
else
CFLAGS += -O2
endif

ifeq ($(ENABLE_SGX_GRAMINE),1)
CFLAGS += -DENABLE_SGX_GRAMINE
endif

DEBUG ?=
export DEBUG=1

.PHONY: all
all: license_server

INC_LIBS := $(SRC_BUILD_DIR)/lib

CFLAGS += -DDEBUG=$(DEBUG) -DENABLE_SELF_SIGNED_CERT #-DENABLE_OCSP_CHECK

INC_DIR := -I$(DEPSDIR)/mbedtls/install/include \
           -I$(DEPSDIR)/mbedtls/crypto/include \
	   -I$(SRC_BUILD_DIR)/include \
	   -I$(SRC_BUILD_DIR)/src/app \
	   -I$(DEPSDIR)/openssl/include \
	   -I$(DEPSDIR)/sqlite \
	   -I$(DEPSDIR)/cJSON \
	   -I$(DEPSDIR)/safestringlib/include

LFLAGS += -Wl,-rpath,$(INC_LIBS) -L$(INC_LIBS) -fpic -D_GNU_SOURCE

ifneq ($(ENABLE_SGX_GRAMINE),1)
LIBS = -Bstatic -lsqlite3 -lsafestring -lssl -lcrypto -lcurl -lcjson -lmbedx509 -lmbedtls -lmbedcrypto -Bdynamic -ldl -lm -lpthread
else
LIBS = -Bstatic -lsqlite3 -lsafestring -lssl -lcrypto -lcurl -lcjson -lmbedx509 -lmbedtls -lmbedcrypto -Bdynamic -lsgx_util -lra_tls_verify_dcap -ldl -lm -lpthread
endif

# Build Executable
#===================================
TARGET = license_server


C_SRC_FILES := \
	utils.c \
	json.c \
	crypto.c \
	certverify.c \
	license_service_server.c \
	db.c

OBJS := $(C_SRC_FILES:.c=.o)

%.o: %.c
	$(CC) $(CFLAGS) $(INC_DIR) $(LFLAGS) -c -o $@ $<

$(TARGET): $(OBJS)
ifneq ($(ENABLE_SGX_GRAMINE),1)
	$(CC) $^ $(LFLAGS)  $(LIBS) -o $@
else
	$(CC)  -o $@ $(OBJS) $(LFLAGS)  $(LIBS) -Wl,--no-as-needed -lsgx_urts  -lsgx_dcap_quoteverify
endif

.PHONY: clean
clean:
	$(RM) -f $(TARGET) *.o

.PHONY: format
format:
	clang-format-9 -i $(shell find . -path ./../deps/safestringlib -prune -o \
                                   \( -name '*.h' -o -name '*.c' \) -print)

.PHONY: distclean
distclean: clean
