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

SRC_BUILD_DIR  := $(TOPDIR)/License_service
ifeq ($(DEBUG),2)
CFLAGS += -O0 -ggdb3
else
CFLAGS += -O2
endif

DEBUG ?=
export DEBUG=1

.PHONY: all
all: license_server

INC_LIBS := $(SRC_BUILD_DIR)/lib

CFLAGS += -DDEBUG=$(DEBUG) #-DPTT_EK_ONDIE_CA #-DENABLE_OCSP_CHECK

INC_DIR := -I$(SRC_BUILD_DIR)/src/lib/mbedtls/install/include \
           -I$(SRC_BUILD_DIR)/src/lib/mbedtls/crypto/include \
	   -I$(SRC_BUILD_DIR)/include \
	   -I$(SRC_BUILD_DIR)/src/app \
	   -I$(SRC_BUILD_DIR)/src/lib/openssl/include \
	   -I$(SRC_BUILD_DIR)/src/lib/sqlite \
	   -I$(SRC_BUILD_DIR)/src/lib/cJSON \
	   -I$(SRC_BUILD_DIR)/src/lib/safestringlib/include

LFLAGS += -Wl,-rpath,$(INC_LIBS)  -L$(INC_LIBS) -fpic -D_GNU_SOURCE
LIBS = -Bstatic -lssl -lcrypto -lsqlite3 -lsafestring -lcjson -Bdynamic -lcurl -lmbedtls -lmbedcrypto -lmbedx509 -ldl -lm -lpthread

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
	$(CC) $^ $(LFLAGS)  $(LIBS) -o $@

.PHONY: clean
clean:
	$(RM) -f $(TARGET) *.o

.PHONY: format
format:
	clang-format-9 -i $(shell find . -path ./src/lib/safestringlib -prune -o \
                                   \( -name '*.h' -o -name '*.c' \) -print)

.PHONY: distclean
distclean: clean
