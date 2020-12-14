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

SRC_BUILD_DIR  := $(TOPDIR)
ifeq ($(DEBUG),2)
CFLAGS += -O0 -ggdb3
else
CFLAGS += -O2
endif

DEBUG ?=
export DEBUG=1

.PHONY: all
all: ovsa_host_server

LIB_DIR := $(SRC_BUILD_DIR)/lib

CFLAGS += -DDEBUG=$(DEBUG) -fstack-protector-strong -D_GNU_SOURCE -fPIE -fPIC -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security

INC_DIR := \
	   -I$(SRC_BUILD_DIR)/include \
           -I$(SRC_BUILD_DIR)/src/lib/openssl/include \
	   -I$(SRC_BUILD_DIR)/src/lib/cJSON \
	   -I$(SRC_BUILD_DIR)/src/lib/safestringlib/include \
	   -I$(SRC_BUILD_DIR)/src/app 

LFLAGS += -Wl,-rpath,$(LIB_DIR)  -L$(LIB_DIR) -fpic -D_GNU_SOURCE
LIBS = -Bstatic -lcjson -lsafestring -lcrypto -Bdynamic -lpthread -ldl

# Build Executable
#===================================
TARGET = ovsa_host_server


C_SRC_FILES := \
	server.c \
	tpm.c \
	json.c \
	utils.c \

OBJS := $(C_SRC_FILES:.c=.o)

%.o: %.c
	$(CC) $(CFLAGS) $(INC_DIR) $(LFLAGS) -c -o $@ $<

$(TARGET): $(OBJS)
	$(CC) $^ $(LFLAGS)  $(LIBS) -o $@
.PHONY: clean
clean:
	$(RM) ovsa_host_server *.o

.PHONY: format
format:
	clang-format-9 -i $(shell find . -path ./src/lib/safestringlib -prune -o \
                                   \( -name '*.h' -o -name '*.c' \) -print)

.PHONY: distclean
distclean: clean
	$(RM) -r *.o ovsa_host_server

