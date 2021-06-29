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

SRC_BUILD_DIR  := $(OVSATOOL_DIR)
ifeq ($(DEBUG),2)
CFLAGS += -O0 -ggdb3
else
CFLAGS += -O2
endif

DEBUG ?=
export DEBUG=1

CFLAGS +=  -g -Wall -DENABLE_SELF_SIGNED_CERT -DENABLE_OCSP_CHECK -fno-exceptions -fPIC -DDEBUG=$(DEBUG) -fstack-protector-strong -fPIE -fPIC -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security -D_GNU_SOURCE
INC_DIR := -I$(SRC_BUILD_DIR)/include \
	   -I$(SRC_BUILD_DIR)/src/lib/libovsa \
	   -I$(SRC_BUILD_DIR)/src/lib/safestringlib/include

LFLAGS += -Wl,-rpath, -L$(SRC_BUILD_DIR)/lib

LIBS = -Bstatic -lovsa -lsafestring -lcurl -lssl -lcrypto -lcjson -Bdynamic -lpthread -ldl

# Build Executable
#===================================
TARGET = ovsatool


C_SRC_FILES := \
	ovsatool.c \
	keygen.c \
	licgen.c \
	controlaccess.c \
	sale.c \
	updatecustlicense.c \
	json.c \
	utils.c

OBJS := $(C_SRC_FILES:.c=.o)

.PHONY : all
all: $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) $(INC_DIR) $(LFLAGS) -c -o $@ $<


$(TARGET): $(OBJS)
	$(CC)  -o $@ $(OBJS) $(LFLAGS)  $(LIBS)

.PHONY: clean
clean:
	rm -f $(TARGET) *.o

