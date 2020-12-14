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

SRC_BUILD_DIR  := $(OVSARUNTIME_DIR)
DEBUG ?=
export DEBUG=1

CP = cp

CFLAGS +=  -g -Wall -DENABLE_SELF_SIGNED_CERT -D_GNU_SOURCE -DENABLE_OCSP_CHECK -fno-exceptions -fPIC -DDEBUG=$(DEBUG) -D OVSA_RUNTIME -DCREATE_PROT_MODEL -fstack-protector-strong -fPIE -fPIC -O2 -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security
OVSATOOL_INC_DIR := -I$(SRC_BUILD_DIR)/include \
	   -I$(SRC_BUILD_DIR)/include/rapidjson \
           -I$(SRC_BUILD_DIR)/../Ovsa_tool/include \
      	   -I$(SRC_BUILD_DIR)/../Ovsa_tool/src/app \
           -I$(SRC_BUILD_DIR)/../Ovsa_tool/src/lib/safestringlib/include \
	   -I$(SRC_BUILD_DIR)/mbedtls/install/include -I../mbedtls/crypto/include \
	   -I$(SRC_BUILD_DIR)/mbedtls/install/include -I../mbedtls/crypto/include \
           -I$(SRC_BUILD_DIR)/../Ovsa_tool/src/lib/cJSON \
           -I$(SRC_BUILD_DIR)/../Ovsa_tool/src/lib/openssl/include

OVSATOOL_SRC_DIR = $(SRC_BUILD_DIR)/../Ovsa_tool/src/app
OVSATOOL_LIB_DIR := $(SRC_BUILD_DIR)/../Ovsa_tool/lib
OVSARUN_LIB_DIR := $(OVSARUNTIME_DIR)/lib
OVSARUN_COM_DIR := $(OVSARUNTIME_DIR)/src/common

LFLAGS += -Wl,-rpath,$(OVSARUN_LIB_DIR) -L$(OVSARUN_LIB_DIR) -L$(OVSATOOL_LIB_DIR)  
LIBS = -Bstatic -lovsa -lsafestring -lcrypto -lssl -lcurl -lcjson -Bdynamic -lmbedcrypto -lmbedtls -lmbedx509 -ldl -lpthread -Wl,-z,defs,--exclude-libs,ALL
LIB_FLAGS := -g -fPIC

# Build Executable
#===================================
TARGET_BIN = ovsaruntime

C_SRC_FILES_LIB := \
	runtime.c \
	tcb_generator.c \
        $(OVSARUN_COM_DIR)/license_service_client.c \
        $(OVSARUN_COM_DIR)/model_loader.c

C_APP_FILES := $(wildcard $(OVSATOOL_SRC_DIR)/json.c)
C_APP_FILES += $(wildcard $(OVSATOOL_SRC_DIR)/utils.c)

OBJS_BIN := $(C_SRC_FILES_LIB:%.c=%.o)
OBJS_BIN += $(C_APP_FILES:$(OVSATOOL_SRC_DIR)/%.c=$(OVSARUN_COM_DIR)/%.o)
SPFLAGS := -fvisibility=hidden

.PHONY : all
all: $(TARGET_BIN)

%.o: %.c
	$(CC) $(CFLAGS) $(OVSATOOL_INC_DIR) $(LFLAGS) -c -o $@ $<

$(OVSARUN_COM_DIR)/%.o:  $(OVSATOOL_SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(OVSATOOL_INC_DIR) $(LFLAGS) -c -o $@ $<
json.o:  $(OVSATOOL_SRC_DIR)/json.c
	$(CC) $(CFLAGS) $(OVSATOOL_INC_DIR) $(LFLAGS) -c -o $@ $<
utils.o:  $(OVSATOOL_SRC_DIR)/utils.c
	$(CC) $(CFLAGS) $(OVSATOOL_INC_DIR) $(LFLAGS) -c -o $@ $<

$(TARGET_BIN):$(OBJS_BIN)
	$(CC) $^ $(LIBS) $(LFLAGS) -o $@
	
.PHONY: clean
clean:
	rm -f $(TARGET_BIN) *.o $(OVSARUN_COM_DIR)/*.o

