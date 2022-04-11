/*****************************************************************************
 * Copyright 2020-2022 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *****************************************************************************
 */
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "runtime.h"
#include "tpm.h"
#include "utils.h"

/* Definition added to include this header file */
#define __ASSEMBLER__
#include "asm-offsets.h"

/* json.h to be included at end due to dependencies */
#include "json.h"

static uint16_t g_isv_prod_id;
static uint16_t g_isv_svn;
static char g_mrsigner[SGX_ENCLAVE_HASH_SIZE];
static char g_mrenclave[SGX_ENCLAVE_HASH_SIZE];

static uint16_t ovsa_convert_to_littleendian(uint8_t* buf) {
    return (buf[1] << 8 | buf[0]);
}

static void ovsa_convert_to_twodigithex(char* buf, size_t size, char* outbuf) {
    int i = 0;
    for (int n = 0; n < size && i < SGX_ENCLAVE_HASH_SIZE; n++) {
        char conv[4];
        snprintf(conv, 4, "%02hhx", buf[n]);
        outbuf[i++] = conv[0];
        outbuf[i++] = conv[1];
    }
}

ovsa_status_t ovsa_generate_reference_tcb(ovsa_tcb_info_t* tcb_info, char* sig_file) {
    ovsa_status_t ret = OVSA_OK;
    FILE* fptr        = NULL;
    uint8_t results[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    uint8_t buf[1024];

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    fptr = fopen(sig_file, "rb");
    if (fptr == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "Error: Opening file %s failed with code %d\n", sig_file, ret);
        goto out;
    }

    /*'enclave_hash': (offs.SGX_ARCH_ENCLAVE_CSS_ENCLAVE_HASH, "32s", 'enclave_hash'),*/
    fseek(fptr, SGX_ARCH_ENCLAVE_CSS_ENCLAVE_HASH, SEEK_SET);
    ret = fread(buf, 32, 1, fptr);
    ovsa_convert_to_twodigithex((char*)buf, 32, g_mrenclave);
    OVSA_DBG(DBG_D, "mrenclave: %s\n", g_mrenclave);

    /* 'modulus': (offs.SGX_ARCH_ENCLAVE_CSS_MODULUS, "384s", 'modulus'),*/
    fseek(fptr, SGX_ARCH_ENCLAVE_CSS_MODULUS, SEEK_SET);
    ret = fread(buf, 384, 1, fptr);
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (uint8_t*)buf, 384);
    SHA256_Final(results, &ctx);
    ovsa_convert_to_twodigithex((char*)results, SHA256_DIGEST_LENGTH, g_mrsigner);
    OVSA_DBG(DBG_D, "mrsigner: %s\n", g_mrsigner);

    /*'isv_prod_id': (offs.SGX_ARCH_ENCLAVE_CSS_ISV_PROD_ID, "<H", 'isv_prod_id'),*/
    fseek(fptr, SGX_ARCH_ENCLAVE_CSS_ISV_PROD_ID, SEEK_SET);
    ret           = fread(buf, 2, 1, fptr);
    g_isv_prod_id = ovsa_convert_to_littleendian(buf);

    /*'isv_svn': (offs.SGX_ARCH_ENCLAVE_CSS_ISV_SVN, "<H", 'isv_svn'),*/
    fseek(fptr, SGX_ARCH_ENCLAVE_CSS_ISV_SVN, SEEK_SET);
    ret       = fread(buf, 2, 1, fptr);
    g_isv_svn = ovsa_convert_to_littleendian(buf);

    fclose(fptr);

    /* Populate to TCB Struct parameters*/
    memcpy_s(tcb_info->mrenclave, SGX_ENCLAVE_HASH_SIZE, g_mrenclave, SGX_ENCLAVE_HASH_SIZE);
    OVSA_DBG(DBG_D, "Attributes: MREnclave is %s\n", g_mrenclave);
    memcpy_s(tcb_info->mrsigner, SGX_ENCLAVE_HASH_SIZE, g_mrsigner, SGX_ENCLAVE_HASH_SIZE);
    OVSA_DBG(DBG_D, "Attributes: MRSigner is %s\n", g_mrsigner);
    tcb_info->isv_svn = g_isv_svn;
    OVSA_DBG(DBG_D, "Attributes: isv_svn is %d\n", g_isv_svn);
    tcb_info->isv_prod_id = g_isv_prod_id;
    OVSA_DBG(DBG_D, "Attributes: isv_prod_id is %d\n", g_isv_prod_id);

out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}
