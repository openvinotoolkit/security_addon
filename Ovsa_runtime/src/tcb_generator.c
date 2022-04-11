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

#include <linux/types.h>
#include <netdb.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "runtime.h"
#include "tpm.h"
#include "utils.h"
/* json.h to be included at end due to dependencies */
#include "json.h"

void ovsa_tcb_gen_help(char* argv) {
    printf("Help for TCB Generator command\n");
    printf("-n : TCB name\n");
    printf("-v : TCB version\n");
    printf("-f : TCB file name\n");
    printf("-k : Keystore name\n");
#ifndef ENABLE_SGX_GRAMINE
    printf("-s : sw_pcr_reg_id [exclude sw pcr registers,valid range=0x1:0xffffff]\n");
    printf("-h : hw_pcr_reg_id [exclude hw pcr registers,valid range=0x1:0xffffff]\n");
    printf(
        "%s gen-tcb-signature -n <TCB name> -v <TCB version> -f <TCB file name> -k "
        "<Keystore> -s <sw_pcr_reg_id> -h <hw_pcr_reg_id>\n",
        argv);
#endif
#ifdef ENABLE_SGX_GRAMINE
    printf("-s : SGX signature file\n");
    printf(
        "%s gen-tcb-signature -n <TCB name> -v <TCB version> -f <TCB file name> -k "
        "<Keystore> -s <SGX signature file>\n",
        argv);

#endif
}

ovsa_status_t ovsa_do_tcb_generation(int argc, char* argv[]) {
    ovsa_status_t ret   = OVSA_OK;
    int asymm_keyslot   = -1;
    size_t size         = 0;
    size_t tcb_buf_size = 0;
    char* tcb_file      = NULL;
    char* tcb_name      = NULL;
    char* tcb_version   = NULL;
    char* keystore      = NULL;
#ifdef ENABLE_SGX_GRAMINE
    char* sig_file = NULL;
#endif
    FILE* fptr        = NULL;
    char* tcb_sig_buf = NULL;
    char* tcb_buf     = NULL;
    ovsa_tcb_sig_t tcb_sig_info;
    int c = 0;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    memset_s(&tcb_sig_info, sizeof(ovsa_tcb_sig_t), 0);
#ifndef ENABLE_SGX_GRAMINE
    int sw_pcr_reg_id = 0;
    int hw_pcr_reg_id = 0;
    /* setting default value to enable all PCR registers into TCB during quote validation */
    sw_pcr_reg_id = (int)strtol(DEFAULT_PCR_ID_SET, NULL, 16);
    hw_pcr_reg_id = (int)strtol(DEFAULT_PCR_ID_SET, NULL, 16);
    while ((c = getopt(argc, argv, "n:v:f:k:s:h:")) != -1)
#else
    while ((c = getopt(argc, argv, "n:v:f:k:s:")) != -1)
#endif
    {
        switch (c) {
            case 'v':
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_VERSION_SIZE) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Error TCB version greater than %d characters not allowed \n",
                             MAX_VERSION_SIZE);
                    ret = OVSA_INVALID_PARAMETER;
                    goto out;
                }
                tcb_version = optarg;
                OVSA_DBG(DBG_D, "OVSA: tcb_version = %s\n", tcb_version);
                break;
            case 'n':
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_NAME_SIZE) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Error TCB name greater than %d characters not allowed \n",
                             MAX_NAME_SIZE);
                    ret = OVSA_INVALID_PARAMETER;
                    goto out;
                }
                tcb_name = optarg;
                OVSA_DBG(DBG_D, "OVSA: tcb_name = %s\n", tcb_name);
                break;
            case 'f':
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_NAME_SIZE) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Error TCB filename greater than %d characters not allowed \n",
                             MAX_NAME_SIZE);
                    ret = OVSA_INVALID_PARAMETER;
                    goto out;
                }
                tcb_file = optarg;
                OVSA_DBG(DBG_D, "OVSA: tcb_file = %s\n", tcb_file);
                break;
#ifdef ENABLE_SGX_GRAMINE
            case 's':
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_NAME_SIZE) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Signature manifest file path size greater than %d characters "
                             "not allowed \n",
                             MAX_NAME_SIZE);
                    ret = OVSA_INVALID_FILE_PATH;
                    goto out;
                }
                sig_file = optarg;
                OVSA_DBG(DBG_D, "Signature manifest    : %s\n", sig_file);
                break;
#endif
            case 'k':
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_NAME_SIZE) {
                    OVSA_DBG(
                        DBG_E,
                        "OVSA: Keystore file path size greater than %d characters not allowed \n",
                        MAX_NAME_SIZE);
                    ret = OVSA_INVALID_FILE_PATH;
                    goto out;
                }
                keystore = optarg;
                OVSA_DBG(DBG_D, "Keystore_name    : %s\n", keystore);
                break;
#ifndef ENABLE_SGX_GRAMINE
            case 's':
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_PCR_ID_SIZE) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Error swpcr_id_set value greater than %d characters not "
                             "allowed [valid range=0x1:0xffffff]\n",
                             MAX_PCR_ID_SIZE);
                    ret = OVSA_INVALID_PARAMETER;
                    goto out;
                }
                ret = ovsa_get_pcr_exclusion_set(optarg, &sw_pcr_reg_id);
                if (ret < OVSA_OK) {
                    OVSA_DBG(DBG_E, "OVSA: Error get SW pcr exclusion failed with error code %d\n",
                             ret);
                    goto out;
                }
                break;
            case 'h':
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_PCR_ID_SIZE) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Error hwpcr_id_set value greater than %d characters not "
                             "allowed [valid range=0x1:0xffffff]\n",
                             MAX_PCR_ID_SIZE);
                    ret = OVSA_INVALID_PARAMETER;
                    goto out;
                }
                ret = ovsa_get_pcr_exclusion_set(optarg, &hw_pcr_reg_id);
                if (ret < OVSA_OK) {
                    OVSA_DBG(DBG_E, "OVSA: Error get HW pcr exclusion failed with error code %d\n",
                             ret);
                    goto out;
                }
                break;
#endif
            default: {
                ovsa_tcb_gen_help(argv[0]);
                goto out;
            }
        }
    }
    if (tcb_version == NULL || tcb_file == NULL || tcb_name == NULL || keystore == NULL
#ifdef ENABLE_SGX_GRAMINE
        || sig_file == NULL
#endif
    ) {
        OVSA_DBG(DBG_E, "OVSA: Error invalid input parameters \n");
        ret = OVSA_INVALID_PARAMETER;
        goto out;
    }
    /*set file mode creation mask*/
    mode_t nmask;
    nmask = S_IRGRP | S_IWGRP | /* group read write */
            S_IROTH | S_IWOTH;  /* other read write */
    umask(nmask);               /*0666 & ~066 = 0600 i.e., (-rw-------)*/
    ret = ovsa_generate_reference_tcb(&tcb_sig_info.tcbinfo,
#ifndef ENABLE_SGX_GRAMINE
                                      sw_pcr_reg_id, hw_pcr_reg_id
#else
                                      sig_file
#endif
    );
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error get generate reference tcbs failed with error code %d\n", ret);
        goto out;
    }
    memcpy_s(tcb_sig_info.tcbinfo.tcb_name, MAX_NAME_SIZE, tcb_name, MAX_NAME_SIZE);
    memcpy_s(tcb_sig_info.tcbinfo.tcb_version, MAX_VERSION_SIZE, tcb_version, MAX_VERSION_SIZE);

    /* crypto init */
    ret = ovsa_crypto_init();
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error crypto init failed with code %d\n", ret);
        goto out;
    }

    OVSA_DBG(DBG_I, "OVSA: Load Asymmetric Key\n");
    /* Get Asym Key Slot from Key store */
    ret = ovsa_crypto_load_asymmetric_key(keystore, &asymm_keyslot);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error get keyslot failed with code %d\n", ret);
        goto out;
    }

    /* Get customer certificate from key slot */
    ret = ovsa_crypto_get_certificate(asymm_keyslot, &tcb_sig_info.tcbinfo.isv_certificate);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error get customer certificate failed with code %d\n", ret);
        goto out;
    }

    /* Create TCB JSON blob */
    size_t cert_len = 0;
    ret             = ovsa_get_string_length(tcb_sig_info.tcbinfo.isv_certificate, &cert_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of certificate string %d\n", ret);
        goto out;
    }
    tcb_buf_size = (sizeof(ovsa_tcb_sig_t) + TCB_INFO_BLOB_TEXT_SIZE + cert_len);
    ret          = ovsa_safe_malloc(tcb_buf_size, &tcb_buf);
    if (ret < OVSA_OK || tcb_buf == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error TCB info buffer allocation failed with code %d\n", ret);
        goto out;
    }
    ret = ovsa_json_create_tcb_signature(&tcb_sig_info, tcb_buf_size, tcb_buf);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error create TCB buffer failed with error code %d\n", ret);
        goto out;
    }

    /* Sign TCB JSON blob */
    size = MAX_SIGNATURE_SIZE + SIGNATURE_BLOB_TEXT_SIZE + tcb_buf_size;
    ret  = ovsa_safe_malloc(size, &tcb_sig_buf);
    if (ret < OVSA_OK || tcb_sig_buf == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error TCB signature buffer allocation failed %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA: Sign TCB JSON Blob\n");
    ret = ovsa_crypto_sign_json_blob(asymm_keyslot, tcb_buf, tcb_buf_size, tcb_sig_buf, size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error TCB signing failed with error code %d\n", ret);
        goto out;
    }

    /*  Store TCB signature JSON blob on specified output file */
    if (tcb_sig_buf != NULL) {
        OVSA_DBG(DBG_I, "OVSA: tcb_buf %s\n\n", tcb_sig_buf);
        if ((tcb_file != NULL) && (fptr = fopen(tcb_file, "w+")) != NULL) {
            ret = ovsa_get_string_length(tcb_sig_buf, &size);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "OVSA: Error could not get length of tcb_sig_buf string %d\n", ret);
                fclose(fptr);
                goto out;
            }
            fwrite(tcb_sig_buf, size, 1, fptr);
            fclose(fptr);
            OVSA_DBG(DBG_I, "OVSA: TCB signature file %s generated successfully\n", tcb_file);
        } else {
            ret = OVSA_FILEOPEN_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Error opening TCB file failed with error code %d\n", ret);
            goto out;
        }
    }
    ovsa_crypto_deinit();

out:
    ovsa_safe_free(&tcb_sig_info.tcbinfo.isv_certificate);
    ovsa_safe_free(&tcb_sig_buf);
    ovsa_safe_free(&tcb_buf);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}
