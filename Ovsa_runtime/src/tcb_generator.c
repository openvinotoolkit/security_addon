/*****************************************************************************
 * Copyright 2020 Intel Corporation
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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "runtime.h"
#include "tpm.h"
#include "utils.h"
/* json.h to be included at end due to dependencies */
#include "json.h"

static void ovsa_tcb_gen_help(char* argv) {
    printf("Help for TCB Generator command\n");
    printf("-n : TCB name\n");
    printf("-v : TCB version\n");
    printf("-f : TCB file name\n");
    printf("-k : Keystore name\n");
    printf(
        "%s gen-tcb-signature -n <TCB name> -v <TCB version> -f <TCB file name> -k "
        "Keystore\n",
        argv);
}

static ovsa_status_t ovsa_do_read_quote_pubkey(ovsa_quote_info_t* sw_quote_info) {
    ovsa_status_t ret = OVSA_OK;
    size_t file_size  = 0;
    char* pcr_buf     = NULL;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /* read pcr */
    ret = ovsa_read_file_content(TPM2_SWQUOTE_PCR, &pcr_buf, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Reading TPM2_SWQUOTE_PCR file failed with error code %d\n", ret);
        goto out;
    }
    /* convert pcr bin to pem*/
    ret = ovsa_crypto_convert_bin_to_base64(pcr_buf, file_size - 1, &sw_quote_info->quote_pcr);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Crypto convert_bin_to_pem failed with code %d\n", ret);
        goto out;
    }
    /*read public key */
    ret = ovsa_read_file_content(TPM2_AK_PUB_PEM_KEY, &sw_quote_info->ak_pub_key, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Reading TPM2_AK_PUB_PEM_KEY file failed with error code %d\n", ret);
        goto out;
    }
out:
    ovsa_safe_free(&pcr_buf);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_get_tpm2_SW_quote(ovsa_quote_info_t* sw_quote_info) {
    ovsa_status_t ret         = OVSA_OK;
    char nonce[MAX_NAME_SIZE] = {'\0'};

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    /* Generate tpm2 quote */
    ret = ovsa_tpm2_generatequote(nonce);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: ovsa_tpm2_generatequote failed with code %d\n", ret);
        goto out;
    }
    ret = ovsa_do_read_quote_pubkey(sw_quote_info);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: read_SW_quote failed with code %d\n", ret);
        goto out;
    }
out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

#ifndef DISABLE_TPM2_HWQUOTE

static ovsa_status_t ovsa_get_tpm2_HW_quote(ovsa_quote_info_t* hw_quote_info) {
    ovsa_status_t ret = OVSA_OK;
    char* nonce       = NULL;
    int sockfd;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /********************************************/
    /*       GET HW QUOTE using SSL connection  */
    /********************************************/
    /* Establish host connection */
    ret = ovsa_establish_host_connection(&sockfd);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: ovsa_establish_host_connection failed with code %d\n", ret);
        goto out;
    }

    /* Generate nonce for HWquote */
    ret = ovsa_create_nonce(&nonce);
    if (ret < OVSA_OK) {
        close(sockfd);
        OVSA_DBG(DBG_E, "Error ovsa_generate_nonce failed with code %d\n", ret);
        goto out;
    }
    /* Get HWQuote */
    ret = ovsa_get_hw_quote(sockfd, nonce, hw_quote_info);

    if (ret < OVSA_OK) {
        close(sockfd);
        OVSA_DBG(DBG_E, "Error ovsa_establish_host_connection failed with code %d\n", ret);
        goto out;
    }
    close(sockfd);

    OVSA_DBG(DBG_I, "OVSA:Generated HW quote successfully \n");
out:
    ovsa_safe_free(&nonce);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}
#endif

static ovsa_status_t ovsa_tpm2_generate_golden_quote(ovsa_quote_info_t* sw_quote_info,
                                                     ovsa_quote_info_t* hw_quote_info) {
    ovsa_status_t ret = OVSA_OK;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    ret = ovsa_get_tpm2_SW_quote(sw_quote_info);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error : Get tpm2 SW quote failed with code %d\n", ret);
        goto out;
    }
#ifndef DISABLE_TPM2_HWQUOTE
    ret = ovsa_get_tpm2_HW_quote(hw_quote_info);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error : Get tpm2 HW quote failed with code %d\n", ret);
        goto out;
    }
#endif
out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
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
    FILE* fptr          = NULL;
    char* tcb_sig_buf   = NULL;
    char* tcb_buf       = NULL;
    ovsa_tcb_sig_t tcb_sig_info;
    size_t file_size = 0;
    ovsa_quote_info_t sw_quote_info;
    ovsa_quote_info_t hw_quote_info;
    int c;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    memset_s(&tcb_sig_info, sizeof(ovsa_tcb_sig_t), 0);
    memset_s(&sw_quote_info, sizeof(ovsa_quote_info_t), 0);
    memset_s(&hw_quote_info, sizeof(ovsa_quote_info_t), 0);
    while ((c = getopt(argc, argv, "n:v:f:k:s:h")) != -1) {
        switch (c) {
            case 'v':
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_VERSION_SIZE) {
                    OVSA_DBG(DBG_E, "OVSA: TCB version greater than %d characters not allowed \n",
                             MAX_VERSION_SIZE);
                    ret = OVSA_INVALID_PARAMETER;
                    goto out;
                }
                tcb_version = optarg;
                OVSA_DBG(DBG_D, "OVSA: tcb_version = %s\n", tcb_version);
                break;
            case 'n':
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_NAME_SIZE) {
                    OVSA_DBG(DBG_E, "OVSA: TCB name greater than %d characters not allowed \n",
                             MAX_NAME_SIZE);
                    ret = OVSA_INVALID_PARAMETER;
                    goto out;
                }
                tcb_name = optarg;
                OVSA_DBG(DBG_D, "OVSA: tcb_name = %s\n", tcb_name);
                break;
            case 'f':
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_NAME_SIZE) {
                    OVSA_DBG(DBG_E, "OVSA: TCB filename greater than %d characters not allowed \n",
                             MAX_NAME_SIZE);
                    ret = OVSA_INVALID_PARAMETER;
                    goto out;
                }
                tcb_file = optarg;
                OVSA_DBG(DBG_D, "OVSA: tcb_file = %s\n", tcb_file);
                break;
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
            case 'h': {
                ovsa_tcb_gen_help(argv[0]);
                goto out;
            }
        }
    }
    if (tcb_version == NULL || tcb_file == NULL || tcb_name == NULL || keystore == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Invalid input parameters \n");
        ret = OVSA_INVALID_PARAMETER;
        goto out;
    }

    ret = ovsa_tpm2_generate_golden_quote(&sw_quote_info, &hw_quote_info);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Get quote measurements failed with error code %d\n", ret);
        goto out;
    }
    ret = ovsa_get_string_length(sw_quote_info.quote_pcr, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of sw_quote_pcr string %d\n", ret);
        goto out;
    }
    memcpy_s(tcb_sig_info.tcbinfo.sw_quote, TPM2_QUOTE_SIZE, sw_quote_info.quote_pcr, file_size);

    ret = ovsa_get_string_length(sw_quote_info.ak_pub_key, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of sw_pub_key string %d\n", ret);
        goto out;
    }
    memcpy_s(tcb_sig_info.tcbinfo.sw_pub_key, TPM2_PUBKEY_SIZE, sw_quote_info.ak_pub_key,
             file_size);
#ifndef DISABLE_TPM2_HWQUOTE
    ret = ovsa_get_string_length(hw_quote_info.quote_pcr, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of HW_quote_pcr string %d\n", ret);
        goto out;
    }
    memcpy_s(tcb_sig_info.tcbinfo.hw_quote, TPM2_QUOTE_SIZE, hw_quote_info.quote_pcr, file_size);

    ret = ovsa_get_string_length(hw_quote_info.ak_pub_key, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of HW_ak_pub_key string %d\n", ret);
        goto out;
    }
    memcpy_s(tcb_sig_info.tcbinfo.hw_pub_key, TPM2_PUBKEY_SIZE, hw_quote_info.ak_pub_key,
             file_size);
#endif
    memcpy_s(tcb_sig_info.tcbinfo.tcb_name, MAX_NAME_SIZE, tcb_name, MAX_NAME_SIZE);
    memcpy_s(tcb_sig_info.tcbinfo.tcb_version, MAX_VERSION_SIZE, tcb_version, MAX_VERSION_SIZE);

    /* crypto init */
    ret = ovsa_crypto_init();
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Crypto init failed with code %d\n", ret);
        goto out;
    }

    OVSA_DBG(DBG_I, "OVSA: Load Asymmetric Key\n");
    /* Get Asym Key Slot from Key store */
    ret = ovsa_crypto_load_asymmetric_key(keystore, &asymm_keyslot);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Get keyslot failed with code %d\n", ret);
        goto out;
    }

    /* Get customer certificate from key slot */
    ret = ovsa_crypto_get_certificate(asymm_keyslot, &tcb_sig_info.tcbinfo.isv_certificate);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Get customer certificate failed with code %d\n", ret);
        goto out;
    }

    /* Create TCB JSON blob */
    size_t cert_len = 0;
    ret             = ovsa_get_string_length(tcb_sig_info.tcbinfo.isv_certificate, &cert_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of certificate string %d\n", ret);
        goto out;
    }
    tcb_buf_size = (sizeof(ovsa_tcb_sig_t) + TPM2_BLOB_TEXT_SIZE + cert_len);
    ret          = ovsa_safe_malloc(tcb_buf_size, &tcb_buf);
    if (ret < OVSA_OK || tcb_buf == NULL) {
        OVSA_DBG(DBG_E, "OVSA: TCB info buffer allocation failed with code %d\n", ret);
        goto out;
    }
    ret = ovsa_json_create_tcb_signature(&tcb_sig_info, tcb_buf);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Create TCB buffer failed with error code %d\n", ret);
        goto out;
    }

    /* Sign TCB JSON blob */
    size = MAX_SIGNATURE_SIZE + SIGNATURE_BLOB_TEXT_SIZE + tcb_buf_size;
    ret  = ovsa_safe_malloc(size, &tcb_sig_buf);
    if (ret < OVSA_OK || tcb_sig_buf == NULL) {
        OVSA_DBG(DBG_E, "OVSA: TCB signature buffer allocation failed %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA: Sign TCB JSON Blob\n");
    ret = ovsa_crypto_sign_json_blob(asymm_keyslot, tcb_buf, tcb_buf_size, tcb_sig_buf);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: TCB signing failed with error code %d\n", ret);
        goto out;
    }

    /*  Store TCB signature JSON blob on specified output file */
    if (tcb_sig_buf != NULL) {
        OVSA_DBG(DBG_I, "OVSA: tcb_buf %s\n\n", tcb_sig_buf);
        if ((tcb_file != NULL) && (fptr = fopen(tcb_file, "w+")) != NULL) {
            ret = ovsa_get_string_length(tcb_sig_buf, &size);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "Error: Could not get length of tcb_sig_buf string %d\n", ret);
                fclose(fptr);
                goto out;
            }
            fwrite(tcb_sig_buf, size, 1, fptr);
            fclose(fptr);
            OVSA_DBG(DBG_I, "OVSA: TCB signature file %s generated successfully\n", tcb_file);
        } else {
            ret = OVSA_FILEOPEN_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Opening TCB file failed with error code %d\n", ret);
            goto out;
        }
    }
    ovsa_crypto_deinit();

out:
    ovsa_safe_free(&tcb_sig_info.tcbinfo.isv_certificate);
    ovsa_safe_free(&tcb_sig_buf);
    ovsa_safe_free(&tcb_buf);
    ovsa_safe_free(&sw_quote_info.quote_pcr);
    ovsa_safe_free(&sw_quote_info.ak_pub_key);
#ifndef DISABLE_TPM2_HWQUOTE
    ovsa_safe_free(&hw_quote_info.quote_pcr);
    ovsa_safe_free(&hw_quote_info.ak_pub_key);
    ovsa_safe_free(&hw_quote_info.quote_message);
    ovsa_safe_free(&hw_quote_info.quote_sig);
    ovsa_safe_free(&hw_quote_info.ek_cert);
#endif
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}
