/*****************************************************************************
 * Copyright 2020-2021 Intel Corporation
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

#include <fnmatch.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "runtime.h"
#include "utils.h"

static ovsa_status_t ovsa_do_decrypt_model_files(
    const int asym_key_slot, const int peer_slot, ovsa_customer_license_sig_t* customer_lic_sig,
    ovsa_controlled_access_model_sig_t* controlled_access_model_sig, char** decrypt_xml,
    char** decrypt_bin, int* xml_len, int* bin_len) {
    ovsa_status_t ret         = OVSA_OK;
    size_t decrypt_model_len  = 0;
    char* decrypted_model_buf = NULL;
    int sym_key_slot          = -1;
    int keyiv_hmac_slot       = -1;
    char* enc_model           = NULL;
    char encryption_key[MAX_EKEY_SIZE];

    ovsa_enc_models_t* enc_model_list = NULL;
    ovsa_enc_models_t* head           = NULL;
    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    memset_s(encryption_key, sizeof(encryption_key), 0);
    memcpy_s(encryption_key, MAX_EKEY_SIZE, customer_lic_sig->customer_lic.encryption_key,
             strnlen_s(customer_lic_sig->customer_lic.encryption_key, MAX_EKEY_SIZE) + 1);

    size_t encrypt_key_buff_len = 0;
    encrypt_key_buff_len        = strnlen_s(encryption_key, RSIZE_MAX_STR);

    /* Unwrap model encryption key */
    ret = ovsa_crypto_unwrap_key(asym_key_slot, peer_slot, encryption_key, encrypt_key_buff_len,
                                 &sym_key_slot, &keyiv_hmac_slot);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error unwrap model encryption key failed with code  %d\n", ret);
        goto out;
    }
    /* Clear encryption_key buffer */
    memset_s(encryption_key, sizeof(encryption_key), 0);

    /* clear key/IV/HMAC from the key slot */
    ovsa_crypto_clear_symmetric_key_slot(keyiv_hmac_slot);

    OVSA_DBG(DBG_I, "OVSA: Unwrap model encryption key Successful \n");
    head           = controlled_access_model_sig->controlled_access_model.enc_model;
    enc_model_list = head;

    if (enc_model_list == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error model file empty  \n");
    } else {
        while (enc_model_list != NULL) {
            enc_model  = enc_model_list->enc_model;
            size_t len = 0;
            ret        = ovsa_get_string_length(enc_model, &len);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "OVSA: Error could not get length of additional_param string %d\n",
                         ret);
                goto out;
            }
            /* Decrypt controlled access model files */
            ret = ovsa_crypto_decrypt_mem(sym_key_slot, enc_model, len, &decrypted_model_buf,
                                          &decrypt_model_len, &keyiv_hmac_slot);
            if (ret != OVSA_OK || decrypted_model_buf == NULL) {
                OVSA_DBG(DBG_E,
                         "OVSA: Error decrypt controlled access model files failed with code %d\n",
                         ret);
                ovsa_safe_free(&decrypted_model_buf);
                goto out;
            }

            /* clear key/IV/HMAC from the key slot */
            ovsa_crypto_clear_symmetric_key_slot(keyiv_hmac_slot);
            char* xml_pattern = "*.xml";
            char* bin_pattern = "*.bin";
            OVSA_DBG(DBG_I, "OVSA: Decrypt model file : %s Successful\n",
                     enc_model_list->file_name);
            if (*decrypt_xml == NULL && (fnmatch(xml_pattern, enc_model_list->file_name, 0) == 0)) {
                ret = ovsa_safe_malloc((decrypt_model_len + 1) * sizeof(char), decrypt_xml);
                if (ret < OVSA_OK) {
                    ret = OVSA_MEMORY_ALLOC_FAIL;
                    OVSA_DBG(DBG_E, "OVSA: Error memory alloc fail for xml file with code %d\n",
                             ret);
                    ovsa_safe_free(&decrypted_model_buf);
                    goto out;
                }
                memcpy_s(*decrypt_xml, decrypt_model_len, decrypted_model_buf, decrypt_model_len);
                *xml_len = decrypt_model_len;
            } else if (*decrypt_bin == NULL &&
                       (fnmatch(bin_pattern, enc_model_list->file_name, 0) == 0)) {
                ret = ovsa_safe_malloc((decrypt_model_len + 1) * sizeof(char), decrypt_bin);
                if (ret < OVSA_OK) {
                    ret = OVSA_MEMORY_ALLOC_FAIL;
                    OVSA_DBG(DBG_E, "OVSA: Error memory alloc fail for xml file with code %d\n",
                             ret);
                    ovsa_safe_free(&decrypted_model_buf);
                    goto out;
                }
                memcpy_s(*decrypt_bin, decrypt_model_len, decrypted_model_buf, decrypt_model_len);
                *bin_len = decrypt_model_len;
            }
            ovsa_safe_free(&decrypted_model_buf);
            decrypted_model_buf = NULL;
            enc_model_list      = enc_model_list->next;
        }
        OVSA_DBG(DBG_D, "\nControlled Access Model files Decrypted Successfully \n");
    }
out:
    /* clear key/IV/HMAC from the key slot */
    ovsa_crypto_clear_symmetric_key_slot(keyiv_hmac_slot);
    /* clear unwrapped encryption key from the key slot */
    ovsa_crypto_clear_symmetric_key_slot(sym_key_slot);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_start_model_loader(
    const int asym_key_slot, const int peer_slot, ovsa_customer_license_sig_t* customer_lic_sig,
    ovsa_controlled_access_model_sig_t* controlled_access_model_sig, char** decrypt_xml,
    char** decrypt_bin, int* xml_len, int* bin_len) {
    ovsa_status_t ret = OVSA_OK;

    /* Decrypt the model files */
    ret = ovsa_do_decrypt_model_files(asym_key_slot, peer_slot, customer_lic_sig,
                                      controlled_access_model_sig, decrypt_xml, decrypt_bin,
                                      xml_len, bin_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Could not decrypt model files\n");
        goto out;
    }
    OVSA_DBG(DBG_D, "\nDecryption model files completed \n---END---\n");

out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}
