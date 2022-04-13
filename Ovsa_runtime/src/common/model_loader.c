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

/* json.h to be included at end due to dependencies */
#include "json.h"

static ovsa_status_t ovsa_do_decrypt_model_files(
    const int asym_key_slot, const int peer_slot, ovsa_customer_license_sig_t* customer_lic_sig,
    ovsa_controlled_access_model_sig_t* controlled_access_model_sig,
    ovsa_model_files_t** decrypted_files) {
    ovsa_status_t ret         = OVSA_OK;
    size_t decrypt_model_len  = 0;
    char* decrypted_model_buf = NULL;
    int sym_key_slot          = -1;
    int keyiv_hmac_slot       = -1;
    char* enc_model           = NULL;
    char encryption_key[MAX_EKEY_SIZE];

    ovsa_model_files_t* enc_model_list = NULL;
    ovsa_model_files_t* enc_model_head = NULL;
    ovsa_model_files_t* dec_model_head = NULL;
    ovsa_model_files_t* dec_model_tail = NULL;
    ovsa_model_files_t* dec_model_cur  = NULL;
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
    enc_model_head = controlled_access_model_sig->controlled_access_model.enc_model;
    enc_model_list = enc_model_head;

    if (enc_model_list == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error model file empty  \n");
    } else {
        while (enc_model_list != NULL) {
            enc_model  = enc_model_list->model_file_data;
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
            OVSA_DBG(DBG_I, "OVSA: Decrypt model file : %s Successful\n",
                     enc_model_list->model_file_name);

            if (dec_model_head == NULL) {
                /* Memory allocated and this needs to be freed by consumer */
                ret = ovsa_safe_malloc(sizeof(ovsa_model_files_t), (char**)&dec_model_head);
                if (ret < OVSA_OK || dec_model_head == NULL) {
                    OVSA_DBG(DBG_E, "OVSA: Error could not allocate memory %d\n", ret);
                    ovsa_safe_free(&decrypted_model_buf);
                    goto out;
                }
                memcpy_s(dec_model_head->model_file_name, MAX_NAME_SIZE,
                         enc_model_list->model_file_name, MAX_NAME_SIZE);
                dec_model_head->model_file_length = decrypt_model_len;
                dec_model_head->next              = NULL;
                dec_model_tail                    = dec_model_head;
            } else {
                /* Memory allocated and this needs to be freed by consumer */
                ret = ovsa_safe_malloc(sizeof(ovsa_model_files_t), (char**)&dec_model_cur);
                if (ret < OVSA_OK || dec_model_cur == NULL) {
                    OVSA_DBG(DBG_E, "OVSA: Error could not allocate memory %d\n", ret);
                    ovsa_safe_free_model_file_list(&dec_model_head);
                    ovsa_safe_free(&decrypted_model_buf);
                    goto out;
                }
                memcpy_s(dec_model_cur->model_file_name, MAX_NAME_SIZE,
                         enc_model_list->model_file_name, MAX_NAME_SIZE);
                dec_model_cur->model_file_length = decrypt_model_len;
                dec_model_cur->next              = NULL;
                dec_model_tail->next             = dec_model_cur;
                dec_model_tail                   = dec_model_cur;
            }
            ret = ovsa_safe_malloc((decrypt_model_len + 1) * sizeof(char),
                                   &dec_model_tail->model_file_data);
            if (ret < OVSA_OK) {
                ret = OVSA_MEMORY_ALLOC_FAIL;
                OVSA_DBG(DBG_E, "OVSA: Error memory alloc fail for xml file with code %d\n", ret);
                ovsa_safe_free_model_file_list(&dec_model_head);
                ovsa_safe_free(&decrypted_model_buf);
                goto out;
            }
            memcpy_s(dec_model_tail->model_file_data, decrypt_model_len, decrypted_model_buf,
                     decrypt_model_len);
            ovsa_safe_free(&decrypted_model_buf);
            decrypted_model_buf = NULL;
            enc_model_list      = enc_model_list->next;
        }
        *decrypted_files = dec_model_head;
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
    const int asym_key_slot, const int peer_slot, char* customer_lic_sig_buf,
    ovsa_controlled_access_model_sig_t* controlled_access_model_sig,
    ovsa_model_files_t** decrypted_files) {
    ovsa_status_t ret = OVSA_OK;
    ovsa_customer_license_sig_t customer_lic_sig;
    /* Set all pointers to NULL for KW fix */
    customer_lic_sig.customer_lic.isv_certificate  = NULL;
    customer_lic_sig.customer_lic.tcb_signatures   = NULL;
    customer_lic_sig.customer_lic.license_url_list = NULL;

    /* Extract customer license json blob */
    memset_s(&customer_lic_sig, sizeof(ovsa_customer_license_sig_t), 0);
    ret = ovsa_json_extract_customer_license(customer_lic_sig_buf, &customer_lic_sig);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error extract customer license json blob failed with code %d\n",
                 ret);
        goto out;
    }
    /* Decrypt the model files */
    ret = ovsa_do_decrypt_model_files(asym_key_slot, peer_slot, &customer_lic_sig,
                                      controlled_access_model_sig, decrypted_files);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Could not decrypt model files\n");
        goto out;
    }
    OVSA_DBG(DBG_D, "\nDecryption model files completed \n---END---\n");

out:
    ovsa_safe_free(&customer_lic_sig.customer_lic.isv_certificate);
    ovsa_safe_free_url_list(&customer_lic_sig.customer_lic.license_url_list);
    ovsa_safe_free_tcb_list(&customer_lic_sig.customer_lic.tcb_signatures);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_license_check_module(const char* keystore, const char* controlled_access_model,
                                        const char* customer_license,
                                        ovsa_model_files_t** decrypted_files) {
    ovsa_status_t ret      = OVSA_OK;
    int asym_keyslot       = -1;
    size_t certlen         = 0;
    char* certificate      = NULL;
    char* cust_lic_sig_buf = NULL;
    int peer_keyslot       = -1;
    ovsa_controlled_access_model_sig_t control_access_model_sig;
    ovsa_customer_license_sig_t cust_lic_sig;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    memset_s(&control_access_model_sig, sizeof(ovsa_controlled_access_model_sig_t), 0);
    memset_s(&cust_lic_sig, sizeof(ovsa_customer_license_sig_t), 0);

    /* Input Parameter Validation check */
    if ((controlled_access_model != NULL) && (customer_license != NULL) && (keystore != NULL)) {
        OVSA_DBG(DBG_I, "OVSA: Load Asymmetric Key\n");
        /* Get Asym Key Slot from Key store */
        ret = ovsa_crypto_load_asymmetric_key(keystore, &asym_keyslot);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error get keyslot failed with code %d\n", ret);
            goto out;
        }

        /* Get customer certificate from key slot */
        ret = ovsa_crypto_get_certificate(asym_keyslot, &certificate);
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error get customer certificate failed with code %d\n", ret);
            goto out;
        }

        OVSA_DBG(DBG_I, "OVSA: Verify customer certificate\n");
        ret = ovsa_get_string_length(certificate, &certlen);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error could not get length of customer certificate %d\n", ret);
            goto out;
        }
        if ((!certlen) || (certlen > MAX_CERT_SIZE)) {
            OVSA_DBG(DBG_E, "OVSA: Error cusotmer certificate length is invalid \n");
            ret = OVSA_INVALID_PARAMETER;
            goto out;
        }
        /*Verify customer certificate*/
        ret = ovsa_crypto_verify_certificate(asym_keyslot, /* PEER CERT */ false, certificate,
                                             /* lifetime_validity_check */ true);

        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error verify customer certificate failed with code %d\n", ret);
            goto out;
        }
        /* Validate Customer license artefact */
        OVSA_DBG(DBG_I, "OVSA: Validate customer license\n");
        peer_keyslot =
            ovsa_validate_customer_license(customer_license, asym_keyslot, &cust_lic_sig_buf);
        if ((peer_keyslot < MIN_KEY_SLOT) || (peer_keyslot >= MAX_KEY_SLOT)) {
            ret = peer_keyslot;
            OVSA_DBG(DBG_E,
                     "OVSA: Error customer license artifact validation failed with code %d\n", ret);
            goto out;
        }
        OVSA_DBG(DBG_I, "OVSA: Validate controlled access model\n");
        /* Validate controlled access model artifact*/
        ret = ovsa_validate_controlled_access_model(
            peer_keyslot, cust_lic_sig_buf, controlled_access_model, &control_access_model_sig);
        if (ret != OVSA_OK) {
            OVSA_DBG(
                DBG_E,
                "OVSA: Error controlled access model artifact validation failed with code %d\n",
                ret);
            goto out;
        }
    } else {
        OVSA_DBG(DBG_E, "OVSA: Error invalid artifacts \n");
        ret = OVSA_INVALID_PARAMETER;
        goto out;
    }
    /* Perform License Check Sequence */
    bool status = false;
    ret         = ovsa_perform_tls_license_check(asym_keyslot, customer_license, &status);
    if ((!status) || ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error TLS Licence check failed with code %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA: Platform and License Validation completed successfully\n");
    OVSA_DBG(DBG_I, "OVSA: Invoking model loader\n");
    /* Invoke Model Loader */
    ret = ovsa_start_model_loader(asym_keyslot, peer_keyslot, cust_lic_sig_buf,
                                  &control_access_model_sig, decrypted_files);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error model Loader Init failed with code %d\n", ret);
    }

out:
    /* clear asymmetric key pairs from the key slot */
    ovsa_crypto_clear_asymmetric_key_slot(asym_keyslot);
    /* clear peer keys from the key slots */
    ovsa_crypto_clear_asymmetric_key_slot(peer_keyslot);
    ovsa_safe_free_model_file_list(&control_access_model_sig.controlled_access_model.enc_model);
    ovsa_safe_free(&certificate);
    ovsa_safe_free(&cust_lic_sig_buf);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}
