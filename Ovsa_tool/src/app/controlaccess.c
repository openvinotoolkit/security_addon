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

#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libovsa.h"
#include "ovsa_tool.h"
#include "safe_mem_lib.h"
#include "safe_str_lib.h"
#include "utils.h"
/* json.h to be included at end due to dependencies */
#include "json.h"

unsigned char g_model_hash[HASH_SIZE];
size_t g_isvcert_len             = 0;
static char* g_isv_certificate   = NULL;
static char* g_model_name        = NULL;
static char* g_model_description = NULL;
static char* g_model_version     = NULL;
static char g_model_guid[GUID_SIZE];

static void ovsa_controlaccess_help(const char* argv) {
    printf("Help for Control Access command\n");
    printf(
        "-i : List of model files to encrypt(Intermediatefiles/ Modelweights/ additionalfiles)\n");
    printf("-n : Model name\n");
    printf("-d : Model description\n");
    printf("-v : Model version number\n");
    printf("-p : Controlled access model file\n");
    printf("-m : Master license file\n");
    printf("-k : Keystore name\n");
    printf("-g : License GUID\n");
    printf("Example for controllAccess as below:\n");
    printf(
        "-i <Intermediate File> <Model weights file> <additional files> -n <Model name> -d <Model "
        "Description> -v <Model Version> -p <Controlled access model file> -m <Master license "
        "file> -k "
        "<key store file>\n\n");
    printf(
        "%s controlAccess -i face_detection.xml face_detection.bin face_detection.txt -n \"Face "
        "Detection\" -d \"Face person detection retail\" -v 0002 -p face_detection_model.json -m "
        "face_detection_model_master.lic -k key_store -g "
        "\"50934a64-5d1b-4655-bcb4-80080fcb8858\"\n",
        argv);
}

static ovsa_status_t ovsa_encrypt_model_files(int keyslot, const ovsa_input_files_t* input_list,
                                              ovsa_model_files_t** enc_model_list, size_t* filelen,
                                              int* file_count) {
    ovsa_status_t ret                  = OVSA_OK;
    size_t size                        = 0;
    size_t outlen                      = 0;
    char* model_buf                    = NULL;
    ovsa_model_files_t* enc_model_cur  = NULL;
    ovsa_model_files_t* enc_model_tail = NULL;
    ovsa_model_files_t* enc_model_head = NULL;
    const ovsa_input_files_t* cur_file = NULL;
    int keyiv_hmac_slot                = -1;
    int len                            = 0;
    int count                          = 0;

    if ((keyslot < MIN_KEY_SLOT) || (keyslot >= MAX_KEY_SLOT) || input_list == NULL) {
        ret = OVSA_INVALID_PARAMETER;
        OVSA_DBG(DBG_E, "OVSA: Error invalid input parameters\n");
        goto out;
    }

    cur_file = input_list;
    while (cur_file != NULL) {
        FILE* fcur_file = fopen(cur_file->name, "r");
        if (fcur_file == NULL) {
            OVSA_DBG(DBG_E, "OVSA: Error opening model file %s\n", cur_file->name);
            ret = OVSA_FILEOPEN_FAIL;
            goto out;
        }

        /* Get size of file data */
        ret = ovsa_crypto_get_file_size(fcur_file, &size);
        if (ret < OVSA_OK || size == 0) {
            OVSA_DBG(DBG_E, "OVSA: Error get file size failed for %s with code %d\n",
                     cur_file->name, ret);
            fclose(fcur_file);
            goto out;
        }
        size -= 1; /* Encryption to be calculated without null terminator */

        /* Read the content of the file */
        ret = ovsa_safe_malloc(size + NULL_TERMINATOR, &model_buf);
        if (ret < OVSA_OK || model_buf == NULL) {
            OVSA_DBG(DBG_E, "OVSA: Error encryption buffer allocation failed with code %d\n", ret);
            fclose(fcur_file);
            goto out;
        }
        ret = fread(model_buf, 1, size, fcur_file);
        fclose(fcur_file);

        if (enc_model_head == NULL) {
            ret = ovsa_safe_malloc(sizeof(ovsa_model_files_t), (char**)&enc_model_head);
            if (ret < OVSA_OK || enc_model_head == NULL) {
                OVSA_DBG(DBG_E,
                         "OVSA: Error model encryption list initialization failed with code %d\n",
                         ret);
                goto out;
            }
            enc_model_head->next = NULL;
            enc_model_tail       = enc_model_head;
        } else {
            ret = ovsa_safe_malloc(sizeof(ovsa_model_files_t), (char**)&enc_model_cur);
            if (ret < OVSA_OK || enc_model_cur == NULL) {
                OVSA_DBG(DBG_E,
                         "OVSA: Error model encryption list initialization failed with code %d\n",
                         ret);
                goto out;
            }
            enc_model_cur->next  = NULL;
            enc_model_tail->next = enc_model_cur;
            enc_model_tail       = enc_model_cur;
        }
        memcpy_s(enc_model_tail->model_file_name, MAX_FILE_NAME, cur_file->name,
                 strnlen_s(cur_file->name, MAX_FILE_NAME));
        /* Encrypt model file */
        ret = ovsa_crypto_encrypt_mem(keyslot, model_buf, size, NULL,
                                      &enc_model_tail->model_file_data, &outlen, &keyiv_hmac_slot);
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error encryption of %s failed with code %d\n", cur_file->name,
                     ret);
            /* Clear key/IV/HMAC from the key slot */
            ovsa_crypto_clear_symmetric_key_slot(keyiv_hmac_slot);
            goto out;
        }
        enc_model_tail->model_file_length = outlen;
        count++;
        len += outlen;
        OVSA_DBG(DBG_D, "OVSA: Encryption of Model file %s successful\n", cur_file->name);
        cur_file = cur_file->next;

        /* Clear key/IV/HMAC from the key slot */
        ovsa_crypto_clear_symmetric_key_slot(keyiv_hmac_slot);

        ovsa_safe_free(&model_buf);
    }

    *filelen        = len;
    *file_count     = count;
    *enc_model_list = enc_model_head;
out:
    ovsa_safe_free(&model_buf);
    return ret;
}

static ovsa_status_t ovsa_do_create_controlled_access_model_file(
    int asymm_keyslot, int sym_keyslot, const ovsa_input_files_t* input_list,
    const char* controlled_access_file) {
    ovsa_status_t ret                  = OVSA_OK;
    int file_count                     = 0;
    size_t size                        = 0;
    size_t model_file_len              = 0;
    size_t controlaccess_buf_len       = 0;
    char* controlaccess_buf_string     = NULL;
    char* controlaccess_buf_sig_string = NULL;
    FILE* fptr                         = NULL;
    ovsa_controlled_access_model_sig_t controlled_access_sig_model;

    if ((asymm_keyslot < MIN_KEY_SLOT) || (asymm_keyslot >= MAX_KEY_SLOT) ||
        (sym_keyslot < MIN_KEY_SLOT) || (sym_keyslot >= MAX_KEY_SLOT) || input_list == NULL ||
        controlled_access_file == NULL) {
        ret = OVSA_INVALID_PARAMETER;
        OVSA_DBG(DBG_E,
                 "OVSA: Error wrong input parameters to create controlled access model file\n");
        return ret;
    }

    OVSA_DBG(DBG_I, "\nOVSA: Controlled access model file generation\n");
    memset_s(&controlled_access_sig_model, sizeof(ovsa_controlled_access_model_sig_t), 0);
    /* Validate global parameters and populate the structure */
    if ((g_model_name != NULL) && (g_model_description != NULL) && (g_model_version != NULL)) {
        /* Controlled Access Model structure */
        memcpy_s(controlled_access_sig_model.controlled_access_model.model_name, MAX_NAME_SIZE,
                 g_model_name, strnlen_s(g_model_name, MAX_NAME_SIZE));
        memcpy_s(controlled_access_sig_model.controlled_access_model.description, MAX_NAME_SIZE,
                 g_model_description, strnlen_s(g_model_description, MAX_NAME_SIZE));
        memcpy_s(controlled_access_sig_model.controlled_access_model.version, MAX_VERSION_SIZE,
                 g_model_version, strnlen_s(g_model_version, MAX_VERSION_SIZE));
    } else {
        ret = OVSA_INVALID_PARAMETER;
        OVSA_DBG(DBG_E, "OVSA: Error wrong global parameters to create controlled access model\n");
        return ret;
    }

    /* Extract certificate from key slot */
    ret = ovsa_crypto_get_certificate(
        asymm_keyslot, &controlled_access_sig_model.controlled_access_model.isv_certificate);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error extract ISV certificate failed with error code %d\n", ret);
        goto out;
    }
    ret = ovsa_get_string_length(
        controlled_access_sig_model.controlled_access_model.isv_certificate, &g_isvcert_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of isv_certificate string %d\n", ret);
        goto out;
    }
    g_isvcert_len = g_isvcert_len + 1; /* For null termination */
    ret           = ovsa_safe_malloc(g_isvcert_len, &g_isv_certificate);
    memcpy_s(g_isv_certificate, g_isvcert_len,
             controlled_access_sig_model.controlled_access_model.isv_certificate, g_isvcert_len);
    controlled_access_sig_model.controlled_access_model.isv_certificate[g_isvcert_len - 1] = '\0';

    /* Verify certificate */
    OVSA_DBG(DBG_I, "OVSA: Verify ISV Certificate\n ");
    if ((!g_isvcert_len) || (g_isvcert_len > MAX_CERT_SIZE)) {
        OVSA_DBG(DBG_E, "OVSA: Error ISV certificate length is invalid \n");
        ret = OVSA_INVALID_PARAMETER;
        goto out;
    }
    ret = ovsa_crypto_verify_certificate(
        asymm_keyslot, /* PEER CERT */ false,
        controlled_access_sig_model.controlled_access_model.isv_certificate,
        /* lifetime_validity_check */ true);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error certificate verification failed with code %d\n", ret);
        goto out;
    }

    /* Read and encrypt input model files */
    OVSA_DBG(DBG_I, "OVSA: Encrypt Model Files\n");
    ret = ovsa_encrypt_model_files(sym_keyslot, input_list,
                                   &controlled_access_sig_model.controlled_access_model.enc_model,
                                   &model_file_len, &file_count);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error file Encryption failed with code %d\n", ret);
        goto out;
    }

    /* Generate model GUID */
    OVSA_DBG(DBG_I, "OVSA: Generate Model GUID\n");
    ret = ovsa_crypto_generate_guid(controlled_access_sig_model.controlled_access_model.model_guid);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error model GUID generation failed with code %d\n", ret);
        goto out;
    }
    memcpy_s(g_model_guid, GUID_SIZE,
             controlled_access_sig_model.controlled_access_model.model_guid, GUID_SIZE);

    /* Create controlled access model JSON blob */
    OVSA_DBG(DBG_I, "OVSA: Create Controlled Access Model JSON Blob\n");
    controlaccess_buf_len = model_file_len + sizeof(ovsa_controlled_access_model_t) +
                            CONTROLLED_ACCESS_MODEL_BLOB_TEXT_SIZE + g_isvcert_len +
                            (file_count * sizeof(ovsa_model_files_t) * MODEL_FILE_BLOB_TEXT_SIZE);
    OVSA_DBG(DBG_D, "OVSA: controlaccess_buf_len %d\n", (int)controlaccess_buf_len);
    ret = ovsa_safe_malloc(controlaccess_buf_len, &controlaccess_buf_string);
    if (ret < OVSA_OK || controlaccess_buf_string == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error controlled access buffer allocation failed with code %d\n",
                 ret);
        goto out;
    }
    ret = ovsa_json_create_controlled_access_model(&controlled_access_sig_model,
                                                   controlaccess_buf_len, controlaccess_buf_string);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E,
                 "OVSA: Error create controlled access model json failed with error code %d\n",
                 ret);
        goto out;
    }

    /* Generate HASH of controlled access model */
    OVSA_DBG(DBG_I, "OVSA: Generate HASH For Controlled Access Model\n");
    ret = ovsa_crypto_compute_hash(controlaccess_buf_string, HASH_ALG_SHA512, g_model_hash,
                                   true /*FORMAT_BASE64*/);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error model HASH generation failed with code %d\n", ret);
        goto out;
    }

    /* Sign controlled access model JSON blob */
    OVSA_DBG(DBG_I, "OVSA: Sign Controlled Access Model JSON Blob\n");
    size = MAX_SIGNATURE_SIZE + SIGNATURE_BLOB_TEXT_SIZE + controlaccess_buf_len;
    ret  = ovsa_safe_malloc(size, &controlaccess_buf_sig_string);
    if (ret < OVSA_OK || controlaccess_buf_sig_string == NULL) {
        OVSA_DBG(DBG_E,
                 "OVSA: Error controlled access model signature buffer allocation failed %d\n",
                 ret);
        goto out;
    }
    ret = ovsa_crypto_sign_json_blob(asymm_keyslot, controlaccess_buf_string, controlaccess_buf_len,
                                     controlaccess_buf_sig_string, size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error controlled access model signing failed with error code %d\n",
                 ret);
        goto out;
    }

    /* Store Controlled access model JSON blob on specified output file */
    if (controlaccess_buf_sig_string != NULL) {
        if ((fptr = fopen(controlled_access_file, "w+")) != NULL) {
            ret = ovsa_get_string_length(controlaccess_buf_sig_string, &size);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "OVSA: Error could not get length of isv_certificate string %d\n",
                         ret);
                fclose(fptr);
                goto out;
            }
            fwrite(controlaccess_buf_sig_string, size, 1, fptr);
            fclose(fptr);
        } else {
            ret = OVSA_FILEOPEN_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Error in creating controlled access model file %s\n",
                     controlled_access_file);
            goto out;
        }
    }

out:
    ovsa_safe_free(&controlaccess_buf_string);
    ovsa_safe_free(&controlaccess_buf_sig_string);
    ovsa_safe_free_model_file_list(&controlled_access_sig_model.controlled_access_model.enc_model);
    ovsa_safe_free(&controlled_access_sig_model.controlled_access_model.isv_certificate);
    return ret;
}

ovsa_status_t ovsa_do_create_master_license_file(int asymm_keyslot, int sym_keyslot,
                                                 const char* masterlic_file,
                                                 const char* license_guid) {
    ovsa_status_t ret           = OVSA_OK;
    size_t size                 = 0;
    size_t master_lic_buf_len   = 0;
    char* master_lic_string     = NULL;
    char* master_lic_sig_string = NULL;
    char* enc_key               = NULL;
    FILE* fptr                  = NULL;
    time_t curtime              = time(NULL);
    char* time_str              = NULL;
    int keyiv_hmac_slot         = -1;
    size_t outlen               = 0;
    ovsa_master_license_sig_t master_sig_license;

    if ((asymm_keyslot < MIN_KEY_SLOT) || (asymm_keyslot >= MAX_KEY_SLOT) ||
        (sym_keyslot < MIN_KEY_SLOT) || (sym_keyslot >= MAX_KEY_SLOT) || license_guid == NULL ||
        masterlic_file == NULL) {
        ret = OVSA_INVALID_PARAMETER;
        OVSA_DBG(DBG_E, "OVSA: Error wrong input parameters to create master license\n");
        return ret;
    }

    OVSA_DBG(DBG_I, "\nOVSA: Master license generation\n");
    memset_s(&master_sig_license, sizeof(ovsa_master_license_sig_t), 0);
    /* Validate global parameters and populate the structure */
    if (g_isv_certificate != NULL && g_model_guid != NULL && g_model_hash != NULL) {
        memcpy_s(master_sig_license.master_lic.license_guid, GUID_SIZE, license_guid,
                 strnlen_s(license_guid, GUID_SIZE));

        /* Set isv certificate */
        ret = ovsa_safe_malloc(g_isvcert_len, &master_sig_license.master_lic.isv_certificate);
        if (ret < OVSA_OK || master_sig_license.master_lic.isv_certificate == NULL) {
            OVSA_DBG(DBG_E, "OVSA: Error master license signature buffer allocation failed %d\n",
                     ret);
            goto out;
        }
        memcpy_s(master_sig_license.master_lic.isv_certificate, g_isvcert_len, g_isv_certificate,
                 g_isvcert_len);
        master_sig_license.master_lic.isv_certificate[g_isvcert_len - 1] = '\0';

        /* Set Model GUID */
        memcpy_s(master_sig_license.master_lic.model_guid, GUID_SIZE, g_model_guid,
                 strnlen_s(g_model_guid, GUID_SIZE));

        /* Set Model Hash */
        memcpy_s(master_sig_license.master_lic.model_hash, HASH_SIZE, g_model_hash, HASH_SIZE);
    } else {
        ret = OVSA_INVALID_PARAMETER;
        OVSA_DBG(DBG_E, "OVSA: Error wrong global parameters to create master license\n");
        return ret;
    }

    /* Wrap symmetric key used for encyption */
    OVSA_DBG(DBG_I, "OVSA: Wrap Key\n");
    ret = ovsa_crypto_wrap_key(asymm_keyslot, sym_keyslot, &enc_key, &outlen, &keyiv_hmac_slot);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error master license wrapkey generation failed with error code %d\n",
                 ret);
        goto out;
    }
    memcpy_s(master_sig_license.master_lic.encryption_key, MAX_EKEY_SIZE, enc_key,
             strnlen_s(enc_key, MAX_EKEY_SIZE));

    OVSA_DBG(DBG_I, "OVSA: Populate Master License Parameters\n");
    /* Set creation date and time */
    time_str           = ctime(&curtime);
    size               = strnlen_s(time_str, MAX_NAME_SIZE);
    time_str[size - 1] = '\0';
    memcpy_s(master_sig_license.master_lic.creation_date, MAX_NAME_SIZE, time_str, size);

    /* Create master license JSON blob */
    OVSA_DBG(DBG_I, "OVSA: Create Master License JSON Blob\n");
    master_lic_buf_len =
        g_isvcert_len + sizeof(ovsa_master_license_t) + MASTER_LICENSE_BLOB_TEXT_SIZE;
    ret = ovsa_safe_malloc(master_lic_buf_len, &master_lic_string);
    if (ret < OVSA_OK || master_lic_string == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error master license buffer allocation %d\n", ret);
        goto out;
    }
    ret =
        ovsa_json_create_master_license(&master_sig_license, master_lic_buf_len, master_lic_string);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error master license json creation failed with error code %d\n",
                 ret);
        goto out;
    }

    /* Sign Master license JSON blob */
    OVSA_DBG(DBG_I, "OVSA: Sign Master License JSON Blob\n");
    size = MAX_SIGNATURE_SIZE + SIGNATURE_BLOB_TEXT_SIZE + master_lic_buf_len;
    ret  = ovsa_safe_malloc(size, &master_lic_sig_string);
    if (ret < OVSA_OK || master_lic_sig_string == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error master license buffer allocation %d\n", ret);
        goto out;
    }

    /* Computes HMAC for master license */
    ret = ovsa_crypto_hmac_json_blob(keyiv_hmac_slot, master_lic_string, master_lic_buf_len,
                                     master_lic_sig_string, size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error master license signing failed with error code %d\n", ret);
        goto out;
    }

    /* Store master license JSON blob on specified output file */
    if (master_lic_sig_string != NULL) {
        if ((fptr = fopen(masterlic_file, "w+")) != NULL) {
            ret = ovsa_get_string_length(master_lic_sig_string, &size);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "OVSA: Error could not get length of signature string %d\n", ret);
                fclose(fptr);
                goto out;
            }
            fwrite(master_lic_sig_string, size, 1, fptr);
            fclose(fptr);
        } else {
            ret = OVSA_FILEOPEN_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Error in creating master license file %s\n", masterlic_file);
            goto out;
        }
    }

out:
    /* Clear key/IV/HMAC from the key slot */
    ovsa_crypto_clear_symmetric_key_slot(keyiv_hmac_slot);
    /* Clear symmetric key from the key slot */
    ovsa_crypto_clear_symmetric_key_slot(sym_keyslot);
    ovsa_safe_free(&enc_key);
    ovsa_safe_free(&master_lic_sig_string);
    ovsa_safe_free(&master_lic_string);
    ovsa_safe_free(&master_sig_license.master_lic.isv_certificate);
    ovsa_safe_free(&g_isv_certificate);
    return ret;
}

ovsa_status_t ovsa_controlaccess_main(int argc, char* argv[]) {
    ovsa_status_t ret              = OVSA_OK;
    int asymm_keyslot              = -1;
    int sym_keyslot                = -1;
    int c                          = 0;
    int i                          = 0;
    size_t argv_len                = 0;
    ovsa_input_files_t* input_list = NULL;
    ovsa_input_files_t* list_tail  = NULL;
    char* license_guid             = NULL;
    char* keystore                 = NULL;
    char* masterlic_file           = NULL;
    char* controlled_access_file   = NULL;

    OVSA_DBG(DBG_D, "%s entry\n", __func__);

    if (argc > MAX_SAFE_ARGC) {
        ret = OVSA_INVALID_PARAMETER;
        OVSA_DBG(DBG_E, "OVSA: Error wrong command given. Please follow -help for help option\n");
        goto out;
    }
    for (i = 0; argc > i; i++) {
        ret = ovsa_get_string_length(argv[i], &argv_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error could not get length of argv string %d\n", ret);
            goto out;
        }
        if (argv_len > RSIZE_MAX_STR) {
            OVSA_DBG(
                DBG_E,
                "OVSA: Error controlAccess argument'%s' greater than %ld characters not allowed \n",
                argv[i], RSIZE_MAX_STR);
            ret = OVSA_INVALID_PARAMETER;
            goto out;
        }
    }

    while ((c = getopt(argc, argv, "i:n:d:v:p:m:k:g:h")) != -1) {
        switch (c) {
            case 'i': {
                int index = 0;
                index     = optind - 1;
                while (index < argc) {
                    if (strnlen_s(optarg, RSIZE_MAX_STR) < MAX_NAME_SIZE) {
                        if (argv[index][0] != '-') {
                            ret = ovsa_store_input_file_list(argv[index], &input_list, &list_tail);
                            if (ret < OVSA_OK) {
                                OVSA_DBG(DBG_E,
                                         "OVSA: Error store Model file list failed with code %d\n",
                                         ret);
                                goto out;
                            }
                            optind = index + 1;
                        } else {
                            break;
                        }
                        index++;
                    } else {
                        OVSA_DBG(DBG_E,
                                 "OVSA: Error name greater than %d characters not allowed \n",
                                 MAX_NAME_SIZE);
                        ret = OVSA_INVALID_PARAMETER;
                        goto out;
                    }
                }
            } break;
            case 'n': {
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_NAME_SIZE) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Error model name greater than %d characters not allowed \n",
                             MAX_NAME_SIZE);
                    ret = OVSA_INVALID_PARAMETER;
                    goto out;
                }
                g_model_name = optarg;
                OVSA_DBG(DBG_D, "OVSA: model_name = %s\n", g_model_name);
            } break;
            case 'd': {
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_NAME_SIZE) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Model description greater than %d characters not allowed \n",
                             MAX_NAME_SIZE);
                    ret = OVSA_INVALID_PARAMETER;
                    goto out;
                }
                g_model_description = optarg;
                OVSA_DBG(DBG_D, "OVSA: model_description = %s\n", g_model_description);
            } break;
            case 'v': {
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_VERSION_SIZE) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Error model version greater than %d characters not allowed \n",
                             MAX_VERSION_SIZE);
                    ret = OVSA_INVALID_PARAMETER;
                    goto out;
                }
                g_model_version = optarg;
                OVSA_DBG(DBG_D, "OVSA: model_version = %s\n", g_model_version);
            } break;
            case 'k': {
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_FILE_NAME) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Error keystore path greater than %d characters not allowed \n",
                             MAX_FILE_NAME);
                    ret = OVSA_INVALID_FILE_PATH;
                    goto out;
                }
                keystore = optarg;
                OVSA_DBG(DBG_D, "OVSA: keystore= %s\n", keystore);
            } break;
            case 'p': {
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_FILE_NAME) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Controlled access model file path greater than %d characters "
                             "not allowed \n",
                             MAX_FILE_NAME);
                    ret = OVSA_INVALID_FILE_PATH;
                    goto out;
                }
                controlled_access_file = optarg;
                OVSA_DBG(DBG_D, "OVSA: controlled_access_file = %s\n", controlled_access_file);
            } break;
            case 'm': {
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_FILE_NAME) {
                    OVSA_DBG(
                        DBG_E,
                        "OVSA: Master license file path greater than %d characters not allowed \n",
                        MAX_FILE_NAME);
                    ret = OVSA_INVALID_FILE_PATH;
                    goto out;
                }
                masterlic_file = optarg;
                OVSA_DBG(DBG_D, "OVSA: masterlic_file = %s\n", masterlic_file);
            } break;
            case 'g': {
                if (strnlen_s(optarg, RSIZE_MAX_STR) > GUID_SIZE) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Error model GUID is greater than %d characters not allowed \n",
                             GUID_SIZE);
                    ret = OVSA_INVALID_PARAMETER;
                    goto out;
                }
                license_guid = optarg;
                if (ovsa_is_guid_valid((unsigned char*)license_guid) != true) {
                    OVSA_DBG(DBG_E, "OVSA: Error entered GUID is not valid...\n");
                    ret = OVSA_INVALID_PARAMETER;
                    goto out;
                }

                OVSA_DBG(DBG_D, "OVSA: license_guid = %s\n", license_guid);
            } break;
            case 'h': {
                ovsa_controlaccess_help(argv[0]);
                goto out;
            }
            default: {
                OVSA_DBG(DBG_E,
                         "OVSA: Error wrong command given. Please follow -help for help option\n");
                ret = OVSA_INVALID_PARAMETER;
                goto out;
            }
        }
    }

    /* optind is for the extra arguments which are not parsed */
    for (; optind < argc; optind++) {
        OVSA_DBG(DBG_I, "extra arguments: %s\n", argv[optind]);
    }

    /* Validate Input parameters */
    if ((input_list != NULL) && (g_model_name != NULL) && (g_model_description != NULL) &&
        (g_model_version != NULL) && (keystore != NULL) && (controlled_access_file != NULL) &&
        (masterlic_file != NULL) && (license_guid != NULL)) {
        /* Initialize crypto */
        ret = ovsa_crypto_init();
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error ovsa crypto init failed with code %d\n", ret);
            goto out;
        }

    } else {
        OVSA_DBG(DBG_E, "OVSA: Error wrong command given. Please follow -help for help option\n");
        ret = OVSA_INVALID_PARAMETER;
        goto out;
    }

    /* Get Asym Key Slot from Key store */
    OVSA_DBG(DBG_I, "OVSA: Load Asymmetric Key\n");
    ret = ovsa_crypto_load_asymmetric_key(keystore, &asymm_keyslot);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error get keyslot failed with code %d\n", ret);
        goto out;
    }

    /* Get Sym Key Slot from Key store */
    OVSA_DBG(DBG_I, "OVSA: Generate Symmetric Key\n");
    ret = ovsa_crypto_generate_symmetric_key(SYMMETRIC_KEY_SIZE, &sym_keyslot);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error generation of Encryption key failed with code %d\n", ret);
        goto out;
    }
    ret = ovsa_do_create_controlled_access_model_file(asymm_keyslot, sym_keyslot, input_list,
                                                      controlled_access_file);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error generation of controlled access model failed with code %d\n",
                 ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA: Generation of %s file successful.\n", controlled_access_file);

    ret = ovsa_do_create_master_license_file(asymm_keyslot, sym_keyslot, masterlic_file,
                                             license_guid);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error generation of Master license failed with code %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA: Generation of %s file successful.\n", masterlic_file);

out:
    /* De-initialize crypto */
    ovsa_crypto_deinit();
    ovsa_safe_free_input_list(&input_list);
    OVSA_DBG(DBG_D, "%s exit\n", __func__);
    return ret;
}
