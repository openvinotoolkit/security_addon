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

static void ovsa_update_custlicense_help(const char* argv) {
    printf("Help for Updatecustlicense command\n");
    printf("-k : Keystore name\n");
    printf("-l : Existing Customer License file\n");
    printf("-p : Customer certificate\n");
    printf("-u : ISV license server URL, Customer certificate\n");
    printf("-c : Updated customer license\n");
    printf("Example for update as below:\n");
    printf(
        "-k <key store file> -l <Customer License File> -p <Customer Certificate> -u <License URL> "
        "<Future License Server Certificate> [-u <License URL> <Future server certificate file>] "
        "-c <Updated Customer license>\n\n");
    printf(
        "%s updatecustlicense -k isv_keystore -l face_detection_model.lic -p customer_cert.crt -u "
        "\"14650@192.166.248.2\" future_customer_cert.crt -c "
        "updated_face_detection_model.lic\n",
        argv);
}

ovsa_status_t ovsa_update_custlicense_main(int argc, char* argv[]) {
    ovsa_status_t ret                = OVSA_OK;
    int i                            = 0;
    int c                            = 0;
    int list_count                   = 0;
    int asymm_keyslot                = -1;
    int peer_keyslot                 = -1;
    int shared_key_slot              = -1;
    int keyiv_hmac_slot              = -1;
    size_t size                      = 0;
    size_t argv_len                  = 0;
    size_t cust_lic_size             = 0;
    char* peer_cert                  = NULL;
    char* keystore                   = NULL;
    char* customer_cert_file         = NULL;
    char* updated_customer_lic_file  = NULL;
    char* isv_certificate            = NULL;
    char* customer_lic_file          = NULL;
    char* customer_lic_sig_string    = NULL;
    char* customer_lic_string        = NULL;
    char* cust_lic_buf               = NULL;
    char* cust_lic_sig_buf           = NULL;
    ovsa_input_url_list_t* list_head = NULL;
    ovsa_input_url_list_t* list_tail = NULL;
    ovsa_customer_license_sig_t customer_license;
    FILE* fptr = NULL;

    memset_s(&customer_license, sizeof(ovsa_customer_license_sig_t), 0);

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
            OVSA_DBG(DBG_E,
                     "OVSA: Error update customer license argument'%s' greater than %ld characters "
                     "not allowed \n",
                     argv[i], RSIZE_MAX_STR);
            ret = OVSA_INVALID_PARAMETER;
            goto out;
        }
    }

    while ((c = getopt(argc, argv, "k:l:p:u:c:h")) != -1) {
        switch (c) {
            case 'k': {
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_FILE_NAME) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Error keystore path greater than %d characters not allowed \n",
                             MAX_FILE_NAME);
                    ret = OVSA_INVALID_FILE_PATH;
                    goto out;
                }
                keystore = optarg;
                OVSA_DBG(DBG_D, "OVSA: keystore = %s\n", keystore);
            } break;
            case 'l': {
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_FILE_NAME) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Customer license file path greater than %d characters not "
                             "allowed \n",
                             MAX_FILE_NAME);
                    ret = OVSA_INVALID_PARAMETER;
                    goto out;
                }
                customer_lic_file = optarg;
                OVSA_DBG(DBG_D, "OVSA: customer_lic_file = %s\n", customer_lic_file);
            } break;
            case 'p': {
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_FILE_NAME) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Customer certificate file path greater than %d characters not "
                             "allowed \n",
                             MAX_FILE_NAME);
                    ret = OVSA_INVALID_PARAMETER;
                    goto out;
                }
                customer_cert_file = optarg;
                OVSA_DBG(DBG_D, "OVSA: customer_cert_file = %s\n", customer_cert_file);
            } break;
            case 'c': {
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_FILE_NAME) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Customer license file path greater than %d characters not "
                             "allowed \n",
                             MAX_FILE_NAME);
                    ret = OVSA_INVALID_PARAMETER;
                    goto out;
                }
                updated_customer_lic_file = optarg;
                OVSA_DBG(DBG_D, "OVSA: updated_customer_lic_file = %s\n",
                         updated_customer_lic_file);
            } break;
            case 'u': {
                int index = 0;
                index     = optind - 1;
                if (index < argc) {
                    if (strnlen_s(optarg, RSIZE_MAX_STR) < MAX_URL_SIZE) {
                        if (argv[index][0] != '-') {
                            ret = ovsa_store_input_url_list(argv[index], &list_head, &list_tail);
                            if (ret < OVSA_OK) {
                                OVSA_DBG(DBG_E, "OVSA: Error load URL list failed with code %d\n",
                                         ret);
                                goto out;
                            }
                            list_count++;
                            optind = index + 1;
                            index++;
                            if (index < argc) {
                                if (strnlen_s(argv[index], RSIZE_MAX_STR) < MAX_NAME_SIZE) {
                                    if (argv[index][0] != '-') {
                                        FILE* fcur_file = fopen(argv[index], "r");
                                        if (fcur_file == NULL) {
                                            OVSA_DBG(DBG_E, "OVSA: Error opening file %s\n",
                                                     argv[index]);
                                            ret = OVSA_FILEOPEN_FAIL;
                                            goto out;
                                        }
                                        fclose(fcur_file);
                                        memcpy_s(list_tail->fut_cert_file, MAX_FILE_NAME,
                                                 argv[index],
                                                 strnlen_s(argv[index], MAX_FILE_NAME));
                                        OVSA_DBG(DBG_D, "OVSA: fut_cert_file is %s\n",
                                                 list_tail->fut_cert_file);
                                        optind = index + 1;
                                    } else {
                                        OVSA_DBG(DBG_E,
                                                 "OVSA: Error certificate file for URL not "
                                                 "specified \n");
                                        ret = OVSA_INVALID_PARAMETER;
                                        goto out;
                                    }
                                } else {
                                    OVSA_DBG(DBG_E,
                                             "OVSA: Error name greater than %d characters not "
                                             "allowed \n",
                                             MAX_NAME_SIZE);
                                    ret = OVSA_INVALID_PARAMETER;
                                    goto out;
                                }
                            } else {
                                OVSA_DBG(DBG_E,
                                         "OVSA: Error certificate file for URL not "
                                         "specified \n");
                                ret = OVSA_INVALID_PARAMETER;
                                goto out;
                            }
                            index++;
                        } else {
                            OVSA_DBG(DBG_E, "OVSA: Error URL not specified \n");
                            ret = OVSA_INVALID_PARAMETER;
                            goto out;
                        }
                    } else {
                        OVSA_DBG(DBG_E, "OVSA: Error URL greater than %d characters not allowed \n",
                                 MAX_URL_SIZE);
                        ret = OVSA_INVALID_PARAMETER;
                        goto out;
                    }
                }
            } break;
            case 'h': {
                ovsa_update_custlicense_help(argv[0]);
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

    if ((keystore == NULL) || (customer_lic_file == NULL) || (list_head == NULL) ||
        (customer_cert_file == NULL) || (updated_customer_lic_file == NULL)) {
        ret = OVSA_INVALID_PARAMETER;
        OVSA_DBG(DBG_E, "OVSA: Error wrong command given. Please follow -help for help option\n");
        goto out;
    }

    /* Initialize crypto */
    ret = ovsa_crypto_init();
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error ovsa crypto init failed with code %d\n", ret);
        goto out;
    }

    /* Get Asym Key Slot from Key store */
    OVSA_DBG(DBG_I, "OVSA: Load Asymmetric Key\n");
    ret = ovsa_crypto_load_asymmetric_key(keystore, &asymm_keyslot);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error get keyslot failed with code %d\n", ret);
        goto out;
    }

    /* Read certficate from on disk file */
    fptr = fopen(customer_cert_file, "r");
    if (fptr == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error opening certificate file failed with code %d\n", ret);
        goto out;
    }

    /* Get length of certificate file */
    size = ovsa_crypto_get_file_size(fptr);
    ret  = ovsa_safe_malloc(size, &peer_cert);
    if (ret < OVSA_OK || peer_cert == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error certificate file buffer allocation failed with code %d\n",
                 ret);
        fclose(fptr);
        goto out;
    }
    ret = fread(peer_cert, 1, size, fptr);
    fclose(fptr);

    OVSA_DBG(DBG_I, "OVSA: Verify Input Certificate\n");

    if ((!size) || (size > MAX_CERT_SIZE)) {
        OVSA_DBG(DBG_E, "OVSA: Error customer certificate length is invalid \n");
        ret = OVSA_INVALID_PARAMETER;
        goto out;
    }
    ret = ovsa_crypto_extract_pubkey_verify_cert(/*PEER Cert*/ true, peer_cert,
                                                 /* lifetime_validity_check */ true, &peer_keyslot);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error verify customer certificate failed with code %d\n", ret);
        goto out;
    }

    /* Extract ISV certificate from key slot */
    ret = ovsa_crypto_get_certificate(asymm_keyslot, &isv_certificate);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error extract ISV certificate failed with error code %d\n", ret);
        goto out;
    }

    /* Verify ISV certificate */
    size_t certlen = 0;
    ret            = ovsa_get_string_length(isv_certificate, &certlen);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of ISV certificate %d\n", ret);
        goto out;
    }
    if ((!certlen) || (certlen > MAX_CERT_SIZE)) {
        OVSA_DBG(DBG_E, "OVSA: Error ISV certificate length is invalid \n");
        ret = OVSA_INVALID_PARAMETER;
        goto out;
    }
    ret = ovsa_crypto_verify_certificate(asymm_keyslot, /*PEER Cert*/ false, isv_certificate,
                                         /* lifetime_validity_check */ true);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error verify certificate failed with code %d\n", ret);
        goto out;
    }

    /* Load customer license Artifact */
    FILE* fcust_lic = fopen(customer_lic_file, "r");
    if (fcust_lic == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error opening customer license file failed with code %d\n", ret);
        goto out;
    }
    cust_lic_size = ovsa_crypto_get_file_size(fcust_lic);
    ret           = ovsa_safe_malloc(cust_lic_size * sizeof(char), &cust_lic_sig_buf);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error init memory failed with code %d\n", ret);
        fclose(fcust_lic);
        goto out;
    }
    if (!fread(cust_lic_sig_buf, 1, cust_lic_size, fcust_lic)) {
        ret = OVSA_FILEIO_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error read customer license file failed with code %d\n", ret);
        fclose(fcust_lic);
        goto out;
    }
    cust_lic_sig_buf[cust_lic_size - 1] = '\0';
    fclose(fcust_lic);

    /* Extract customer licensce json blob */
    ret = ovsa_json_extract_customer_license(cust_lic_sig_buf, &customer_license);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error extract customer license json blob failed with code %d\n",
                 ret);
        goto out;
    }

    /* Compute shared key using customer private key and ISV public key */
    ret = ovsa_crypto_create_ecdh_key(asymm_keyslot, peer_keyslot, &shared_key_slot);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error generating shared key failed with error code %d\n", ret);
        goto out;
    }

    /* Extract salt from encryption_key and derive key/IV/HMAC for customer license */
    ret = ovsa_crypto_derive_keyiv_hmac(
        shared_key_slot, customer_license.customer_lic.encryption_key,
        strnlen_s(customer_license.customer_lic.encryption_key, MAX_EKEY_SIZE), &keyiv_hmac_slot);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error deriving key/IV/HAMC failed with error code %d\n", ret);
        goto out;
    }

    /* Verifies the HMAC for customer license */
    ret = ovsa_safe_malloc(cust_lic_size * sizeof(char), &cust_lic_buf);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error init memory failed with code %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA: Verify customer license signature\n");
    ret = ovsa_crypto_verify_hmac_json_blob(keyiv_hmac_slot, cust_lic_sig_buf, cust_lic_size,
                                            cust_lic_buf);
    if (ret != OVSA_OK || cust_lic_buf == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error verify customer license json blob failed with code %d\n", ret);
        goto out;
    }

    /* Update customer license structure */
    ovsa_input_url_list_t* url_list_next = list_head;
    char cert_hash[HASH_SIZE];
    while (url_list_next != NULL) {
        memset_s(cert_hash, HASH_SIZE, 0);
        ovsa_license_serv_url_list_t* cust_url_list =
            customer_license.customer_lic.license_url_list;
        bool update_success = false;
        while (cust_url_list != NULL) {
            int url_indicator = -1;
            strcmp_s(url_list_next->license_serv_url, MAX_URL_SIZE, cust_url_list->license_serv_url,
                     &url_indicator);
            if (url_indicator == 0) {
                ret = ovsa_generate_cert_hash(url_list_next->fut_cert_file, cert_hash);
                if (ret < OVSA_OK) {
                    OVSA_DBG(DBG_E, "OVSA: Error generating certificate hash with code %d\n", ret);
                    goto out;
                }
                memset_s(cust_url_list->fut_cert_hash, HASH_SIZE, 0);
                memcpy_s(cust_url_list->fut_cert_hash, HASH_SIZE, cert_hash, HASH_SIZE);
                update_success = true;
                break;
            }
            cust_url_list = cust_url_list->next;
        }
        if (!update_success) {
            OVSA_DBG(
                DBG_E,
                "OVSA: WARNING %s URL is not present in input customer license - Ignoring %s\n",
                url_list_next->license_serv_url, url_list_next->fut_cert_file);
        }
        url_list_next = url_list_next->next;
    }
    memset_s(customer_license.signature, MAX_SIGNATURE_SIZE, 0);

    /* Create customer license JSON string from the structure */
    cust_lic_size = cust_lic_size + (list_count * HASH_SIZE) + 1;
    ret           = ovsa_safe_malloc(cust_lic_size, &customer_lic_string);
    if (ret < OVSA_OK || customer_lic_string == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error customer license buffer allocation failed with code %d\n",
                 ret);
        goto out;
    }
    ret = ovsa_json_create_customer_license(&customer_license, cust_lic_size, customer_lic_string);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error create customer license failed with error code %d\n", ret);
        goto out;
    }

    /* Sign customer license JSON blob */
    OVSA_DBG(DBG_I, "OVSA: Sign Customer License JSON blob \n");
    ret = ovsa_safe_malloc(cust_lic_size, &customer_lic_sig_string);
    if (ret < OVSA_OK || customer_lic_sig_string == NULL) {
        OVSA_DBG(DBG_E,
                 "OVSA: Error customer license signature buffer allocation failed with code %d\n",
                 ret);
        goto out;
    }

    /* Computes HMAC for customer license */
    ret = ovsa_crypto_hmac_json_blob(keyiv_hmac_slot, customer_lic_string, cust_lic_size,
                                     customer_lic_sig_string);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error customer license signing failed with error code %d\n", ret);
        goto out;
    }

    /* Store customer license JSON blob on specified output file */
    OVSA_DBG(DBG_I, "OVSA: Store Customer License JSON blob\n");
    if (customer_lic_sig_string != NULL) {
        if ((fptr = fopen(updated_customer_lic_file, "w+")) != NULL) {
            ret = ovsa_get_string_length(customer_lic_sig_string, &size);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "OVSA: Error could not get length of signature string %d\n", ret);
                fclose(fptr);
                goto out;
            }
            fwrite(customer_lic_sig_string, size, 1, fptr);
            fclose(fptr);
            OVSA_DBG(DBG_I, "OVSA: Customer license file %s generated successfully\n",
                     updated_customer_lic_file);
        } else {
            ret = OVSA_FILEOPEN_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Error create file %s failed with error code %d\n",
                     updated_customer_lic_file, ret);
            goto out;
        }
    }

out:
    /* clear key/IV/HMAC from the key slot */
    ovsa_crypto_clear_symmetric_key_slot(keyiv_hmac_slot);
    /* clear shared key from the key slot */
    ovsa_crypto_clear_symmetric_key_slot(shared_key_slot);
    /* De-initialize crypto */
    ovsa_crypto_deinit();
    ovsa_safe_free(&cust_lic_buf);
    ovsa_safe_free(&cust_lic_sig_buf);
    ovsa_safe_free(&customer_lic_string);
    ovsa_safe_free(&customer_lic_sig_string);
    ovsa_safe_free(&isv_certificate);
    ovsa_safe_free(&peer_cert);
    ovsa_safe_free(&customer_license.customer_lic.isv_certificate);
    ovsa_safe_free_input_url_list(&list_head);
    ovsa_safe_free_url_list(&customer_license.customer_lic.license_url_list);
    ovsa_safe_free_tcb_list(&customer_license.customer_lic.tcb_signatures);
    OVSA_DBG(DBG_D, "%s exit\n", __func__);
    return ret;
}
