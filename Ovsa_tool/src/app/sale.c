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

static void ovsa_sale_help(const char* argv) {
    printf("Help for Sale command\n");
    printf("-m : Master license file\n");
    printf("-k : Keystore name\n");
    printf("-l : License config file\n");
    printf("-t : List of TCB signature files\n");
    printf("-p : Customer certificate\n");
    printf("-c : Customer license\n");
    printf("Example for sale as below:\n");
    printf(
        "-m <Master license file> -k <key store file> -l <license conf file> -t <  list of TCB "
        "Signature files  > -p <Customer Certificate> -c <Customer license>\n\n");
    printf(
        "%s sale -m face_detection_model_master.lic -k key_store.json -l license_conf.json "
        "-t tcb1.sig tcb2.sig -p customer_cert.crl -c face_detection_model_customer.lic\"\n",
        argv);
}

static int ovsa_get_list_file_count(ovsa_license_serv_url_list_t* url_list) {
    ovsa_license_serv_url_list_t* furl = url_list;
    int count                          = 0;
    while (furl != NULL) {
        count++;
        furl = furl->next;
    }
    return count;
}

static ovsa_status_t ovsa_check_is_master_license_expired(const char* master_lic_time_str,
                                                          int req_lic_days) {
    /* Get the current time in UTC */
    time_t max_master_lic_time, current_time;
    struct tm max_master_lic_tm, *current_time_tm = NULL;
    int elapsedtime = 0;

    if (ovsa_get_current_time(&current_time, &current_time_tm) != OVSA_OK)
        return OVSA_TIME_SYSTIME_ERROR;

    memset_s(&max_master_lic_tm, sizeof(struct tm), 0);
    /* Convert master license creation time in time_t format by adding MAX Model validity period */
    strptime(master_lic_time_str, "%a %b %d %H:%M:%S %Y", &max_master_lic_tm);
    max_master_lic_tm.tm_year += MAX_CONTROLLED_ACCESS_MODEL_VALIDITY_TIME_PERIOD;
    max_master_lic_time = mktime(&max_master_lic_tm);
    OVSA_DBG(DBG_D, "OVSA: master license req time: %s", asctime(&max_master_lic_tm));

    /* If current time exceeds updated master license time, it indicates license expired */
    elapsedtime = difftime(current_time, max_master_lic_time);
    if (elapsedtime > 0) {
        OVSA_DBG(
            DBG_E,
            "ERROR: Master license has expired. Please regenerate Master license to continue.\n");
        return OVSA_TIME_LICEXPIRED_ERROR;
    }

    /* Age of model + Requested license duration should not exceed license validity */
    current_time_tm->tm_mday += req_lic_days;
    current_time = mktime(current_time_tm);
    OVSA_DBG(DBG_D, "OVSA: Current date + license req time: %s", asctime(current_time_tm));

    elapsedtime = difftime(current_time, max_master_lic_time);
    if (elapsedtime > 0) {
        int days = TIMECONVERT_SECSTODAYS(elapsedtime); /* Convert seconds to days */
        OVSA_DBG(DBG_E,
                 "ERROR: Requested license duration %d days exceeds Master license validity."
                 " Please request license for less than %d days\n",
                 req_lic_days, req_lic_days - days);
        return OVSA_TIME_DURATIONEXCEEDS_ERROR;
    }
    return OVSA_OK;
}

static ovsa_status_t ovsa_check_cert_validity(const char* isv_cert, const char* cust_cert,
                                              int req_lic_days) {
    char isv_cert_issue_date[MAX_DATE_TIME_SIZE];
    char customer_cert_issue_date[MAX_DATE_TIME_SIZE];
    char isv_cert_end_date[MAX_DATE_TIME_SIZE];
    char customer_cert_end_date[MAX_DATE_TIME_SIZE];
    ovsa_status_t ret = OVSA_OK;

    time_t current_time, isv_cert_time, customer_cert_time;
    struct tm *current_time_tm, isv_cert_tm, customer_cert_tm;
    int elapsedtime = 0;

    memset_s(&customer_cert_tm, sizeof(struct tm), 0);
    memset_s(&isv_cert_tm, sizeof(struct tm), 0);
    memset_s(isv_cert_issue_date, sizeof(isv_cert_issue_date), 0);
    memset_s(customer_cert_issue_date, sizeof(customer_cert_issue_date), 0);
    memset_s(isv_cert_end_date, sizeof(isv_cert_end_date), 0);
    memset_s(customer_cert_end_date, sizeof(customer_cert_end_date), 0);

    ret = ovsa_crypto_extract_cert_date(isv_cert, isv_cert_issue_date, isv_cert_end_date);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "ERROR: Could not extract start and end date from ISV certificate\n");
        return ret;
    }
    ret =
        ovsa_crypto_extract_cert_date(cust_cert, customer_cert_issue_date, customer_cert_end_date);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "ERROR: Could not extract start and end date from customer certificate\n");
        return ret;
    }

    ret = ovsa_get_current_time(&current_time, &current_time_tm);
    if (ret != OVSA_OK) {
        return ret;
    }

    /* Check requested duration is with in Certificate validity */
    current_time_tm->tm_mday += req_lic_days;
    current_time = mktime(current_time_tm);
    OVSA_DBG(DBG_D, "OVSA: Current date + license req time: %s", asctime(current_time_tm));

    /* Check ISV Certificate validity */
    strptime(isv_cert_issue_date, "%b %d %H:%M:%S %Y", &isv_cert_tm);
    isv_cert_tm.tm_mon += MAX_CERT_VALIDITY_PERIOD;
    isv_cert_time = mktime(&isv_cert_tm);

    OVSA_DBG(DBG_I, "OVSA: ISV Certificte validity expires on: %s", asctime(&isv_cert_tm));

    elapsedtime = difftime(current_time, isv_cert_time);
    if (elapsedtime > 0) {
        int days = TIMECONVERT_SECSTODAYS(elapsedtime); /* Convert seconds to days */
        OVSA_DBG(
            DBG_E,
            "ERROR: ISV Certificate with requested license of %d days exceeds MAX certificate limit"
            " Please request license for less than %d days\n",
            req_lic_days, req_lic_days - days);
        return OVSA_TIME_DURATIONEXCEEDS_ERROR;
    }

    /* Check Customer Certificate validity */
    strptime(customer_cert_issue_date, "%b %d %H:%M:%S %Y", &customer_cert_tm);
    customer_cert_tm.tm_mon += MAX_CERT_VALIDITY_PERIOD;
    customer_cert_time = mktime(&customer_cert_tm);

    OVSA_DBG(DBG_I, "OVSA: Customer Certificate validity time expires on : %s",
             asctime(&customer_cert_tm));

    elapsedtime = difftime(current_time, customer_cert_time);
    if (elapsedtime > 0) {
        int days = TIMECONVERT_SECSTODAYS(elapsedtime); /* Convert seconds to days */
        OVSA_DBG(DBG_E,
                 "ERROR: Customer Certificate with requested license of %d days exceeds MAX "
                 "certificate limit."
                 " Please request license for less than %d days\n",
                 req_lic_days, req_lic_days - days);
        return OVSA_TIME_DURATIONEXCEEDS_ERROR;
    }
    return OVSA_OK;
}

static ovsa_status_t ovsa_verify_artefacts(int asymm_keyslot, const char* input_file,
                                           ovsa_hash_alg_t hash_type, char** output_sig_buf) {
    ovsa_status_t ret    = OVSA_OK;
    char* sig_buf        = NULL;
    char* file_buf       = NULL;
    char* encryption_key = NULL;
    FILE* fptr           = NULL;
    size_t size          = 0;
    int shared_key_slot  = -1;
    int keyiv_hmac_slot  = -1;

    if ((asymm_keyslot < MIN_KEY_SLOT) || (asymm_keyslot >= MAX_KEY_SLOT) || input_file == NULL) {
        ret = OVSA_INVALID_PARAMETER;
        OVSA_DBG(DBG_E, "OVSA: Error wrong input parameters to verify file\n");
        return ret;
    }

    OVSA_DBG(DBG_I, "OVSA: Verify file %s\n", input_file);
    fptr = fopen(input_file, "r");
    if (fptr == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error opening file %s failed with code %d\n", input_file, ret);
        goto out;
    }
    size = ovsa_crypto_get_file_size(fptr);
    ret  = ovsa_safe_malloc(size, &sig_buf);
    if (ret < OVSA_OK || sig_buf == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error buffer allocation failed with code %d\n", ret);
        fclose(fptr);
        goto out;
    }
    ret               = fread(sig_buf, 1, size, fptr);
    sig_buf[size - 1] = '\0';
    fclose(fptr);

    ret = ovsa_safe_malloc(size, &file_buf);
    if (ret < OVSA_OK || file_buf == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error buffer allocation failed with code %d\n", ret);
        ovsa_safe_free(&sig_buf);
        goto out;
    }

    if (hash_type == SIGN_VERIFY) {
        ret = ovsa_crypto_verify_json_blob(asymm_keyslot, sig_buf, size, file_buf);
    } else {
        /* Extract encryption_key from master license */
        ret = ovsa_json_extract_element(sig_buf, "encryption_key", (void**)&encryption_key);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error extract json element failed with error code %d\n", ret);
            goto out;
        }

        /* Compute shared key using ISV's secondary private key and ISV primary public key */
        ret = ovsa_crypto_create_ecdh_key(asymm_keyslot + 1, asymm_keyslot, &shared_key_slot);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error generating shared key failed with error code %d\n", ret);
            goto out;
        }

        /* Extract salt from encryption_key and derive key/IV/HMAC for master license */
        ret = ovsa_crypto_derive_keyiv_hmac(shared_key_slot, encryption_key,
                                            strnlen_s(encryption_key, MAX_EKEY_SIZE),
                                            &keyiv_hmac_slot);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error deriving key/IV/HAMC failed with error code %d\n", ret);
            goto out;
        }

        /* Verifies the HMAC for master license */
        ret = ovsa_crypto_verify_hmac_json_blob(keyiv_hmac_slot, sig_buf, size, file_buf);
    }
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error verify json failed with error code %d\n", ret);
        goto out;
    }
    *output_sig_buf = sig_buf;
    OVSA_DBG(DBG_I, "OVSA: %s file verified successfully\n", input_file);

out:
    if (hash_type == HMAC_VERIFY) {
        /* Clear key/IV/HMAC from the key slot */
        ovsa_crypto_clear_symmetric_key_slot(keyiv_hmac_slot);
        /* Clear shared key from the key slot */
        ovsa_crypto_clear_symmetric_key_slot(shared_key_slot);
    }
    ovsa_safe_free(&encryption_key);
    ovsa_safe_free(&file_buf);
    return ret;
}

ovsa_status_t ovsa_sale_main(int argc, char* argv[]) {
    ovsa_status_t ret                 = OVSA_OK;
    int asymm_keyslot                 = -1;
    int peer_slot                     = -1;
    int keyiv_hmac_slot               = -1;
    int c                             = 0;
    int file_count                    = 0;
    int tcb_signature_size            = 0;
    int url_file_count                = 0;
    int i                             = 0;
    size_t argv_len                   = 0;
    size_t outlen                     = 0;
    size_t size                       = 0;
    size_t cert_size                  = 0;
    size_t cust_lic_size              = 0;
    ovsa_input_files_t* tcb_list_head = NULL;
    char* keystore                    = NULL;
    char* lic_cnf_file                = NULL;
    char* customer_cert_file          = NULL;
    char* isv_certificate             = NULL;
    char* customer_lic_file           = NULL;
    char* masterlic_file              = NULL;
    char* cert_buff                   = NULL;
    char* customer_lic_sig_string     = NULL;
    char* customer_lic_string         = NULL;
    char* lic_cnf_sig_buf             = NULL;
    char* lic_cnf_buf                 = NULL;
    char* master_lic_sig_buf          = NULL;
    char* master_lic_buf              = NULL;
    char* tcb_sig_buf                 = NULL;
    time_t today                      = time(NULL);
    char* time_str                    = NULL;
    char* enc_key                     = NULL;
    ovsa_tcb_sig_list_t* tcb_list     = NULL;
    ovsa_customer_license_sig_t customer_license;
    ovsa_license_config_sig_t lic_conf_sig;
    ovsa_master_license_sig_t master_lic_sig;

    memset_s(&master_lic_sig, sizeof(ovsa_master_license_sig_t), 0);
    memset_s(&lic_conf_sig, sizeof(ovsa_license_config_sig_t), 0);
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
                     "OVSA: Error sale argument'%s' greater than %ld characters not allowed \n",
                     argv[i], RSIZE_MAX_STR);
            ret = OVSA_INVALID_PARAMETER;
            goto out;
        }
    }

    while ((c = getopt(argc, argv, "m:k:l:t:p:c:h")) != -1) {
        switch (c) {
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
                    OVSA_DBG(
                        DBG_E,
                        "OVSA: License config file path greater than %d characters not allowed \n",
                        MAX_FILE_NAME);
                    ret = OVSA_INVALID_PARAMETER;
                    goto out;
                }
                lic_cnf_file = optarg;
                OVSA_DBG(DBG_D, "OVSA: lic_cnf_file = %s\n", lic_cnf_file);
            } break;
            case 't': {
                int index;
                ovsa_input_files_t* tcb_list_tail = NULL;
                index                             = optind - 1;
                while (index < argc) {
                    if (strnlen_s(argv[index], RSIZE_MAX_STR) < MAX_FILE_NAME) {
                        if (argv[index][0] != '-') {
                            ret = ovsa_store_input_file_list(argv[index], &tcb_list_head,
                                                             &tcb_list_tail);
                            if (ret < OVSA_OK) {
                                OVSA_DBG(DBG_E,
                                         "OVSA: Error store TCB file list failed with code %d\n",
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
                                 MAX_FILE_NAME);
                        ret = OVSA_INVALID_PARAMETER;
                        goto out;
                    }
                }
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
                customer_lic_file = optarg;
                OVSA_DBG(DBG_D, "OVSA: customer_lic_file = %s\n", customer_lic_file);
            } break;
            case 'h': {
                ovsa_sale_help(argv[0]);
                goto out;
            }
            default: {
                OVSA_DBG(DBG_E,
                         "OVSA: Error wrong command given. Please follow -help for help option "
                         "c = %d\n",
                         c);
                ret = OVSA_INVALID_PARAMETER;
                goto out;
            }
        }
    }

    /* optind is for the extra arguments which are not parsed */
    for (; optind < argc; optind++) {
        OVSA_DBG(DBG_I, "extra arguments: %s\n", argv[optind]);
    }

    if ((masterlic_file == NULL) || (keystore == NULL) || (lic_cnf_file == NULL) ||
        (tcb_list_head == NULL) || (customer_cert_file == NULL) || (customer_lic_file == NULL)) {
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
    FILE* fptr = fopen(customer_cert_file, "r");
    if (fptr == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error opening certificate file failed with code %d\n", ret);
        goto out;
    }

    /* Get length of certificate file */
    size = ovsa_crypto_get_file_size(fptr);
    ret  = ovsa_safe_malloc(size, &cert_buff);
    if (ret < OVSA_OK || cert_buff == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error certificate file buffer allocation failed with code %d\n",
                 ret);
        fclose(fptr);
        goto out;
    }
    ret = fread(cert_buff, 1, size, fptr);
    fclose(fptr);

    OVSA_DBG(DBG_I, "OVSA: Verify Input Certificate\n");

    if ((!size) || (size > MAX_CERT_SIZE)) {
        OVSA_DBG(DBG_E, "OVSA: Error customer certificate length is invalid \n");
        ret = OVSA_INVALID_PARAMETER;
        goto out;
    }
    ret = ovsa_crypto_extract_pubkey_verify_cert(/*PEER Cert*/ true, cert_buff,
                                                 /* lifetime_validity_check */ true, &peer_slot);
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

    /* Verify License config file */
    ret = ovsa_verify_artefacts(asymm_keyslot, lic_cnf_file, SIGN_VERIFY, &lic_cnf_sig_buf);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error verify certificate failed with code %d\n", ret);
        goto out;
    }

    /* Verify Master License config file */
    ret = ovsa_verify_artefacts(asymm_keyslot, masterlic_file, HMAC_VERIFY, &master_lic_sig_buf);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error verify certificate failed with code %d\n", ret);
        goto out;
    }

    ovsa_tcb_sig_list_t* tcb_cur_list  = NULL;
    ovsa_tcb_sig_list_t* tcb_tail_list = NULL;
    ovsa_input_files_t* tcb_file       = tcb_list_head;
    file_count                         = 0;
    tcb_signature_size                 = 0;
    while (tcb_file != NULL) {
        /* Verify TCB Signature file */
        ret = ovsa_verify_artefacts(asymm_keyslot, tcb_file->name, SIGN_VERIFY, &tcb_sig_buf);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error verify certificate failed with code %d\n", ret);
            goto out;
        }

        ret = ovsa_get_string_length(tcb_sig_buf, &size);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error could not get length of tcb_sig_buf string %d\n", ret);
            goto out;
        }
        if (tcb_list == NULL) {
            ret = ovsa_safe_malloc(sizeof(ovsa_tcb_sig_list_t), (char**)&tcb_list);
            if (ret < OVSA_OK || tcb_list == NULL) {
                OVSA_DBG(DBG_E, "OVSA: Error init encoded list failed %d\n", ret);
                goto out;
            }
            tcb_list->next = NULL;
            tcb_tail_list  = tcb_list;
        } else {
            ret = ovsa_safe_malloc(sizeof(ovsa_tcb_sig_list_t), (char**)&tcb_cur_list);
            if (ret < OVSA_OK || tcb_cur_list == NULL) {
                OVSA_DBG(DBG_E, "OVSA: Error init encoded list failed %d\n", ret);
                goto out;
            }
            tcb_cur_list->next  = NULL;
            tcb_tail_list->next = tcb_cur_list;
            tcb_tail_list       = tcb_cur_list;
        }
        ret = ovsa_safe_malloc(size + 1, &tcb_tail_list->tcb_signature);
        if (ret < OVSA_OK || tcb_tail_list->tcb_signature == NULL) {
            OVSA_DBG(DBG_E, "OVSA: Error init encoded list failed %d\n", ret);
            goto out;
        }
        memcpy_s(tcb_tail_list->tcb_signature, size, tcb_sig_buf, size);
        tcb_file = tcb_file->next;
        file_count++;
        tcb_signature_size += size;
        ovsa_safe_free(&tcb_sig_buf);
        tcb_sig_buf = NULL;
    }
    customer_license.customer_lic.tcb_signatures = tcb_list;
    /* Extract License config */
    OVSA_DBG(DBG_I, "OVSA: Extract License Config\n");
    ret = ovsa_json_extract_license_config(lic_cnf_sig_buf, &lic_conf_sig);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error extract license config failed with error code %d\n", ret);
        goto out;
    }

    /* Extract Master license */
    OVSA_DBG(DBG_I, "OVSA: Extract Master License\n");
    ret = ovsa_json_extract_master_license(master_lic_sig_buf, &master_lic_sig);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error extract master license failed with error code %d\n", ret);
        goto out;
    }

    int req_lic_days = lic_conf_sig.lic_config.time_limit;
    if (req_lic_days > 0) {
        /*
         * Validate Master License
         * Step #1: Check Model encryption time has not expired
         * Step #2: Requested license duration should not exceed license validity
         */
        ret = ovsa_check_is_master_license_expired(master_lic_sig.master_lic.creation_date,
                                                   req_lic_days);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error master license time check failed with error code %d\n",
                     ret);
            goto out;
        }
        /*
         * Step #3: ISV & Customer cert + Requested license duration should not exceed license
         * validity
         */
        ret = ovsa_check_cert_validity(isv_certificate, cert_buff, req_lic_days);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error master license validity check failed with error code %d\n",
                     ret);
            goto out;
        }
        OVSA_DBG(DBG_I, "OVSA: Approved Model license duration is %d days\n", req_lic_days);
    }

    /* Rewrap Key */
    OVSA_DBG(DBG_I, "OVSA: Rewrap encryption key with customer certificate\n");
    ret = ovsa_crypto_rewrap_key(asymm_keyslot, peer_slot, master_lic_sig.master_lic.encryption_key,
                                 strnlen_s(master_lic_sig.master_lic.encryption_key, MAX_EKEY_SIZE),
                                 &enc_key, &outlen, &keyiv_hmac_slot);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error master license wrapkey failed with error code %d\n", ret);
        goto out;
    }
    memcpy_s(customer_license.customer_lic.encryption_key, MAX_EKEY_SIZE, enc_key,
             strnlen_s(enc_key, MAX_EKEY_SIZE));

    /* Set creation date and time */
    time_str           = ctime(&today);
    size               = strnlen_s(time_str, MAX_NAME_SIZE);
    time_str[size - 1] = '\0';
    memcpy_s(customer_license.customer_lic.creation_date, MAX_NAME_SIZE, time_str, size);

    /* Set all values of Customer License from master license */
    ret = ovsa_get_string_length(master_lic_sig.master_lic.isv_certificate, &cert_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of isv_certificate string %d\n", ret);
        goto out;
    }
    ret = ovsa_safe_malloc(cert_size + 1, &customer_license.customer_lic.isv_certificate);
    if (ret < OVSA_OK || customer_license.customer_lic.isv_certificate == NULL) {
        OVSA_DBG(DBG_E,
                 "OVSA: Error customer license isv certificate allocation failed with code %d\n",
                 ret);
        goto out;
    }
    memcpy_s(customer_license.customer_lic.isv_certificate, cert_size,
             master_lic_sig.master_lic.isv_certificate, cert_size);
    customer_license.customer_lic.isv_certificate[cert_size - 1] = '\0';
    memcpy_s(customer_license.customer_lic.model_hash, HASH_SIZE,
             master_lic_sig.master_lic.model_hash,
             strnlen_s(master_lic_sig.master_lic.model_hash, HASH_SIZE));
    memcpy_s(customer_license.customer_lic.model_guid, GUID_SIZE,
             master_lic_sig.master_lic.model_guid,
             strnlen_s(master_lic_sig.master_lic.model_guid, GUID_SIZE));
    memcpy_s(customer_license.customer_lic.license_guid, GUID_SIZE,
             master_lic_sig.master_lic.license_guid,
             strnlen_s(master_lic_sig.master_lic.license_guid, GUID_SIZE));

    /* Set all values of Customer License from license config */
    memcpy_s(customer_license.customer_lic.license_name, MAX_NAME_SIZE,
             lic_conf_sig.lic_config.license_name,
             strnlen_s(lic_conf_sig.lic_config.license_name, MAX_NAME_SIZE));
    memcpy_s(customer_license.customer_lic.license_version, MAX_VERSION_SIZE,
             lic_conf_sig.lic_config.license_version,
             strnlen_s(lic_conf_sig.lic_config.license_version, MAX_VERSION_SIZE));
    customer_license.customer_lic.license_type     = lic_conf_sig.lic_config.license_type;
    customer_license.customer_lic.usage_count      = lic_conf_sig.lic_config.usage_count;
    customer_license.customer_lic.time_limit       = lic_conf_sig.lic_config.time_limit;
    customer_license.customer_lic.license_url_list = lic_conf_sig.lic_config.license_url_list;

    /* Find the file count for license URL */
    url_file_count = ovsa_get_list_file_count(lic_conf_sig.lic_config.license_url_list);

    /* Create customer license JSON blob */
    OVSA_DBG(DBG_I, "OVSA: Create Customer License blob\n");
    cust_lic_size =
        sizeof(ovsa_customer_license_t) + (cert_size + 1) + CUSTOMER_LICENSE_BLOB_TEXT_SIZE +
        (file_count * TCB_NAME_BLOB_TEXT_SIZE) + tcb_signature_size +
        (url_file_count * (LICENSE_URL_BLOB_TEXT_SIZE + sizeof(ovsa_license_serv_url_list_t)));

    ret = ovsa_safe_malloc(cust_lic_size, &customer_lic_string);
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
    OVSA_DBG(DBG_I, "OVSA: Sign Customer License JSON blob\n");
    size = MAX_SIGNATURE_SIZE + SIGNATURE_BLOB_TEXT_SIZE + cust_lic_size;
    ret  = ovsa_safe_malloc(size, &customer_lic_sig_string);
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
        if ((fptr = fopen(customer_lic_file, "w+")) != NULL) {
            ret = ovsa_get_string_length(customer_lic_sig_string, &size);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "OVSA: Error could not get length of signature string %d\n", ret);
                fclose(fptr);
                goto out;
            }
            fwrite(customer_lic_sig_string, size, 1, fptr);
            fclose(fptr);
            OVSA_DBG(DBG_I, "OVSA: Customer license file %s generated successfully\n",
                     customer_lic_file);
        } else {
            ret = OVSA_FILEOPEN_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Error create file %s failed with error code %d\n",
                     customer_lic_file, ret);
            goto out;
        }
    }

out:
    /* De-initialize crypto */
    ovsa_crypto_deinit();
    ovsa_safe_free(&cert_buff);
    ovsa_safe_free(&enc_key);
    ovsa_safe_free(&lic_cnf_sig_buf);
    ovsa_safe_free(&lic_cnf_buf);
    ovsa_safe_free(&master_lic_sig_buf);
    ovsa_safe_free(&master_lic_buf);
    ovsa_safe_free(&customer_lic_string);
    ovsa_safe_free(&tcb_sig_buf);
    ovsa_safe_free(&customer_lic_sig_string);
    ovsa_safe_free(&isv_certificate);
    ovsa_safe_free(&customer_license.customer_lic.isv_certificate);
    ovsa_safe_free(&master_lic_sig.master_lic.isv_certificate);
    ovsa_safe_free(&lic_conf_sig.lic_config.isv_certificate);
    ovsa_safe_free_url_list(&customer_license.customer_lic.license_url_list);
    ovsa_safe_free_input_list(&tcb_list_head);
    ovsa_safe_free_tcb_list(&tcb_list);
    OVSA_DBG(DBG_D, "%s exit\n", __func__);
    return ret;
}
