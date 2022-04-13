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

#include "libovsa.h"
#include "ovsa_tool.h"
#include "safe_mem_lib.h"
#include "safe_str_lib.h"
#include "utils.h"
/* json.h to be included at end due to dependencies */
#include "json.h"

static void ovsa_licgen_help(const char* argv) {
    printf("Help for Licgen command\n");
    printf("-t : Type of license (Sale / InstanceLimit / TimeLimit)\n");
    printf("-l : License limit\n");
    printf("-n : License name\n");
    printf("-v : License version number\n");
    printf("-u : ISV license server URL, current certificate file, future certificate file\n");
    printf("-k : Keystore name\n");
    printf("-o : Output file to store license config data\n");
    printf("Example for Licgen as below:\n");
    printf(
        "%s licgen -t <License Type> [-l <Usage Count Limit> or <Time Limit>] -n \"License "
        "name\" -v \"License Version\" -u <License URL> <Certificate file> [<Future certificate "
        "file>] [-u <License URL> <Certificate file> [<Future certificate file>]] -k <key store "
        "file> -o <lic conf file>\n\n",
        argv);
    printf(
        "%s licgen -t Sale -n \"Full unlimited license\" -v 0001 -u "
        "\"14650@192.166.248.2\"url_cert.crt -k key_store -o license_conf\n",
        argv);
    printf(
        "%s licgen -t InstanceLimit -l 10 -n \"Instance limited license\" -v 0001 -u "
        "\"14650@192.166.248.2\" url_cert.crt future_cert.crt -k key_store -o license_conf\n",
        argv);
    printf(
        "%s licgen -t TimeLimit -l 30 -n \"Time bound license\" -v 0001 -u "
        "\"14650@192.166.248.2\" url_cert.crt -k key_store -o license_conf\n",
        argv);
}

ovsa_status_t ovsa_licgen_main(int argc, char* argv[]) {
    ovsa_status_t ret            = OVSA_OK;
    int asymm_keyslot            = -1;
    int c                        = 0;
    int i                        = 0;
    int usage_limit              = -1;
    size_t lic_buf_size          = 0;
    size_t lic_sig_buf_size      = 0;
    size_t list_count            = 0;
    size_t cert_len              = 0;
    size_t argv_len              = 0;
    ovsa_license_type_t lic_type = MAXLICENSETYPE;
    ovsa_license_config_sig_t license_info;
    license_info.lic_config.isv_certificate     = NULL;
    ovsa_input_url_list_t* list_head            = NULL;
    ovsa_input_url_list_t* list_tail            = NULL;
    ovsa_license_serv_url_list_t* url_list_head = NULL;
    ovsa_license_serv_url_list_t* url_list_tail = NULL;
    char* lic_name                              = NULL;
    char* lic_version                           = NULL;
    char* keystore                              = NULL;
    char* licconf_file                          = NULL;
    char* lic_buf_string                        = NULL;
    char* lic_buf_sig_string                    = NULL;
    FILE* fptr                                  = NULL;

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
                     "OVSA: Error licgen argument'%s' greater than %ld characters not allowed \n",
                     argv[i], RSIZE_MAX_STR);
            ret = OVSA_INVALID_PARAMETER;
            goto out;
        }
    }

    while ((c = getopt(argc, argv, "t:l:n:v:u:k:o:h")) != -1) {
        switch (c) {
            case 't': {
                lic_type = ovsa_json_map_license_type(optarg);
                if (lic_type == MAXLICENSETYPE) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Wrong command given."
                             " Please follow -help for help option\n");
                    ret = OVSA_INVALID_PARAMETER;
                    goto out;
                }
                OVSA_DBG(DBG_D, "LicGen: license_type = %d\n", lic_type);
            } break;
            case 'n': {
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_NAME_SIZE) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Error license name greater than %d characters not allowed \n",
                             MAX_NAME_SIZE);
                    ret = OVSA_INVALID_PARAMETER;
                    goto out;
                }
                lic_name = optarg;
                OVSA_DBG(DBG_D, "LicGen: license_name = %s\n", lic_name);
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
                                        memcpy_s(list_tail->cur_cert_file, MAX_FILE_NAME,
                                                 argv[index],
                                                 strnlen_s(argv[index], MAX_FILE_NAME));
                                        OVSA_DBG(DBG_D, "OVSA:cur_cert_file is %s\n",
                                                 list_tail->cur_cert_file);
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
                                goto out;
                            }
                            index++;
                        } else {
                            OVSA_DBG(DBG_E, "OVSA: Error URL not specified\n");
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
            case 'v': {
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_VERSION_SIZE) {
                    OVSA_DBG(DBG_E,
                             "OVSA: License version greater than %d characters not allowed \n",
                             MAX_VERSION_SIZE);
                    ret = OVSA_INVALID_FILE_PATH;
                    goto out;
                }
                lic_version = optarg;
                OVSA_DBG(DBG_D, "LicGen: license_version = %s\n", lic_version);
            } break;
            case 'k': {
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_FILE_NAME) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Keystore file path greater than %d characters not allowed \n",
                             MAX_FILE_NAME);
                    ret = OVSA_INVALID_FILE_PATH;
                    goto out;
                }
                keystore = optarg;
                OVSA_DBG(DBG_D, "LicGen: keystore= %s\n", keystore);
            } break;
            case 'o': {
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_FILE_NAME) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Output file path greater than %d characters not allowed \n",
                             MAX_FILE_NAME);
                    ret = OVSA_INVALID_FILE_PATH;
                    goto out;
                }
                licconf_file = optarg;
                OVSA_DBG(DBG_D, "LicGen: licenseconf_file = %s\n", licconf_file);
            } break;
            case 'l': {
                if (isdigit((int)(unsigned char)*optarg)) {
                    usage_limit = atoi(optarg);
                    OVSA_DBG(DBG_D, "LicGen: usage_limit = %d\n", usage_limit);
                    if (usage_limit <= 0) {
                        OVSA_DBG(DBG_E,
                                 "OVSA: Usage limit should be greater than zero."
                                 " Please follow -help for help option\n");
                        ret = OVSA_INVALID_PARAMETER;
                        goto out;
                    }
                } else {
                    OVSA_DBG(DBG_E,
                             "OVSA: Usage limit should be a positive integer."
                             " Please follow -help for help option\n");
                    ret = OVSA_INVALID_PARAMETER;
                    goto out;
                }
            } break;
            case 'h': {
                ovsa_licgen_help(argv[0]);
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

    /* Set input values license configuration structure */
    if ((lic_name != NULL) && (list_head != NULL) && (lic_version != NULL) &&
        (lic_type != MAXLICENSETYPE) && (licconf_file != NULL) && (keystore != NULL)) {
        /* Initialize crypto */
        ret = ovsa_crypto_init();
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error ovsa crypto init failed with code %d\n", ret);
            goto out;
        }

        memset_s(&license_info, sizeof(ovsa_license_config_sig_t), 0);
        license_info.lic_config.license_type = lic_type;

        if ((license_info.lic_config.license_type != SALE) && (usage_limit <= 0)) {
            OVSA_DBG(DBG_E,
                     "OVSA: Error invalid usage limit. Please follow -help for help option\n");
            ret = OVSA_INVALID_PARAMETER;
            goto out;
        }

        if (license_info.lic_config.license_type == INSTANCELIMIT) {
            license_info.lic_config.usage_count = usage_limit;
            license_info.lic_config.time_limit  = 0;
        } else if (license_info.lic_config.license_type == TIMELIMIT) {
            license_info.lic_config.time_limit  = usage_limit;
            license_info.lic_config.usage_count = 0;
        } else {
            license_info.lic_config.time_limit  = 0;
            license_info.lic_config.usage_count = 0;
        }

        char cert_hash[HASH_SIZE], fut_cert_hash[HASH_SIZE];
        list_tail = list_head;
        while (list_tail != NULL) {
            ret = ovsa_store_license_url_list(list_tail->license_serv_url, &url_list_head,
                                              &url_list_tail);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "OVSA: Error load URL list failed with code %d\n", ret);
                goto out;
            }
            memset_s(cert_hash, HASH_SIZE, 0);
            ret = ovsa_generate_cert_hash(list_tail->cur_cert_file, cert_hash);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "OVSA: Error generating certificate hash with code %d\n", ret);
                goto out;
            }
            memcpy_s(url_list_tail->cur_cert_hash, HASH_SIZE, cert_hash, HASH_SIZE);

            if (list_tail->fut_cert_file[0] != '\0') {
                memset_s(fut_cert_hash, HASH_SIZE, 0);
                ret = ovsa_generate_cert_hash(list_tail->fut_cert_file, fut_cert_hash);
                if (ret < OVSA_OK) {
                    OVSA_DBG(DBG_E, "OVSA: Error generating certificate hash with code %d\n", ret);
                    goto out;
                }
                memcpy_s(url_list_tail->fut_cert_hash, HASH_SIZE, fut_cert_hash, HASH_SIZE);
            }
            list_tail = list_tail->next;
        }
        memcpy_s(license_info.lic_config.license_name, MAX_NAME_SIZE, lic_name,
                 strnlen_s(lic_name, MAX_NAME_SIZE));
        memcpy_s(license_info.lic_config.license_version, MAX_VERSION_SIZE, lic_version,
                 strnlen_s(lic_version, MAX_VERSION_SIZE));
        license_info.lic_config.license_url_list = url_list_head;
    } else {
        OVSA_DBG(DBG_E,
                 "OVSA: Error Invalid input parameters. Please follow -help for help option\n");
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

    ret = ovsa_crypto_get_certificate(asymm_keyslot, &license_info.lic_config.isv_certificate);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error license config get certificate failed with error code %d\n",
                 ret);
        goto out;
    }

    /* Create license config JSON blob */
    ret = ovsa_get_string_length(license_info.lic_config.isv_certificate, &cert_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of isv_certificate string %d\n", ret);
        goto out;
    }
    lic_buf_size =
        (sizeof(ovsa_license_config_t) + LICENSE_CONFIG_BLOB_TEXT_SIZE +
         ((sizeof(ovsa_license_serv_url_list_t) * LICENSE_URL_BLOB_TEXT_SIZE * list_count)) +
         cert_len);
    ret = ovsa_safe_malloc(lic_buf_size, &lic_buf_string);
    if (ret < OVSA_OK || lic_buf_string == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error license config buffer allocation failed with code %d\n", ret);
        goto out;
    }
    ret = ovsa_json_create_license_config(&license_info, lic_buf_size, lic_buf_string);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error create license config failed with error code %d\n", ret);
        goto out;
    }

    /* Sign license config JSON blob */
    lic_sig_buf_size = MAX_SIGNATURE_SIZE + SIGNATURE_BLOB_TEXT_SIZE + lic_buf_size;
    ret              = ovsa_safe_malloc(lic_sig_buf_size, &lic_buf_sig_string);
    if (ret < OVSA_OK || lic_buf_sig_string == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error license config signature buffer allocation failed %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA: Sign License Config JSON Blob\n");
    ret = ovsa_crypto_sign_json_blob(asymm_keyslot, lic_buf_string, lic_buf_size,
                                     lic_buf_sig_string, lic_sig_buf_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error license config signing failed with error code %d\n", ret);
        goto out;
    }

    /* Store license config JSON blob on specified output file */
    if (lic_buf_sig_string != NULL) {
        OVSA_DBG(DBG_D, "OVSA: licbuf %s\n\n", lic_buf_sig_string);
        if ((fptr = fopen(licconf_file, "w+")) != NULL) {
            ret = ovsa_get_string_length(lic_buf_sig_string, &lic_sig_buf_size);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "OVSA: Error could not get length of isv_certificate string %d\n",
                         ret);
                fclose(fptr);
                goto out;
            }
            fwrite(lic_buf_sig_string, lic_sig_buf_size, 1, fptr);
            fclose(fptr);
            OVSA_DBG(DBG_I, "OVSA: License config file %s generated successfully\n", licconf_file);
        } else {
            ret = OVSA_FILEOPEN_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Error create file %s failed with error code %d\n", licconf_file,
                     ret);
            goto out;
        }
    }

    /* De-initialize crypto */
    ovsa_crypto_deinit();

out:
    ovsa_safe_free(&lic_buf_string);
    ovsa_safe_free(&lic_buf_sig_string);
    ovsa_safe_free(&license_info.lic_config.isv_certificate);
    ovsa_safe_free_input_url_list(&list_head);
    ovsa_safe_free_url_list(&url_list_head);
    OVSA_DBG(DBG_D, "%s exit\n", __func__);
    return ret;
}
