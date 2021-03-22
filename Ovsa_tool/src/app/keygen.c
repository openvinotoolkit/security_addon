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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libovsa.h"
#include "ovsa_tool.h"
#include "safe_str_lib.h"
#include "utils.h"
/* json.h to be included at end due to dependencies */
#include "json.h"

static void ovsa_keygen_help(const char* argv) {
    printf("Help for Keygen command\n");
    printf("-storekey: subcommand to generate key store\n");
    printf("-storecert: subcommand to store certificate to key store\n");
    printf("-getcert: subcommand to retrieve certificate from key store and store to file\n");
    printf("-sign: subcommand to sign specified input file\n");
    printf("-verify: subcommand to verify specified input file with signature\n");
    printf("-t ECDSA: Algorithm for generating Asymmetric key pair\n");
    printf("-k : Key store file path\n");
    printf("-n : Name of keystore to be stored in keystore file\n");
    printf("-r : CSR file path\n");
    printf("-e : Subject element for CSR file generation\n");
    printf("-c : Certificate file to be stored to key store / read from key store\n");
    printf("-p : Input file to be signed / verified\n");
    printf("-o : Output file to store signed\n");
    printf("-s : Signature for verification\n");
    printf("Example for Keygen as below:\n");
    printf(
        "%s keygen -storekey -t ECDSA -k Mykeystore -n \"ISVName\" -e "
        "\"/C=IN/ST=KA/O=Intel, Inc./CN=intel.com/L=Bangalore/mail=xyz@intel.com\"\n",
        argv);
    printf("%s keygen -storecert -c cert.crl -k Mykeystore \n", argv);
    printf("%s keygen -getcert -k Mykeystore -c cert.crl\n", argv);
    printf("%s keygen -sign -p input.txt -o signed.txt -k Mykeystore\n", argv);
    printf("%s keygen -verify -p input.txt -s signed.txt -k Mykeystore\n", argv);
}

static ovsa_status_t ovsa_do_cmd_verify(const char* file_to_verify, const char* signature,
                                        const char* keystore) {
    ovsa_status_t ret    = OVSA_OK;
    size_t sig_file_size = 0;
    char* sig_buf        = NULL;
    FILE* fptr           = NULL;
    int asym_keyslot     = -1;

    if ((file_to_verify != NULL) && (signature != NULL) && (keystore != NULL)) {
        /* Initialize crypto */
        ret = ovsa_crypto_init();
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error ovsa crypto init failed with code %d\n", ret);
            goto out;
        }

        /* Load asymmetric_key */
        ret = ovsa_crypto_load_asymmetric_key(keystore, &asym_keyslot);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error get keyslot failed with code %d\n", ret);
            goto exit;
        }

        /* Read the Signature file */
        fptr = fopen(signature, "r");
        if (fptr == NULL) {
            ret = OVSA_FILEOPEN_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Error opening signature file failed with code %d\n", ret);
            goto exit;
        }

        /* Get length of Signature file */
        sig_file_size = ovsa_crypto_get_file_size(fptr);
        ret           = ovsa_safe_malloc(sig_file_size, &sig_buf);
        if (ret < OVSA_OK || sig_buf == NULL) {
            OVSA_DBG(DBG_E, "OVSA: Error signature buffer allocation failed %d\n", ret);
            goto exit;
        }
        ret = fread(sig_buf, 1, sig_file_size, fptr);

        /* Verify file */
        ret = ovsa_crypto_verify_file(asym_keyslot, file_to_verify, sig_buf);
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error verification failed with code %d\n", ret);
        }
        ovsa_safe_free(&sig_buf);
    exit:
        if (fptr != NULL)
            fclose(fptr);
        /* De-initialize crypto */
        ovsa_crypto_deinit();

    } else {
        OVSA_DBG(DBG_E, "OVSA: Error wrong command given. Please follow -help for help option\n");
        ret = OVSA_INVALID_PARAMETER;
    }
out:
    return ret;
}

static ovsa_status_t ovsa_do_cmd_sign(const char* file_to_sign, const char* signed_file,
                                      const char* keystore) {
    ovsa_status_t ret = OVSA_OK;
    int asym_keyslot  = -1;

    if ((file_to_sign != NULL) && (signed_file != NULL) && (keystore != NULL)) {
        /* Initialize crypto */
        ret = ovsa_crypto_init();
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error crypto init failed with code %d\n", ret);
            goto out;
        }

        /* Load asymmetric_key */
        ret = ovsa_crypto_load_asymmetric_key(keystore, &asym_keyslot);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error get keyslot failed with code %d\n", ret);
            goto exit;
        }

        /* Sign file */
        ret = ovsa_crypto_sign_file(asym_keyslot, file_to_sign, signed_file);
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error signing failed with code %d\n", ret);
        }
    exit:
        /* De-initialize crypto */
        ovsa_crypto_deinit();
    } else {
        OVSA_DBG(DBG_E, "OVSA: Error wrong command given. Please follow -help for help option\n");
        ret = OVSA_INVALID_PARAMETER;
    }
out:
    return ret;
}

static ovsa_status_t ovsa_do_cmd_getcert(const char* keystore, const char* cert_file) {
    ovsa_status_t ret = OVSA_OK;
    int asym_keyslot  = -1;

    if ((keystore != NULL) && (cert_file != NULL)) {
        /* Initialize crypto */
        ret = ovsa_crypto_init();
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error crypto init failed with code %d\n", ret);
            goto out;
        }

        /* Load asymmetric_key */
        ret = ovsa_crypto_load_asymmetric_key(keystore, &asym_keyslot);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error get keyslot failed with code %d\n", ret);
            goto exit;
        }

        /* Read certificate to file */
        ret = ovsa_crypto_store_certificate_file(asym_keyslot, /* PEER CERT */ false,
                                                 /* lifetime_validity_check */ true, cert_file);
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error reading certificate file failed with code %d\n", ret);
        }
    exit:
        /* De-initialize crypto */
        ovsa_crypto_deinit();
    } else {
        OVSA_DBG(DBG_E, "OVSA: Error wrong command given. Please follow -help for help option\n");
        ret = OVSA_INVALID_PARAMETER;
    }
out:
    return ret;
}

static ovsa_status_t ovsa_do_cmd_storecert(const char* keystore, const char* cert_file) {
    ovsa_status_t ret     = OVSA_OK;
    size_t cert_file_size = 0;
    char* cert_buff       = NULL;
    int asym_keyslot      = -1;

    if ((keystore != NULL) && (cert_file != NULL)) {
        /* Initialize crypto */
        ret = ovsa_crypto_init();
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error crypto init failed with code %d\n", ret);
            goto out;
        }

        /* Load asymmetric_key */
        ret = ovsa_crypto_load_asymmetric_key(keystore, &asym_keyslot);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error get keyslot failed with code %d\n", ret);
            goto exit;
        }

        /* Read certficate from on disk file */
        FILE* fptr = fopen(cert_file, "r");
        if (fptr == NULL) {
            ret = OVSA_FILEOPEN_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Error opening certificate file failed with code %d\n", ret);
            goto exit;
        }

        /* Get length of certificate file */
        cert_file_size = ovsa_crypto_get_file_size(fptr);
        ret            = ovsa_safe_malloc(cert_file_size, &cert_buff);
        if (ret < OVSA_OK || cert_buff == NULL) {
            OVSA_DBG(DBG_E, "OVSA: Error certificate buffer allocation failed %d\n", ret);
            fclose(fptr);
            goto exit;
        }
        ret = fread(cert_buff, 1, cert_file_size, fptr);
        fclose(fptr);

        /* Verify & store certificate */
        if ((!cert_file_size) || (cert_file_size > MAX_CERT_SIZE)) {
            OVSA_DBG(DBG_E, "OVSA: Error certificate length is invalid \n");
            ret = OVSA_INVALID_PARAMETER;
            goto exit;
        }
        ret = ovsa_crypto_store_certificate_keystore(asym_keyslot, /* PEER CERT */ false, cert_buff,
                                                     /* lifetime_validity_check */ true, keystore);
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error store certificate failed with code %d\n", ret);
        }
    exit:
        /* De-initialize crypto */
        ovsa_crypto_deinit();
    } else {
        OVSA_DBG(DBG_E, "OVSA: Error wrong command given. Please follow -help for help option\n");
        ret = OVSA_INVALID_PARAMETER;
    }
out:
    ovsa_safe_free(&cert_buff);
    return ret;
}

static ovsa_status_t ovsa_do_cmd_storekey(ovsa_key_alg_t alg_type, const char* isv_name,
                                          const char* keystore, const char* csr_filename,
                                          const char* subject) {
    ovsa_status_t ret = OVSA_OK;
    int asym_keyslot  = -1;

    /* Generate asymmetric keypair */
    if ((alg_type == 0) && (isv_name != NULL) && (keystore != NULL) && (subject != NULL) &&
        (csr_filename != NULL)) {
        /* Initialize crypto */
        ret = ovsa_crypto_init();
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error crypto init failed with code %d\n", ret);
            goto out;
        }
        ret = ovsa_crypto_generate_asymmetric_key_pair(alg_type, subject, isv_name, keystore,
                                                       csr_filename, &asym_keyslot);
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error create keystore/CSR failed with code %d\n", ret);
        }

        /* De-initialize crypto */
        ovsa_crypto_deinit();
    } else {
        OVSA_DBG(DBG_E, "OVSA: Error wrong command given. Please follow -help for help option\n");
        ret = OVSA_INVALID_PARAMETER;
        goto out;
    }
out:
    return ret;
}

static ovsa_keygen_cmd_t ovsa_get_keygen_cmd(const char* command) {
    ovsa_keygen_cmd_t opcode = INVALID_CMD;

    optind++;

    if (!strcmp(command, "-storekey"))
        opcode = STOREKEY;
    else if (!strcmp(command, "-storecert"))
        opcode = STORECERT;
    else if (!strcmp(command, "-getcert"))
        opcode = GETCERT;
    else if (!strcmp(command, "-sign"))
        opcode = SIGN;
    else if (!strcmp(command, "-verify"))
        opcode = VERIFY;
    else if (!strcmp(command, "-help"))
        opcode = HELP;

    return opcode;
}

ovsa_status_t ovsa_keygen_main(int argc, char* argv[]) {
    ovsa_status_t ret        = OVSA_OK;
    int c                    = 0;
    int i                    = 0;
    size_t argv_len          = 0;
    ovsa_key_alg_t alg_type  = INVALID_ALGO;
    ovsa_keygen_cmd_t opcode = INVALID_CMD;
    char* isv_name           = NULL;
    char* keystore           = NULL;
    char* subject            = NULL;
    char* cert_file          = NULL;
    char* input_file         = NULL;
    char* signed_file        = NULL;
    char* signature          = NULL;
    char* csr_filename       = NULL;

    OVSA_DBG(DBG_D, "%s entry\n", __func__);
    if (argc < 3 || argc > MAX_SAFE_ARGC) {
        OVSA_DBG(DBG_E, "OVSA: Wrong command given. Please follow -help for help option\n");
        ret = OVSA_INVALID_PARAMETER;
        goto out;
    }

    for (i = 0; argc > i; i++) {
        ret = ovsa_get_string_length(argv[i], &argv_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error could not get length of argv string %d\n", ret);
            goto out;
        }
        if (argv_len > RSIZE_MAX_STR) {
            OVSA_DBG(DBG_E, "OVSA: keygen argument'%s' greater than %ld characters not allowed \n",
                     argv[i], RSIZE_MAX_STR);
            ret = OVSA_INVALID_PARAMETER;
            goto out;
        }
    }

    opcode = ovsa_get_keygen_cmd(argv[2]);

    while ((c = getopt(argc, argv, "ht:n:k:e:c:o:p:s:r:")) != -1) {
        switch (c) {
            case 't':
                if (strcmp("ECDSA", optarg)) {
                    OVSA_DBG(DBG_I, "Info: Unsupported Algorithm: %s\n", optarg);
                    OVSA_DBG(DBG_I, "Defaulting to ECDSA\n");
                }
                alg_type = ECDSA;
                break;
            case 'n':
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_NAME_SIZE) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Error keystore name greater than %d characters not allowed \n",
                             MAX_NAME_SIZE);
                    ret = OVSA_INVALID_FILE_PATH;
                    goto out;
                }
                isv_name = optarg;
                break;
            case 'k':
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_FILE_NAME) {
                    OVSA_DBG(
                        DBG_E,
                        "OVSA: Error keystore file name greater than %d characters not allowed \n",
                        MAX_FILE_NAME);
                    ret = OVSA_INVALID_FILE_PATH;
                    goto out;
                }
                keystore = optarg;
                OVSA_DBG(DBG_D, "keystore_name: %s \n", keystore);
                break;
            case 'r':
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_FILE_NAME) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Error CSR File name greater than %d characters not allowed \n",
                             MAX_FILE_NAME);
                    ret = OVSA_INVALID_FILE_PATH;
                    goto out;
                }
                csr_filename = optarg;
                OVSA_DBG(DBG_D, "CSR File name: %s \n", csr_filename);
                break;
            case 'e':
                subject = optarg;
                OVSA_DBG(DBG_D, "subject: %s \n", subject);
                break;
            case 'c':
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_FILE_NAME) {
                    OVSA_DBG(
                        DBG_E,
                        "OVSA: Error certificate path greater than %d characters not allowed \n",
                        MAX_FILE_NAME);
                    ret = OVSA_INVALID_FILE_PATH;
                    goto out;
                }
                cert_file = optarg;
                break;
            case 'p':
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_FILE_NAME) {
                    OVSA_DBG(
                        DBG_E,
                        "OVSA: Error file to sign path greater than %d characters not allowed \n",
                        MAX_FILE_NAME);
                    ret = OVSA_INVALID_FILE_PATH;
                    goto out;
                }
                input_file = optarg;
                OVSA_DBG(DBG_D, "file to be signed: %s \n", input_file);
                break;
            case 'o':
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_FILE_NAME) {
                    OVSA_DBG(
                        DBG_E,
                        "OVSA: Error signature file path greater than %d characters not allowed \n",
                        MAX_FILE_NAME);
                    ret = OVSA_INVALID_FILE_PATH;
                    goto out;
                }
                signed_file = optarg;
                OVSA_DBG(DBG_D, "Signed File: %s \n", signed_file);
                break;
            case 's':
                if (strnlen_s(optarg, RSIZE_MAX_STR) > MAX_FILE_NAME) {
                    OVSA_DBG(
                        DBG_E,
                        "OVSA: Error signature file path greater than %d characters not allowed \n",
                        MAX_FILE_NAME);
                    ret = OVSA_INVALID_FILE_PATH;
                    goto out;
                }
                signature = optarg;
                OVSA_DBG(DBG_D, "Signature: %s \n", signature);
                break;
            case 'h':
                ovsa_keygen_help(argv[0]);
                goto out;
        }
    }

    /* optind is for the extra arguments which are not parsed */
    for (; optind < argc; optind++) {
        OVSA_DBG(DBG_I, "extra arguments: %s\n", argv[optind]);
    }

    if (keystore == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Keystore name is empty. Please follow -help for help option\n");
        ret = OVSA_INVALID_PARAMETER;
        goto out;
    }

    switch (opcode) {
        case STOREKEY:
            ret = ovsa_do_cmd_storekey(alg_type, isv_name, keystore, csr_filename, subject);
            if (ret != OVSA_OK) {
                OVSA_DBG(DBG_E, "OVSA: StoreKey command failed with error code %d\n", ret);
                goto out;
            }
            OVSA_DBG(DBG_I, "OVSA: Key store %s, %s created successfully\n", keystore,
                     csr_filename);
            break;
        case STORECERT:
            ret = ovsa_do_cmd_storecert(keystore, cert_file);
            if (ret != OVSA_OK) {
                OVSA_DBG(DBG_E, "OVSA: StoreCert command failed with error code %d\n", ret);
                goto out;
            }
            OVSA_DBG(DBG_I, "OVSA: Certificate %s stored successfully to %s\n", cert_file,
                     keystore);
            break;
        case GETCERT:
            ret = ovsa_do_cmd_getcert(keystore, cert_file);
            if (ret != OVSA_OK) {
                OVSA_DBG(DBG_E, "OVSA: GetCert command failed with error code %d\n", ret);
                goto out;
            }
            OVSA_DBG(DBG_I, "OVSA: Certificate extracted successfully to %s from %s\n", cert_file,
                     keystore);
            break;
        case SIGN:
            ret = ovsa_do_cmd_sign(input_file, signed_file, keystore);
            if (ret != OVSA_OK) {
                OVSA_DBG(DBG_E, "OVSA: Sign command failed with error code %d\n", ret);
                goto out;
            }
            OVSA_DBG(DBG_I, "OVSA: %s file signed successfully and signature stored in %s\n",
                     input_file, signed_file);
            break;
        case VERIFY:
            ret = ovsa_do_cmd_verify(input_file, signature, keystore);
            if (ret != OVSA_OK) {
                OVSA_DBG(DBG_E, "OVSA: Verify command failed with error code %d\n", ret);
                goto out;
            }
            OVSA_DBG(DBG_I, "OVSA: %s file verified successfully with signature\n", input_file);
            break;
        case HELP:
            ovsa_keygen_help(argv[0]);
            goto out;
            break;
        default:
            OVSA_DBG(DBG_E, "OVSA: Wrong command given. Please follow -help for help option\n");
            ret = OVSA_INVALID_PARAMETER;
    }
out:
    OVSA_DBG(DBG_D, "%s exit\n", __func__);
    return ret;
}
