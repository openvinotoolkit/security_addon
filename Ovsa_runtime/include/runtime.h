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

#ifndef __OVSA_RUNTIME_H_
#define __OVSA_RUNTIME_H_

#include <mbedtls/ssl.h>
#include <stdint.h>

#include "libovsa.h"
#include "ovsa_tool.h"
#include "safe_str_lib.h"
#include "tpm.h"

#define MESSAGE_BLOB_TEXT_SIZE  34
#define MAX_COMMAND_TYPE_LENGTH 50
#define NONCE_SIZE              32
#define PAYLOAD_LENGTH          8 /* 8Bytes */
#define PROT_MODEL_PATH         "model/"
#define CURVE_LIST_SIZE         2
#define CIPHER_SUITE_SIZE       1
#define NONCE_BUF_SIZE          (NONCE_SIZE * 2) /* In B64 format */

typedef struct ovsa_quote_info {
    char* quote_message;
    char* quote_sig;
    char* quote_pcr;
    char* ak_pub_key;
    char* ek_pub_key;
    char* ek_cert;
} ovsa_quote_info_t;

typedef struct ovsa_sw_ek_ak_bind_info {
    char* sw_ak_pub_key;
    char* sw_ak_name;
    char* sw_ek_pub_key;
    char* sw_ek_pub_sig;
    char* sw_ek_cert;
    char* sw_ek_cert_sig;
    char* platform_cert;
} ovsa_sw_ek_ak_bind_info_t;

typedef enum {
    OVSA_SEND_NONCE = 0,
    OVSA_SEND_EK_AK_BIND,
    OVSA_SEND_EK_AK_BIND_INFO,
    OVSA_SEND_QUOTE_NONCE,
    OVSA_SEND_SIGN_NONCE,
    OVSA_SEND_QUOTE_INFO,
    OVSA_SEND_HW_QUOTE,
    OVSA_SEND_CUST_LICENSE,
    OVSA_SEND_LICENSE_CHECK_RESP,
    OVSA_INVALID_CMD
} ovsa_command_type_t;

/* Enum values for mode files type */
typedef enum { BIN_FILE = 0, XML_FILE } ovsa_model_file_type_t;

/*!
 * \brief load model files and decrypt
 *
 * \param[in] asym_key_slot
 * \param[in] peer_cert_slot
 * \param[in] ovsa_customer_license_sig_t
 * \param[in] ovsa_protected_model_sig_t
 * \param[out] decrypt_xml          decrypted model buffer
 * \param[out] decrypt_bin          decrypted weights buffer
 * \param[out] xml_len              model buffer size
 * \param[out] bin_len              weights buffer size
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_module_loader(int asym_key_slot, int peer_cert_slot,
                                 ovsa_customer_license_sig_t* cust_lic,
                                 ovsa_protected_model_sig_t* prot_model, char** decrypt_xml,
                                 char** decrypt_bin, int* xml_len, int* bin_len);

/*!
 * \brief generate signature
 *
 * \param[in] asym_key_slot asymmetric keyslot
 * \param[in] in_buff       input buffer
 * \param[in] in_buff_len   input size
 * \param[out] out_buff     signed buffer
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_crypto_sign_mem(int asym_key_slot, char* in_buff, size_t in_buff_len,
                                   char* out_buff);

/*!
 * \brief Load artefacts ,verify artifacts and perform validation.
 *
 * \param[in]  keystore_name        keystore info
 * \param[in]  protected_model      protected model json
 * \param[in]  customer_license     customer_license json
 * \param[out] decrypt_xml          decrypted model buffer
 * \param[out] decrypt_bin          decrypted weights buffer
 * \param[out] xml_len              model buffer size
 * \param[out] bin_len              weights buffer size
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_license_check_module(const char* keystore, const char* protected_model,
                                        const char* customer_license, char** decrypt_xml,
                                        char** decrypt_bin, int* xml_len, int* bin_len);

/*!
 * \brief generate TCB signature files.
 *
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_do_tcb_generation(int argc, char* argv[]);

/*!
 * \brief establish host connection
 *
 * \param[in]   _sockfd    file descriptor for socket
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_establish_host_connection(int* _sockfd);

/*!
 * \brief establish host connection
 *
 * \param[in]  _sockfd         file descriptor of the socket
 * \param[in]  nonce_buf       buffer containing the nonce value
 * \param[in]  hw_quote_info   hard ware quote value
 * \return ovsa_status_t
 */

ovsa_status_t ovsa_get_hw_quote(int sockfd, char* nonce_buf, ovsa_quote_info_t* hw_quote_info);

/*!
 * \brief create nouce
 *
 * \param[out] nonce_buf  Buffer to store the nouce
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_create_nonce(char** nonce_buf);

/*!
 * extern functions list
 */
extern void ovsa_safe_free(char** ptr);
extern void ovsa_safe_free_enc_list(ovsa_enc_models_t** listhead);
extern void ovsa_safe_free_url_list(ovsa_license_serv_url_list_t** listhead);
#endif
