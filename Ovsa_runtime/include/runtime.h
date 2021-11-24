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

#ifndef __OVSA_RUNTIME_H_
#define __OVSA_RUNTIME_H_

#include <mbedtls/ssl.h>
#include <stdint.h>

#include "libovsa.h"
#include "ovsa_tool.h"
#include "safe_str_lib.h"
#include "tpm.h"

#ifndef ENABLE_SGX_GRAMINE
#define MAX_LEN              13
#define DEFAULT_HOST_IP_ADDR "192.168.122.1"
#define DEFAULT_PORT         4450
#define SA                   struct sockaddr

#define DISABLE_RA_TLS
#define DEFAULT_PCR_ID_SET         "0xFFFFFF" /*Set all PCR ID's 0:23 */
#define TPM2_NVM_HWQUOTE_LEN_FILE  "/tmp/read_hwquote_len"
#define TPM2_NVM_HWQUOTE_BLOB_FILE "/tmp/read_hw_quote_"
#endif

#define MESSAGE_BLOB_TEXT_SIZE  34
#define MAX_COMMAND_TYPE_LENGTH 50
#define NONCE_SIZE              32
#define PAYLOAD_LENGTH          8 /* 8Bytes */
#define CURVE_LIST_SIZE         2
#define CIPHER_SUITE_SIZE       1
#define NONCE_BUF_SIZE          (NONCE_SIZE * 2) /* In B64 format */

#ifndef ENABLE_SGX_GRAMINE
#define MAX_INDEX_LEN         8
#define MAX_NVMQUOTE_SIZE     2044
#define TPM2_NV_INDEX_START   0
#define QUOTE_NONCE_HASH_SIZE 32

#define HW_QUOTE_SIZE_LENGTH  8 /* Size in bytes to store of HW Quote file */
#define MAX_NV_INDEX_BUF_SIZE 2048
#endif

#define mbedtls_printf      printf
#define READ_TIMEOUT_MS     20000 /* 20 seconds */
#define MBEDTLS_DEBUG_LEVEL 0

#ifndef ENABLE_SGX_GRAMINE
typedef struct ovsa_quote_info {
    char* quote_message;
    char* quote_sig;
    char* quote_pcr;
    char* ak_pub_key;
    char* ek_pub_key;
    char* ek_cert;
} ovsa_quote_info_t;

typedef struct ovsa_ek_ak_bind_info {
    char* ak_pub_key;
    char* ak_name;
    char* ek_pub_key;
    char* ek_pub_sig;
    char* ek_cert;
    char* ek_cert_sig;
    char* platform_cert;
#ifdef PTT_EK_ONDIE_CA
    char* ROM_cert;
    char* Chain_cert;
#endif
} ovsa_ek_ak_bind_info_t;
#endif

typedef enum {
    OVSA_SEND_NONCE = 0,
#ifndef ENABLE_SGX_GRAMINE
    OVSA_SEND_EK_AK_BIND,
    OVSA_SEND_EK_AK_BIND_INFO,
    OVSA_SEND_QUOTE_NONCE,
#endif
    OVSA_SEND_SIGN_NONCE,
#ifndef ENABLE_SGX_GRAMINE
    OVSA_SEND_QUOTE_INFO,
    OVSA_SEND_HW_QUOTE,
#endif
    OVSA_SEND_CUST_LICENSE,
    OVSA_SEND_UPDATE_CUST_LICENSE,
    OVSA_SEND_UPDATE_CUST_LICENSE_ACK,
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
 * \param[in] ovsa_controlled_access_model_sig_t
 * \param[out] decrypt_xml          decrypted model buffer
 * \param[out] decrypt_bin          decrypted weights buffer
 * \param[out] xml_len              model buffer size
 * \param[out] bin_len              weights buffer size
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_module_loader(int asym_key_slot, int peer_cert_slot,
                                 ovsa_customer_license_sig_t* cust_lic,
                                 ovsa_controlled_access_model_sig_t* control_access_model,
                                 char** decrypt_xml, char** decrypt_bin, int* xml_len,
                                 int* bin_len);

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
 * \param[in]  keystore_name            keystore info
 * \param[in]  controlled_access_model  controlled access model json
 * \param[in]  customer_license         customer_license json
 * \param[in]  decrypted_files          sturcture containing decrypted files info
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_license_check_module(const char* keystore, const char* controlled_access_model,
                                        const char* customer_license,
                                        ovsa_model_files_t** decrypted_files);

/*!
 * \brief Validation for cutomerlicense json and load info to structure
 *
 * \param[in]  customer_license         customer_license json
 * \param[in]  asym_keyslot             asymmetric keyslot index
 * \param[out] customer_lic_sig         structure containing customer license info
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_validate_customer_license(const char* customer_license, const int asym_keyslot,
                                             ovsa_customer_license_sig_t* customer_lic_sig);

/*!
 * \brief Validation for controlled access model json and load info to structure
 *
 * \param[in]  peer_keyslot                peer keyslot index
 * \param[in]  controlled_access_model     controlled access model json
 * \param[out] controlled_access_model_sig structure containing controlled access info
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_validate_controlled_access_model(
    const int peer_keyslot, const char* controlled_access_model,
    ovsa_controlled_access_model_sig_t* controlled_access_model_sig);

/*!
 * \brief Perform License check with tls connection
 *
 * \param[in]  asym_keyslot       asymmetric keyslot index
 * \param[in]  customer_license   customer_license json
 * \param[out] status             status of license check performed
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_perform_tls_license_check(const int asym_keyslot, const char* customer_license,
                                             bool* status);

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
 * \brief create nouce
 *
 * \param[out] nonce_buf  Buffer to store the nouce
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_create_nonce(char** nonce_buf);

#ifndef ENABLE_SGX_GRAMINE
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
 * \brief read nvm HW quote
 *
 * \param[out]  hw_quote_info buffer to store quote info
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_nvread_tpm2_HW_quote(ovsa_quote_info_t* hw_quote_info);

/*!
 * \brief tpm2 read nvm
 * \param[in]  hw_quote_file  file name
 * \param[in]  nvindex        nv index to read
 * \param[in]  size           size to be read
 * \param[out] hwquote_buff   buffer to store quote info
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_tpm2_nvread(char* hw_quote_file, int nvindex, int size, int offset,
                               char* hwquote_buff);

/*!
 * \brief tpm2_generate_reference
 * \param[out]  ovsa_tcb_info  tcb_info
 * \param[in]  sw_pcr_reg_id   sw_pcr_reg_id
 * \param[in]  hw_pcr_reg_id   sw_pcr_reg_id
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_generate_reference_tcb(ovsa_tcb_info_t* tcb_info, int sw_pcr_reg_id,
                                          int hw_pcr_reg_id);

/*!
 * \brief get_pcr_exclusion_set
 * \param[in]  pcr_exclusion pcr_exclusion
 * \param[out] pcr_id_set    pcr_id_set
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_get_pcr_exclusion_set(char* pcr_exclusion, int* pcr_id_set);

/*!
 * \brief send_EK_AK_bind_info
 * \param[in] asym_keyslot asymmetric keyslot index
 * \param[in] _ssl_session ssl_session
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_send_EK_AK_bind_info(const int asym_keyslot, void** _ssl_session);

/*!
 * \brief remove_quote_files
 * \Remove the quote file
 */
void ovsa_remove_quote_files(void);

/*!
 * \brief do_get_quote_nounce
 * \param[in] asym_keyslot asymmetric  keyslot index
 * \param[in] quote_credout_blob       quote credential
 * \param[in] cust_lic_sig_buf         customer license
 * \param[in] _ssl_session             ssl session
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_do_get_quote_nounce(const int asym_keyslot, char* quote_credout_blob,
                                       char* cust_lic_sig_buf, void** _ssl_session);
#endif

#ifdef ENABLE_SGX_GRAMINE
/*!
 * \brief generate reference tcb
 * \param[out] ovsa_tcb_info  tcb_info
 * \param[in]  sig_file tcb file
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_generate_reference_tcb(ovsa_tcb_info_t* tcb_info, char* sig_file);
#endif

/*!
 * \brief tcb_gen_help
 * tcb generation help
 */
void ovsa_tcb_gen_help(char* argv);
ovsa_status_t ovsa_validate_customer_license(const char* customer_license, const int asym_keyslot,
                                             ovsa_customer_license_sig_t* customer_lic_sig);
ovsa_status_t ovsa_validate_controlled_access_model(
    const int peer_keyslot, const char* controlled_access_model,
    ovsa_controlled_access_model_sig_t* controlled_access_model_sig);
ovsa_status_t ovsa_perform_tls_license_check(const int asym_keyslot, const char* customer_license,
                                             bool* status);

/*!
 * extern functions list
 */
extern void ovsa_safe_free(char** ptr);
extern void ovsa_safe_free_model_file_list(ovsa_model_files_t** listhead);
extern void ovsa_safe_free_url_list(ovsa_license_serv_url_list_t** listhead);
#endif /*__OVSA_RUNTIME_H_*/
