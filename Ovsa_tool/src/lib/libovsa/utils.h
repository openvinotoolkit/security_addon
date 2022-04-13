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

#ifndef __OVSA_UTILS_H_
#define __OVSA_UTILS_H_

#include <openssl/bio.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "cJSON.h"
#include "libovsa.h"
#include "safe_mem_lib.h"

#define BUFSIZE               1024 * 8
#define MAX_SYM_KEY_SIZE      4096
#define KEY_PAIR_SIZE         2
#define MAX_HMAC_LENGTH       EVP_MAX_KEY_LENGTH
#define MAX_KEYIV_HMAC_LENGTH EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH + MAX_HMAC_LENGTH
#define MAX_MAGIC_SALT_LENGTH 32

#ifdef ENABLE_SELF_SIGNED_CERT
#define NUM_OF_SECONDS_IN_DAY 86400
/*
 * IETF RFC 5280 says serial number must be <= 20 bytes. Use 159 bits
 * so that the first bit will never be one, so that the DER encoding
 * rules won't force a leading octet.
 */
#define SERIAL_RAND_BITS 159
#endif

union {
    struct {
        uint32_t time_low;
        uint16_t time_mid;
        uint16_t time_hi_and_version;
        uint8_t clk_seq_hi_res;
        uint8_t clk_seq_low;
        uint8_t node[6];
    };
    uint8_t __rnd[16];
} uuid;

/** \brief This function generates CSR file based on the contents specified in subject and stores
 *              as on-disk file.
 *
 * \param[in]  private_key  Pointer to private key to be used for CSR generation.
 * \param[in]  subject      Contains information needed for CSR generation.
 * \param[out] csr_file     File name to store CSR.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_generate_csr(const char* private_key, const char* subject,
                                       const char* csr_file);

/** \brief This function does signing, verification and hashing operation.
 *
 * \param[in]  buf    Buffer pointer for reading the input data.
 * \param[in]  inp    Pointer to input data.
 * \param[in]  key    Pointer to Private or Public key used for signing or verification.
 * \param[in]  sigin  Signature buffer to read the signature.
 * \param[in]  siglen Size of the private/public key.
 * \param[in]  file   Pointer to input file.
 * \param[out] out    Generated signature.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_do_sign_verify_hash(unsigned char* buf, BIO* inp, const EVP_PKEY* key,
                                              const unsigned char* sigin, int siglen,
                                              const char* file, BIO* out);

/** \brief This function is used for dynamic memory allocation
 *
 * \param[in] size  Buffer size for alloaction.
 * \param[in] what  Name of the operation for which allocation is made.
 *
 * \return allocated buffer pointer on Success or NULL in Failure
 */
void* ovsa_crypto_app_malloc(size_t size, const char* what);

/** \brief This function is used to free the allocated memory
 *
 * \param[in] buff  Buffer to be freed
 */
void ovsa_crypto_openssl_free(char** buff);

/** \brief This function reads the Private/Public Key
 *
 * \param[in] p_key        Pointer to read the Private/Public Key.
 * \param[in] key_descrip  Description of the key.
 *
 * \return Pointer to the key on Success or NULL in Failure
 */
EVP_PKEY* ovsa_crypto_load_key(const char* p_key, const char* key_descrip);

/** \brief This function reads the certificate
 *
 * \param[in] cert          Pointer to read the certificate.
 * \param[in] cert_descrip  Description of the certificate.
 *
 * \return Pointer to the certificate on Success or NULL in Failure
 */
X509* ovsa_crypto_load_cert(const char* cert, const char* cert_descrip);

/** \brief This function checks the lifetime validity of the certificate.
 *
 * \param[in] cert    Pointer to read the certificate.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_check_cert_lifetime_validity(const char* cert);

/** \brief This function calculates the length of the input buffer.
 *
 * \param[in]  in_buff       Buffer pointer for calculating the length.
 * \param[out] in_buff_len   Length of the input buffer.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_get_string_length(const char* in_buff, size_t* in_buff_len);

/** \brief This function does string comparison.
 *
 * \param[in]  src_buff    Source pointer to the string to be compared.
 * \param[in]  dest_buff   Destination pointer to the string to be compared.
 * \param[out] indicator   Output of the compared string.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_compare_strings(const char* src_buff, const char* dest_buff, int* indicator);

/*!
 * \brief This function creates isv keystore.
 *
 * \param [in]  keystore     Structure containing keystore information
 * \param [out] outputBuf    Buffer updated with json file contents
 * \param [in]  outLen       Length of output buffer allocated.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_json_create_isv_keystore(const ovsa_isv_keystore_t keystore[], char* outputBuf,
                                            size_t outLen);

/*!
 * \brief This function extracts keystore contents.
 *
 * \param [in]  inputBuf    Buffer having json file contents.
 * \param [out] keystore    Structure containing keystore information.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_json_extract_keystore_info(const char* inputBuf, ovsa_isv_keystore_t keystore[]);

/*!
 * \brief This function creates encrypted keystore.
 *
 * \param [in]  keystore     Buffer containing encrypted keystore information.
 * \param [out] outputBuf    Buffer updated with json file contents.
 * \param [in]  outLen         Length of output buffer allocated.
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_json_create_encrypted_keystore(const char* keystoreBuf, char* outputBuf,
                                                  size_t outLen);

/*!
 * \brief This function extract encrypted keystore contents.
 *
 * \param [in]  inputBuf       Buffer having json file contents.
 * \param [out] en_keystore    Buffer containing encrypted keystore information.
 * \param [in]  outLen         Length of output buffer allocated.
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_json_extract_encrypted_keystore(const char* inputBuf,
                                                   ovsa_enc_keystore_t* en_keystore, size_t outLen);

/*!
 * \brief This function gets the size of the specified keyname.
 *
 * \param [in]  keyName    Name of key to read.
 * \param [in]  inBuf      Buffer with json file contents.
 * \param [out] len        Updated with value length.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_json_getitem_size(const char* keyName, const char* inBuf, size_t* len);

/*!
 * \brief This function appends the signature to the input buffer.
 *
 * \param [in]  inputBuf    Buffer with json file contents.
 * \param [in]  sigBuf      Buffer containing signature.
 * \param [out] outBuf      Buffer updated with json file contents.
 * \param [in]  buff_len    Length of output buffer allocated.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_json_apend_signature(const char* inputBuf, const char* sigBuf, char* outBuf,
                                        size_t buff_len);

/*!
 * \brief ovsa_safe_add
 *
 * \param [in]  size_t Variable1 ,Sum of var1+var2 stored in var1
 * \param [in]  size_t Variable2
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_safe_add(size_t* var1, size_t var2);

#endif /* __OVSA_UTILS_H_ */
