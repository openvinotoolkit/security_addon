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

#ifndef __OVSA_SYMMETRIC_H_
#define __OVSA_SYMMETRIC_H_

extern ovsa_isv_keystore_t g_key_store[MAX_KEY_SLOT];
extern pthread_mutex_t g_symmetric_index_lock;
extern char g_sym_key[MAX_KEY_SLOT][MAX_EKEY_SIZE];
extern BIO* g_bio_err;

#define PBKDF2_ITERATION_COUNT 10000

/** \brief This function adds symmetric keys to the symmetric keystore array.
 *
 * \param[in]  symmetric_key  Generated symmetric_keys.
 * \param[out] sym_key_slot   Symmetric key slot index.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_add_symmetric_keystore_array(const char* symmetric_key,
                                                       int* sym_key_slot);

/** \brief This function generates salt and prefix with magic.
 *
 * \param[out] magic_salt_buff  Pointer to magic/salt.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_generate_salt(char* salt_buff, char* magic_salt_buff);

/** \brief This function derives the unsealing key from TPM which is the password and salt.
 *         Password is added to the symmetric key slot and salt is prefixed with magic.
 *
 * \param[out] magic_salt_buff  Pointer to magic/salt buffer.
 * \param[out] sym_key_slot     Symmetric key slot index.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_derive_unsealing_key(char* magic_salt_buff, int* sym_key_slot);

/** \brief This function encrypts the keystore contents and computes hmac for the encrypted
 *         keystore blob and writes the encrypted keystore content and hmac element to the
 *         keystore json blob.
 *
 * \param[in]  sym_key_slot      Symmetric key slot index.
 * \param[in]  enc_keystore_name Encrypted keystore file name.
 * \param[in]  in_buff           Input buffer for encryption.
 * \param[in]  in_buff_len       Input buffer length.
 * \param[in]  magic_salt_buff   Pointer to magic/salt buffer.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_encrypt_keystore(int sym_key_slot, const char* enc_keystore_name,
                                           const char* in_buff, size_t in_buff_len,
                                           char* magic_salt_buff);

/** \brief This function decrypts the keystore contents and verifies hmac for the encrypted
 *         keystore blob and returns the decrypted buffer and length.
 *
 * \param[in]  sym_key_slot      Symmetric key slot index.
 * \param[in]  in_buff           Input buffer for encryption.
 * \param[in]  in_buff_len       Input buffer length.
 * \param[in]  magic_salt_buff   Pointer to magic/salt buffer.
 * \param[out] out_buff          Decrypted output buffer.
 * \param[out] out_buff_len      Output buffer length.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_decrypt_keystore(int sym_key_slot, const char* in_buff,
                                           size_t in_buff_len, const char* magic_salt_buff,
                                           char** out_buff, size_t* out_buff_len);

#endif /* __OVSA_SYMMETRIC_H_ */
