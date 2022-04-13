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

#ifndef __OVSA_ASYMMETRIC_H_
#define __OVSA_ASYMMETRIC_H_

#include "utils.h"

#define MAX_KEYPAIR 2

extern BIO* g_bio_err;
extern pthread_mutex_t g_asymmetric_index_lock;
extern pthread_mutex_t g_symmetric_index_lock;
extern ovsa_isv_keystore_t g_key_store[MAX_KEY_SLOT];
extern char g_sym_key[MAX_KEY_SLOT][MAX_EKEY_SIZE];

/** \brief This function adds keystore contents to the asymmetric keystore array.
 *
 * \param[in]  isv_keystore   ovsa_isv_keystore_t contents.
 * \param[out] asym_key_slot  Asymmetric key slot index.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_add_asymmetric_keystore_array(const ovsa_isv_keystore_t* isv_keystore,
                                                        int* asym_key_slot);

/** \brief This function adds certificate to the specified asymmetric keystore array.
 *
 * \param[in] asym_key_slot  Asymmetric key slot index.
 * \param[in] cert           Pointer to certificate.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_add_cert_keystore_array(int asym_key_slot, const char* cert);

/** \brief This function signs the contents of memory of specified length and stores the signature
 *         into output buffer using the private key from the key slot.
 *
 * \param[in]  asym_key_slot  Asymmetric key slot index.
 * \param[in]  in_buff        Input buffer for signing.
 * \param[in]  in_buff_len    Length of input buffer for signing.
 * \param[out] out_buff       Output buffer to store signature.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_sign_mem(int asym_key_slot, const char* in_buff, size_t in_buff_len,
                                   char* out_buff);

/** \brief This function verifies the signature of the input buffer with the specified signature
 *         using the public key from the key slot.
 *
 * \param[in]  asym_key_slot  Asymmetric key slot index.
 * \param[in]  in_buff        Input buffer for verification.
 * \param[in]  in_buff_len    Length of input buffer for verification.
 * \param[in]  signature      Pointer to signature to be used for verification.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_verify_mem(int asym_key_slot, const char* in_buff, size_t in_buff_len,
                                     const char* signature);

/** \brief This function computes hmac for the memory buffer and stores the hmac into output buffer
 *         using the hmac key from the key slot.
 *
 * \param[in]  keyiv_hmac_slot  Key/IV/HMAC key slot index.
 * \param[in]  in_buff          Input buffer for computing hmac.
 * \param[in]  in_buff_len      Length of input buffer.
 * \param[out] out_buff         Output buffer to store hmac.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_compute_hmac(int keyiv_hmac_slot, const char* in_buff, size_t in_buff_len,
                                       char* out_buff);

#endif /* __OVSA_ASYMMETRIC_H_ */
