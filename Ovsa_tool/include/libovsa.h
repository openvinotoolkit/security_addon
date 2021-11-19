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

#ifndef __OVSA_LIBOVSA_H_
#define __OVSA_LIBOVSA_H_

#include <openssl/ocsp.h>
#include <stdbool.h>
#include <time.h>

#include "ovsa_errors.h"

/* Size of the HASH key Considering SHA512 for HASHING */
#define HASH_SIZE 192 /* Actual 130: Considering the length for B64 */
/* Size of the GUID size */
#define GUID_SIZE 36

#define MAX_FILE_NAME                                    256
#define MAX_NAME_SIZE                                    256
#define MAX_SAFE_ARGC                                    64
#define MAX_VERSION_SIZE                                 32
#define MAX_SIGNATURE_SIZE                               256 /* Actual size: 143 */
#define MAX_MAC_SIZE                                     128 /* Actual size: 90 */
#define MAX_KEY_SIZE                                     512 /* Actual size: 359 */
#define MAX_EKEY_SIZE                                    256 /* Actual size: 45 */
#define MAX_URL_SIZE                                     256
#define MAX_TCB_SIZE                                     256
#define MAX_BUF_SIZE                                     4096
#define KEYSTORE_BLOB_TEXT_SIZE                          155
#define MIN_KEY_SLOT                                     0
#define MAX_KEY_SLOT                                     64
#define SYMMETRIC_KEY_SIZE                               32
#define ENC_KEYSTORE_BLOB_TEXT_SIZE                      20
#define SIGNATURE_BLOB_TEXT_SIZE                         18
#define NULL_TERMINATOR                                  1
#define MAX_DATE_TIME_SIZE                               32
#define MAX_CERT_VALIDITY_PERIOD                         18 /* Months */
#define MAX_CONTROLLED_ACCESS_MODEL_VALIDITY_TIME_PERIOD 5  /* 5 years */
#define TIMECONVERT_SECSTODAYS(timeSecs)                 ((timeSecs % (86400 * 30)) / 86400)
#define HASH_ALG_SHA256                                  1
#define HASH_ALG_SHA384                                  2
#define HASH_ALG_SHA512                                  3

/* As per the ASN1_STRING_TABLE, computed max size of the attribute types
   found in the Distinguished Name are around ~129K and added certain buffer
   to accomadate the attributes where max size is not available. */
#define MAX_CERT_SIZE (256UL << 10) /* 256KB */

typedef enum { ECDSA, INVALID_ALGO = 99 } ovsa_key_alg_t;

typedef char GUID[GUID_SIZE + 1];

/* Structure of keystore information */
typedef struct ovsa_isv_keystore {
    char isv_name[MAX_NAME_SIZE];
    char public_key[MAX_KEY_SIZE];
    char private_key[MAX_KEY_SIZE];
    GUID key_guid;
    char* isv_certificate;
} ovsa_isv_keystore_t;

/* Structure of encrypted keystore */
typedef struct ovsa_enc_keystore {
    char* keystore;
    char signature[MAX_MAC_SIZE];
} ovsa_enc_keystore_t;

/** \brief This function initializes the crypto.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_init(void);

/** \brief This function de-initializes the crypto.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_deinit(void);

/** \brief This function generates Asymmetric Key Pair, CSR, GUID, creates keystore file
 *         and writes keystore as a on-disk protected file.
 *
 * \param[in]  alg_type        Algorithm type for key generation.
 * \param[in]  subject         Contains information needed for CSR generation.
 * \param[in]  isv_name        ISV name.
 * \param[in]  keystore_name   Keystore JSON blob.
 * \param[in]  file_name   CSR file name.
 * \param[out] asym_key_slot   Asymmetric key slot index.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_generate_asymmetric_key_pair(ovsa_key_alg_t alg_type, const char* subject,
                                                       const char* isv_name,
                                                       const char* keystore_name,
                                                       const char* file_name, int* asym_key_slot);

/** \brief This function reads and extracts key store JSON blob and populate keystore info.
 *
 * \param[in]  keystore_name  Keystore JSON blob.
 * \param[out] asym_key_slot  Asymmetric key slot index.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_load_asymmetric_key(const char* keystore_name, int* asym_key_slot);

/** \brief This function compares the keystore contents and returns the matching keyslot if found.
 *
 * \param[in]  keystore_name  Keystore JSON blob.
 * \param[out] asym_key_slot  Asymmetric key slot index.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_get_asymmetric_key_slot(const char* keystore_name, int* asym_key_slot);

/** \brief This function verifies the certificate signature and adds certificate to JSON blob
 *         and writes keystore as a on-disk protected file.
 *
 * \param[in]  asym_key_slot              Asymmetric key slot index.
 * \param[in]  peer_cert                  boolean value to indicate the peer certificate.
 * \param[in]  cert                       Pointer to certificate.
 * \param[in]  lifetime_validity_check    boolean value for lifetime validity check.
 * \param[in]  keystore_name              Keystore JSON blob.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_store_certificate_keystore(int asym_key_slot, bool peer_cert,
                                                     const char* cert, bool lifetime_validity_check,
                                                     const char* keystore_name);

/** \brief This function compares the public key from specified certificate with the public key from
 * keystore in the specified keyslot. Returns OVSA_OK if public key matches else returns OVSA_ERROR
 *
 * \param[in]  asym_key_slot  Asymmetric key slot index.
 * \param[in]  cert           Pointer to certificate.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_compare_certkey_and_keystore(int asym_key_slot, const char* cert,
                                                       EVP_PKEY** pkey, X509** xcert);

/** \brief This function verifies the certificate signature and writes as a on-disk protected file.
 *
 * \param[in]  asym_key_slot              Asymmetric key slot index.
 * \param[in]  peer_cert                  boolean value to indicate the peer certificate.
 * \param[in]  lifetime_validity_check    boolean value for lifetime validity check.
 * \param[in]  cert_file_name             File to store the certificate.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_store_certificate_file(int asym_key_slot, bool peer_cert,
                                                 bool lifetime_validity_check,
                                                 const char* cert_file_name);

/** \brief This function gets the certificate from the corresponding key slot and returns the
 *         certificate pointer.
 *
 * \param[in]  asym_key_slot  Asymmetric key slot index.
 * \param[out] cert           Pointer to store certificate.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_get_certificate(int asym_key_slot, char** cert);

/** \brief This function signs and generates signed file for the specified file using the private
 *         key.
 *
 * \param[in]  asym_key_slot  Asymmetric key slot index.
 * \param[in]  file_to_sign   Input file for signing
 * \param[out] signed_file    File to store the signed file.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_sign_file(int asym_key_slot, const char* file_to_sign,
                                    const char* signed_file);

/** \brief This function verifies the specified input file with the provided signature using the
 *         public key.
 *
 * \param[in] asym_key_slot  Asymmetric key slotindex.
 * \param[in] file_to_verify Input file whose signature needs to be verified.
 * \param[in] signature      Signature file.
 *
 * \return ovsa_status_t : OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_verify_file(int asym_key_slot, const char* file_to_verify,
                                      const char* signature);

/** \brief This function signs the input JSON blob of specified length using the private key
 *         from the key slot and creates the signature element and appends to the JSON blob and
 *         returns the JSON blob with signature.
 *
 * \param[in]  asym_key_slot   Asymmetric key slot index.
 * \param[in]  in_buff         Input buffer for signing.
 * \param[in]  in_buff_len     Length of input buffer for signing.
 * \param[out] out_buff        Output buffer to store signature.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_sign_json_blob(int asym_key_slot, const char* in_buff, size_t in_buff_len,
                                         char* out_buff);

/** \brief This function extracts and strips the signature element from the input JSON blob of
 *         specified length and verifies the JSON blob with the extracted signature using the
 *         public key from the key slot and returns the JSON blob without signature.
 *
 * \param[in]  asym_key_slot   Asymmetric key slot index.
 * \param[in]  in_buff         Input buffer for verification.
 * \param[in]  in_buff_len     Length of input buffer for verification.
 * \param[out] out_buff        Output buffer to strip the signature.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_verify_json_blob(int asym_key_slot, const char* in_buff,
                                           size_t in_buff_len, char* out_buff);

/** \brief This function hmac's the input JSON blob of specified length using the hmac key
 *         from the key slot and creates the hmac element and appends to the JSON blob and
 *         returns the JSON blob with signature.
 *
 * \param[in]  keyiv_hmac_slot key/IV/HMAC slot index.
 * \param[in]  in_buff         Input buffer for signing.
 * \param[in]  in_buff_len     Length of input buffer for signing.
 * \param[out] out_buff        Output buffer to store hmac.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_hmac_json_blob(int keyiv_hmac_slot, const char* in_buff,
                                         size_t in_buff_len, char* out_buff);

/** \brief This function extracts and strips the hmac element from the input JSON blob of
 *         specified length and verifies the JSON blob with the extracted signature using the
 *         hmac key from the key slot and returns the JSON blob without signature.
 *
 * \param[in]  keyiv_hmac_slot key/IV/HMAC slot index.
 * \param[in]  in_buff         Input buffer for verification.
 * \param[in]  in_buff_len     Length of input buffer for verification.
 * \param[out] out_buff        Output buffer to strip the hmac.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_verify_hmac_json_blob(int keyiv_hmac_slot, const char* in_buff,
                                                size_t in_buff_len, char* out_buff);

/** \brief This function encrypts the symmetric key using the Private key.
 *
 * \param[in]  asym_key_slot   Asymmetric key slot index.
 * \param[in]  sym_key_slot    Symmetric key slot index.
 * \param[out] out_buff        Output buffer to store encrypted data.
 * \param[out] out_buff_len    Length of the output buffer.
 * \param[out] keyiv_hmac_slot key/IV/HMAC slot index.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_wrap_key(int asym_key_slot, int sym_key_slot, char** out_buff,
                                   size_t* out_buff_len, int* keyiv_hmac_slot);

/** \brief This function rewraps the key by decrypting the contents of memory specified as input
 *         using the Public key.
 *
 * \param[in]  asym_key_slot   Asymmetric key slot index.
 * \param[in]  peer_key_slot   Peer key slot index.
 * \param[in]  in_buff         Input buffer for decryption.
 * \param[in]  in_buff_len     Length of input buffer for decryption.
 * \param[out] out_buff        Output buffer to store decrypted data.
 * \param[out] out_buff_len    Length of the output buffer.
 * \param[out] keyiv_hmac_slot key/IV/HMAC slot index.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_rewrap_key(int asym_key_slot, int peer_key_slot, const char* in_buff,
                                     size_t in_buff_len, char** out_buff, size_t* out_buff_len,
                                     int* keyiv_hmac_slot);

/** \brief This function unwrap the key by decrypting the contents of memory specified as input
 *         using the Public key.
 *
 * \param[in]  asym_key_slot   Asymmetric key slot index.
 * \param[in]  peer_key_slot   Peer slot index.
 * \param[in]  in_buff         Input buffer for decryption.
 * \param[in]  in_buff_len     Length of input buffer for decryption.
 * \param[out] sym_key_slot    Symmetric key slot index.
 * \param[out] keyiv_hmac_slot key/IV/HMAC slot index.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_unwrap_key(int asym_key_slot, int peer_key_slot, const char* in_buff,
                                     size_t in_buff_len, int* sym_key_slot, int* keyiv_hmac_slot);

/** \brief This function extracts public key from the certificate.
 *
 * \param[in]  cert       Pointer to certificate to be used for extracting public key.
 * \param[out] public_key Pointer to store public key.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_extract_pubkey_certificate(const char* cert, char* public_key);

/** \brief This function computes the hash of the memory buffer.
 *
 * \param[in]  in_buff   Input buffer for hashing.
 * \param[in]  hash_alg  Hashing algorithm.
 * \param[out] out_buff  Output buffer to store the computed hashed.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_compute_hash(const char* in_buff, int hash_alg, unsigned char* out_buff,
                                       bool b64_format);

/** \brief This function verifies the entire certificate chain along with OCSP check.
 *
 * \param[in]  asym_key_slot            Asymmetric key slot index.
 * \param[in]  peer_cert                boolean value to indicate the peer certificate.
 * \param[in]  cert                     Pointer to certificate to be used for signature validation.
 * \param[in]  lifetime_validity_check  boolean value for lifetime validity check.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_verify_certificate(int asym_key_slot, bool peer_cert, const char* cert,
                                             bool lifetime_validity_check);

/** \brief This function extracts public key from certificate, verifies the certificate and
 *         adds the public key and certificate to the keystore.
 *
 * \param[in]  peer_cert                boolean value to indicate the peer certificate.
 * \param[in]  cert                     Pointer to certificate to be used for signature validation.
 * \param[in]  lifetime_validity_check  boolean value for lifetime validity check.
 * \param[out] peer_slot                Peer slot index.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_extract_pubkey_verify_cert(bool peer_cert, const char* cert,
                                                     bool lifetime_validity_check, int* peer_slot);

/** \brief This function generates GUID based on rand bytes
 *
 * \param[out] guid  Generated GUID.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_generate_guid(char* guid);

/** \brief This function generates symmetric Key based on rand bytes.
 *
 * \param[in]  key_size       Key size for random number generation.
 * \param[out] sym_key_slot   Symmetric key slot index.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_generate_symmetric_key(int key_size, int* sym_key_slot);

/** \brief This function computes ECDH shared key for asymmetric encryption based on the private
 *         key and corresponding peer public key.
 *
 * \param[in]  asym_key_slot   Asymmetric key slot index.
 * \param[in]  peer_key_slot   Peer key slot index.
 * \param[out] shared_key_slot Shared key slot index containing computed shared key.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_create_ecdh_key(int asym_key_slot, int peer_key_slot,
                                          int* shared_key_slot);

/** \brief This function derives key, IV and HMAC using password based key derivation.
 *
 * \param[in]  sym_key_slot    Symmetric key slot index.
 * \param[in]  in_buff         Input buffer for extracting salt.
 * \param[in]  in_buff_len     Length of input buffer.
 * \param[out] keyiv_hmac_slot key/IV/HMAC slot index.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_derive_keyiv_hmac(int sym_key_slot, const char* in_buff,
                                            size_t in_buff_len, int* keyiv_hmac_slot);

/** \brief This function encrypts the contents of memory specified as input using the
 *         encryption key.
 *
 * \param[in]  sym_key_slot    Symmetric key slot index.
 * \param[in]  in_buff         Input buffer for encryption.
 * \param[in]  in_buff_len     Length of input buffer for encryption.
 * \param[in]  magic_salt_buff Salt prefixed with magic buffer.
 * \param[out] out_buff        Output buffer to store encrypted data.
 * \param[out] out_buff_len    Length of the output buffer.
 * \param[out] keyiv_hmac_slot key/IV/HMAC slot index.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_encrypt_mem(int sym_key_slot, const char* in_buff, size_t in_buff_len,
                                      char* magic_salt_buff, char** out_buff, size_t* out_buff_len,
                                      int* keyiv_hmac_slot);

/** \brief This function decrypts the contents of memory specified as input using the
 *         decryption key.
 *
 * \param[in]  sym_key_slot    Symmetric key slot index.
 * \param[in]  in_buff         Input buffer for decryption.
 * \param[in]  in_buff_len     Length of input buffer for decryption.
 * \param[out] out_buff        Output buffer to store decrypted data.
 * \param[out] out_buff_len    Length of the output buffer.
 * \param[out] keyiv_hmac_slot key/IV/HMAC slot index.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_decrypt_mem(int sym_key_slot, const char* in_buff, size_t in_buff_len,
                                      char** out_buff, size_t* out_buff_len, int* keyiv_hmac_slot);

/** \brief This function clears the asymmetric primary and secondary key pairs from the
 *         asymmetric key slot.
 *
 * \param[in]  asym_key_slot  Asymmetric key slot index.
 */
void ovsa_crypto_clear_asymmetric_key_slot(int asym_key_slot);

/** \brief This function clears the specified symmetric key from the symmetric key slot.
 *
 * \param[in]  sym_key_slot  Symmetric key slot index.
 */
void ovsa_crypto_clear_symmetric_key_slot(int sym_key_slot);

/** \brief This function converts binary contents to base64 format.
 *
 * \param[in]  in_buff         Input buffer for conversion.
 * \param[in]  in_buff_len     Length of input buffer.
 * \param[out] out_buff        Output buffer to store pem formatted data.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_convert_bin_to_base64(const char* in_buff, size_t in_buff_len,
                                                char** out_buff);

/** \brief This function converts base64 formatted data to bin format.
 *
 * \param[in]  in_buff         Input buffer for conversion.
 * \param[in]  in_buff_len     Length of input buffer.
 * \param[out] out_buff        Output buffer to store bin formatted data.
 * \param[out] out_buff_len    Length of the output buffer.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_convert_base64_to_bin(const char* in_buff, size_t in_buff_len,
                                                char* out_buff, size_t* out_buff_len);

/** \brief This function extracts the issue date and expiry date from the certificate.
 *
 * \param[in]  cert        Pointer to certificate.
 * \param[out] issue_date  Pointer to store the issue date.
 * \param[out] expiry_date Pointer to store the expiry date.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_crypto_extract_cert_date(const char* cert, char* issue_date, char* expiry_date);

/** \brief This function gets the file size and points the file pointer to the begining of the file.
 *
 * \param[in]  fp  File pointer.
 *
 * \return File size or OVSA_ERROR
 */
int ovsa_crypto_get_file_size(FILE* fp);

/** \brief This function gives the current time.
 *
 * \param[out] ovsa_current_time    Pointer to store the current time.
 * \param[out] ovsa_current_time_tm Pointer to fill the tm structure.
 *
 * \return File size or OVSA_ERROR
 */
ovsa_status_t ovsa_get_current_time(time_t* ovsa_current_time, struct tm** ovsa_current_time_tm);

#endif /* __OVSA_LIBOVSA_H_ */
