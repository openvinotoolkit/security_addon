/*
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
 *
 */

#ifndef __OVSA_LICENSESERVICE_H_
#define __OVSA_LICENSESERVICE_H_
#include <mbedtls/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <stdint.h>

#include "tss2/tss2_tpm2_types.h"

#define MAX_NAME_SIZE           256
#define MAX_LEN                 5
#define MESSAGE_BLOB_TEXT_SIZE  34
#define GUID_SIZE               36
#define PAYLOAD_LENGTH          8 /* BYTE */
#define MAX_COMMAND_TYPE_LENGTH 50
#define MAX_FILE_NAME_LEN       10

#define mbedtls_printf      printf
#define READ_TIMEOUT_MS     300000 /* 30 seconds */
#define MBEDTLS_DEBUG_LEVEL 0

/* ! Size of the HASH key Considering SHA512 for HASHING */
#define HASH_B64_SIZE            192 /* Actual 130: Considering the length for B64 */
#define NONCE_SIZE               32
#define NONCE_BUF_SIZE           (NONCE_SIZE * 2) /* In B64 format */
#define MAX_SIGNATURE_SIZE       128
#define MAX_VERSION_SIZE         32
#define MAX_KEY_SIZE             512
#define MAX_EKEY_SIZE            128 /* actual size: 45 */
#define MAX_URL_SIZE             256
#define BUFSIZE                  1024 * 8
#define NULL_TERMINATOR          1
#define TCB_INFO_MAX_QUOTE_SIZE  3072
#define TCB_INFO_MAX_PUBKEY_SIZE 512
#define DEFAULT_RATLS_PORT       "4451"
#define DEFAULT_TLS_PORT         "4452"
#define MAX_BUF_SIZE             4096
#define MAX_FILE_LEN             64
#define TPM2_TPMU_HA_SIZE        64
#define DEFAULT_PCR_ID_SET       "0xFFFFFF" /*Set all PCR ID's 0:23 */
#define HASH_ALG_SHA256          1
#define HASH_ALG_SHA384          2
#define HASH_ALG_SHA512          3
#define QUOTE_NONCE_HASH_SIZE    32
/* Size of the HASH key Considering SHA512 for HASHING */
#define HASH_SIZE 192 /* Actual 130: Considering the length for B64 */

/* As per the ASN1_STRING_TABLE, computed max size of the attribute types
   found in the Distinguished Name are around ~129K and added certain buffer
   to accomadate the attributes where max size is not available. */
#define MAX_CERT_SIZE (256UL << 10) /* 256KB */

/* self signed server certificate based on sha384 */
#define CERTIFICATE_PATH "/opt/ovsa/certs/server.crt"
/* server private key based on ECC secp521r1 curve */
#define KEY_PATH          "/opt/ovsa/certs/server.key"
#define CURVE_LIST_SIZE   2
#define CIPHER_SUITE_SIZE 1

#define TPM2_SWQUOTE_MSG        "SW_pcr_quote.plain"
#define TPM2_AK_HWPUB_PEM_KEY   "HW_pub_key.pub"
#define TPM2_HWQUOTE_SIG        "HW_pcr_quote.signature"
#define TPM2_HWQUOTE_MSG        "HW_pcr_quote.plain"
#define TPM2_HWQUOTE_PCR        "HW_pcr.bin"
#define TPM2_CREDOUT_FILE       "cred.out"
#define TPM2_SWQUOTE_PCR        "SW_pcr.bin"
#define TPM2_SWQUOTE_SIG        "SW_pcr_quote.signature"
#define TPM2_AK_PUB_PEM_KEY     "SW_pub_key.pub"
#define TPM2_EK_PUB_KEY         "tpm_ek.pub"
#define TPM2_SWQUOTE_EK_CERT    "tpm_ek_cert.bin"
#define TPM2_AK_NAME_HEX        "tpm_ak.name.hex"
#define QUOTE_NONCE             "server_quote_nonce.bin"
#define SECRET_NONCE            "secret.bin"
#define TPM2_HWQUOTE_NONCE_FILE "hw_quote_nonce.bin"
#define TPM2_SWQUOTE_NONCE_FILE "sw_quote_nonce.bin"

#ifdef ENABLE_SGX_GRAMINE
#define SGX_ENCLAVE_HASH_SIZE 65
#endif

#define TPM2_MAX_PCRS 32

#define DBG_E 0x01
#define DBG_I 0x02
#define DBG_D 0x04

#if DEBUG == 2
#define DBG_LEVEL (DBG_E | DBG_I | DBG_D)
#elif DEBUG == 1
#define DBG_LEVEL (DBG_E | DBG_I)
#elif DEBUG == 0
#define DBG_LEVEL (DBG_E)
#endif

#define OVSA_DBG(class, fmt...)  \
    do {                         \
        if ((class) & DBG_LEVEL) \
            printf(fmt);         \
    } while (0)

#define CREATE_TMP_DIR_PATH(tmp_dir_path, client_fd)            \
    char fdbuf[5];                                              \
    snprintf(fdbuf, 5, "%d", client_fd);                        \
    memset_s(tmp_dir_path, sizeof(tmp_dir_path), 0);            \
    strcpy_s(tmp_dir_path, sizeof("/tmp/ovsa_"), "/tmp/ovsa_"); \
    strcat_s(tmp_dir_path, MAX_FILE_LEN, fdbuf);                \
    strcat_s(tmp_dir_path, MAX_FILE_LEN, "/");

#define CREATE_FILE_PATH(tmp_dir_path, key_file, TPM2_QUOTE_INFO)     \
    memset_s(key_file, sizeof(key_file), 0);                          \
    memcpy_s(key_file, MAX_FILE_LEN, tmp_dir_path, sizeof(key_file)); \
    strcat_s(key_file, MAX_FILE_LEN, TPM2_QUOTE_INFO);

#ifdef ENABLE_SGX_GRAMINE
typedef int (*sgx_measurements_cb_t)(const char* mrenclave, const char* mrsigner,
                                     const char* isv_prod_id, const char* isv_svn);
#endif

typedef int (*ovsa_license_service_cb_t)(void* ssl, void* data);
typedef char GUID[GUID_SIZE + 1];

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
    char* ROM_cert;
    char* Chain_cert;
} ovsa_ek_ak_bind_info_t;

typedef struct {
    size_t count;
    TPML_DIGEST pcr_values[TPM2_MAX_PCRS];
} tpm2_pcrs;

typedef enum {
    OVSA_SEND_NONCE = 0,
    OVSA_SEND_EK_AK_BIND,
    OVSA_SEND_EK_AK_BIND_INFO,
    OVSA_SEND_QUOTE_NONCE,
    OVSA_SEND_SIGN_NONCE,
    OVSA_SEND_QUOTE_INFO,
    OVSA_SEND_CUST_LICENSE,
    OVSA_SEND_UPDATE_CUST_LICENSE,
    OVSA_SEND_UPDATE_CUST_LICENSE_ACK,
    OVSA_SEND_LICENSE_CHECK_RESP,
    OVSA_INVALID_CMD
} ovsa_command_type_t;

/* Enum values for license type */
typedef enum { SALE = 0, INSTANCELIMIT, TIMELIMIT, MAXLICENSETYPE } ovsa_license_type_t;

typedef enum {
    /* OVSA */
    OVSA_OK                = 0,
    OVSA_INVALID_PARAMETER = -1,
    OVSA_INVALID_FILE_PATH = -2,
    OVSA_FILEOPEN_FAIL     = -3,
    OVSA_FILEIO_FAIL       = -4,
    OVSA_MEMORY_ALLOC_FAIL = -5,
    OVSA_MEMIO_ERROR       = -6,
    OVSA_NOTIMPL           = -7,

    /* CRYPTO */
    OVSA_CRYPTO_ECKEY_ERROR      = -8,
    OVSA_CRYPTO_BIO_ERROR        = -9,
    OVSA_CRYPTO_EVP_ERROR        = -10,
    OVSA_CRYPTO_PEM_ENCODE_ERROR = -11,
    OVSA_CRYPTO_X509_ERROR       = -12,
    OVSA_CRYPTO_OCSP_ERROR       = -13,
    OVSA_CRYPTO_GENERIC_ERROR    = -14,

    /* JSON ERRORS */
    OVSA_JSON_ERROR_ADD_ELEMENT   = -15,
    OVSA_JSON_MEMORY_ALLOC_FAIL   = -16,
    OVSA_JSON_ERROR_CREATE_OBJECT = -17,
    OVSA_JSON_ERROR_CREATE_DATA   = -18,
    OVSA_JSON_UNSUPPORTED_DATA    = -19,
    OVSA_JSON_INVALID_INPUT       = -20,
    OVSA_JSON_PARSE_FAIL          = -21,
    OVSA_JSON_PRINT_FAIL          = -22,

    /* License Service */
    OVSA_LICENCE_SERVER_START_FAIL                = -23,
    OVSA_MBEDTLS_SSL_WRITE_FAILED                 = -24,
    OVSA_MBEDTLS_SSL_READ_FAILED                  = -25,
    OVSA_MBEDTLS_SSL_CLOSE_FAILED                 = -26,
    OVSA_MBEDTLS_SSL_SETUP_FAILED                 = -27,
    OVSA_MBEDTLS_SSL_HANDSHAKE_FAILED             = -28,
    OVSA_MBEDTLS_SSL_X509_CERT_VERIFY_FAILED      = -29,
    OVSA_MBEDTLS_CTR_DRBG_SEED_FAILED             = -30,
    OVSA_MBEDTLS_x509_CERT_PARSE_FAILED           = -31,
    OVSA_MBEDTLS_PK_PARSE_KEYFILE_FAILED          = -32,
    OVSA_MBEDTLS_NET_BIND_FAILED                  = -33,
    OVSA_MBEDTLS_SSL_CONFIG_DEFAULTS_FAILED       = -34,
    OVSA_MBEDTLS_SSL_CONFIG_OWN_CERT              = -35,
    OVSA_TCB_VALIDATION_FAILED                    = -36,
    OVSA_TPM2_CREDENTIAL_SECRET_VALIDATION_FAILED = -37,
    OVSA_INVALID_CMD_TYPE                         = -38,

    /* DB */
    OVSA_DB_INIT_FAIL       = -39,
    OVSA_DB_UPDATE_FAIL     = -40,
    OVSA_DB_QUERY_FAIL      = -41,
    OVSA_DB_TIMELIMT_FAIL   = -42,
    OVSA_DB_USAGELIMIT_FAIL = -43,

    /* TPM2 command */
    OVSA_SYSCALL_READ_PIPE_FAIL = -44,
    OVSA_SYSCALL_DUP2_FAIL      = -45,
    OVSA_TPM2_GENERIC_ERROR     = -46,
    OVSA_TPM2_CMD_EXEC_FAIL     = -47,
    OVSA_SYSCALL_WAITPID_FAIL   = -48,
    OVSA_SYSCALL_EXECVE_FAIL    = -49,
    OVSA_SYSCALL_FORK_FAIL      = -50,
    OVSA_RMDIR_FAIL             = -51,
    OVSA_RMFILE_FAIL            = -52,
    OVSA_CLOSEDIR_FAIL          = -53,

    OVSA_INTEGER_OVERFLOW      = -54,
    OVSA_INTEGER_UNDERFLOW     = -55,
    OVSA_PCR_VALIDATION_FAILED = -56,
    OVSA_PCR_ID_NOT_VALID      = -57,
    OVSA_TCB_NOT_VALID         = -58,

    OVSA_FAIL = -99
} ovsa_status_t;

typedef char GUID[GUID_SIZE + 1];
/* TCB Signature list in Customer License
   This is going to contain the TCB Signature JSON blob */

/* To Store list of License Server URL for License Config Struct */
typedef struct ovsa_license_serv_url_list {
    char license_serv_url[MAX_URL_SIZE];
    char cur_cert_hash[HASH_SIZE];
    char fut_cert_hash[HASH_SIZE];
    struct ovsa_license_serv_url_list* next;
} ovsa_license_serv_url_list_t;

/* TCB Signature Struct */
typedef struct ovsa_tcb_info {
    char tcb_name[MAX_NAME_SIZE];
    char tcb_version[MAX_VERSION_SIZE];
    char hw_quote[TCB_INFO_MAX_QUOTE_SIZE];
    char sw_quote[TCB_INFO_MAX_QUOTE_SIZE];
    char hw_pub_key[TCB_INFO_MAX_PUBKEY_SIZE];
    char sw_pub_key[TCB_INFO_MAX_PUBKEY_SIZE];
    char sw_pcr_id_set[TPM2_MAX_PCRS];
    char hw_pcr_id_set[TPM2_MAX_PCRS];
#ifdef ENABLE_SGX_GRAMINE
    char mrenclave[SGX_ENCLAVE_HASH_SIZE];
    char mrsigner[SGX_ENCLAVE_HASH_SIZE];
    int isv_svn;
    int isv_prod_id;
#endif
    char* isv_certificate;
} ovsa_tcb_info_t;

typedef struct ovsa_tcb_sig_list {
    char* tcb_signature;
    struct ovsa_tcb_sig_list* next;
} ovsa_tcb_sig_list_t;

/* TCB Signature Struct with Signature */
typedef struct ovsa_tcb_sig {
    char signature[MAX_SIGNATURE_SIZE];
    ovsa_tcb_info_t tcbinfo;
} ovsa_tcb_sig_t;

/* Customer License Struct */
typedef struct ovsa_customer_license {
    char license_name[MAX_NAME_SIZE];
    char license_version[MAX_VERSION_SIZE];
    char creation_date[MAX_NAME_SIZE];
    char model_hash[HASH_B64_SIZE];
    char encryption_key[MAX_EKEY_SIZE];
    ovsa_license_type_t license_type;
    int usage_count;
    int time_limit;
    GUID license_guid;
    GUID model_guid;
    char* isv_certificate;
    ovsa_license_serv_url_list_t* license_url_list;
    ovsa_tcb_sig_list_t* tcb_signatures;
} ovsa_customer_license_t;

/* License Info Struct with Signature */
typedef struct ovsa_customer_license_sig {
    char signature[MAX_SIGNATURE_SIZE];
    ovsa_customer_license_t customer_lic;
} ovsa_customer_license_sig_t;

/** \brief This function reads the Private/Public Key
 *
 * \param[in] P_Key        Pointer to read the Private/Public Key.
 * \param[in] key_descrip  Description of the key.
 *
 * \return Pointer to the key on Success or NULL in Failure
 */
EVP_PKEY* ovsa_license_service_crypto_load_key(const char* p_Key, const char* key_descrip);

/** \brief This function does signing, verification and hashing operation.
 *
 * \param[in]  buf    Buffer pointer for reading the input data.
 * \param[in]  inp    Pointer to input data.
 * \param[in]  key    Pointer to Private or Public key used for signing or
 * verification. \param[in]  sigin  Signature buffer to read the signature.
 * \param[in]  siglen Size of the private/public key.
 * \param[in]  file   Pointer to input file.
 * \param[out] out    Generated signature.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_license_service_crypto_do_sign_verify_hash(unsigned char* buf, BIO* inp,
                                                              const EVP_PKEY* key,
                                                              const unsigned char* sigin,
                                                              int siglen, const char* file,
                                                              BIO* out);

/** \brief This function reads the certificate
 *
 * \param[in] cert          Pointer to read the certificate.
 * \param[in] cert_descrip  Description of the certificate.
 *
 * \return Pointer to the certificate on Success or NULL in Failure
 */
X509* ovsa_license_service_crypto_load_cert(const char* cert, const char* cert_descrip);

/** \brief This function verifies whether the certificate is valid.
 *
 * \param[in]  cert    Pointer to certificate.
 *
 * \param[in]  cert_chain    Pointer to certificate chain.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_license_service_crypto_verify_certificate(const char* cert,
                                                             const char* cert_chain);

/** \brief This function extracts public key from the certificate.
 *
 * \param[in]  cert   Pointer to certificate to be used for extracting public
 * key. \param[out] Pubkey Pointer to store public key.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_license_service_crypto_extract_pubkey_certificate(const char* cert,
                                                                     char* pubkey);

/** \brief This function verifies the signature of the input buffer with the
 * specified signature using the public key from the key slot.
 *
 * \param[in]  asym_key_slot  Asymmetric key slot index.
 * \param[in]  in_buff        Input buffer for verification.
 * \param[in]  in_buff_len    Length of input buffer for verification.
 * \param[in]  signature      Pointer to signature to be used for verification.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_license_service_crypto_verify_mem(const char* cert, const char* in_buff,
                                                     size_t in_buff_len, char* signature);
/** \brief This function converts binary contents to pem format.
 *
 * \param[in]  in_buff         Input buffer for conversion.
 * \param[in]  in_buff_len     Length of input buffer.
 * \param[out] out_buff        Output buffer to store pem formatted data.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_license_service_crypto_convert_bin_to_pem(const char* in_buff,
                                                             size_t in_buff_len, char** out_buff);

/** \brief This function converts pem formatted data to bin format.
 *
 * \param[in]  in_buff         Input buffer for conversion.
 * \param[in]  in_buff_len     Length of input buffer.
 * \param[out] out_buff        Output buffer to store bin formatted data.
 * \param[out] out_buff_len    Length of the output buffer.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_license_service_crypto_convert_base64_to_bin(const char* in_buff,
                                                                size_t in_buff_len, char* out_buff,
                                                                size_t* out_buff_len);
/** \brief This function generates nonce and send json message payload to client.
 *
 * \param[out] out_buff        Output buffer to store nonce buffer.
 * \param[out] out_buff        Output buffer to store json message blob buffer..
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_license_service_generate_nonce_payload(char** nonce_buf, char** json_payload);
/** \brief This function generates nonce .
 *
 * \param[out] out_buff        Output buffer to store nonce buffer.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_license_service_create_nonce(char** nonce_buf);
/** \brief This function verifies the signature of the input buffer with the specified signature
 *         using the public key from the key slot.
 *
 * \param[in]  in_buff        Input certificate buffer to extract public key for verfication.
 * \param[in]  in_buff        Input buffer for verification.
 * \param[in]  in_buff_len    Length of input buffer for verification.
 * \param[in]  signature      Pointer to signature to be used for verification.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_license_service_crypto_verify_mem(const char* cert, const char* in_buff,
                                                     size_t in_buff_len, char* signature);
/** \brief This function extracts public key from the certificate.
 *
 * \param[in]  cert       Pointer to certificate to be used for extracting public key.
 * \param[out] public_key Pointer to store public key.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_license_service_crypto_extract_pubkey_certificate(const char* cert,
                                                                     char* public_key);

/** \brief This function computes the hash of the memory buffer.
 *
 * \param[in]  in_buff   Input buffer for hashing.
 * \param[in]  hash_alg  Hashing algorithm.
 * \param[out] out_buff  Output buffer to store the computed hashed.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_license_service_crypto_compute_hash(const char* in_buff, int hash_alg,
                                                       char* out_buff, bool b64_format);

/** \brief This function converts binary to base64 format of the buffer.
 *
 * \param[in]  in_buff      Input buffer in binary.
 * \param[in]  in_buff_len  Buffer length.
 * \param[out] out_buff     Output buffer in base64.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_license_service_crypto_convert_bin_to_base64(const char* in_buff,
                                                                size_t in_buff_len,
                                                                char** out_buff);
#ifdef ENABLE_SGX_GRAMINE
int ra_tls_verify_callback(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags);
void ra_tls_set_measurement_callback(int (*f_cb)(const char* mrenclave, const char* mrsigner,
                                                 const char* isv_prod_id, const char* isv_svn));
ovsa_status_t ovsa_license_service_sgx_measurements_callback(const char* mrenclave,
                                                             const char* mrsigner,
                                                             const char* isv_prod_id,
                                                             const char* isv_svn);
#endif

#endif
