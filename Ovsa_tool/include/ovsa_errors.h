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

#ifndef __OVSA_ERRORS_H_
#define __OVSA_ERRORS_H_

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

#ifndef ENABLE_SGX_GRAMINE
    /* SYSCALL EXECUTION ERRORS */
    OVSA_SYSCALL_EXECVE_FAIL      = -23,
    OVSA_SYSCALL_GETENV_PATH_FAIL = -24,
    OVSA_SYSCALL_CREATE_PIPE_FAIL = -25,
    OVSA_SYSCALL_READ_PIPE_FAIL   = -26,
    OVSA_SYSCALL_FORK_FAIL        = -27,
    OVSA_SYSCALL_DUP2_FAIL        = -28,
    OVSA_SYSCALL_WAITPID_FAIL     = -29,
#endif

    /* Runtime ERRORS */
    OVSA_LICENSE_CHECK_FAIL          = -30,
    OVSA_INVALID_CMD_TYPE            = -31,
    OVSA_LICENSE_SERVER_CONNECT_FAIL = -32,

#ifndef ENABLE_SGX_GRAMINE
    /* TPM ERRORS */
    OVSA_TPM2_CMD_EXEC_FAIL = -33,
    OVSA_TPM2_GENERIC_ERROR = -34,
#endif

    /* License Time calculation ERRORS */
    OVSA_TIME_SYSTIME_ERROR         = -35,
    OVSA_TIME_LICEXPIRED_ERROR      = -36,
    OVSA_TIME_DURATIONEXCEEDS_ERROR = -37,

    /* Synchronization ERRORS */
    OVSA_MUTEX_LOCK_FAIL    = -38,
    OVSA_MUTEX_UNLOCK_FAIL  = -39,
    OVSA_MUTEX_INIT_FAIL    = -40,
    OVSA_MUTEX_DESTROY_FAIL = -41,

    /* SOCK CONN ERRORS */
    OVSA_SOCKET_CONN_FAIL   = -42,
    OVSA_SOCKET_READ_FAIL   = -43,
    OVSA_SOCKET_WRITE_FAIL  = -44,
    OVSA_SOCKET_CONN_CLOSED = -45,

    OVSA_INTEGER_OVERFLOW                              = -46,
    OVSA_INTEGER_UNDERFLOW                             = -47,
    OVSA_PEER_CERT_HASH_VALIDATION_FAILED              = -48,
    OVSA_CONTROLED_ACCESS_MODEL_HASH_VALIDATION_FAILED = -49,

    OVSA_FAIL = -99
} ovsa_status_t;
#endif /* __OVSA_ERRORS_H_ */
