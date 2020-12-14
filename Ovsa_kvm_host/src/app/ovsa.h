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

#ifndef __OVSA_H_
#define __OVSA_H_

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

#define MAX_PORT_LEN            5
#define MAX_IP_ADDR_STR_LEN     18
#define DEFAULT_TCP_PORT_NUMBER 4450
#define DEFAULT_HOST_IP         "192.168.122.1"
#define SA                      struct sockaddr

#define PAYLOAD_LENGTH      8
#define MAX_NAME_SIZE       256
#define TPM2_QUOTE_PCR_SIZE 3072
#define TPM2_QUOTE_MSG_SIZE 512
#define TPM2_QUOTE_SIG_SIZE 512
#define TPM2_PUBKEY_SIZE    512

#define CREATE_TMP_DIR_PATH(tmp_dir_path, sockfd)               \
    char fdbuf[5];                                              \
    snprintf(fdbuf, 5, "%d", sockfd);                           \
    memset_s(tmp_dir_path, sizeof(tmp_dir_path), 0);            \
    strcpy_s(tmp_dir_path, sizeof("/tmp/ovsa_"), "/tmp/ovsa_"); \
    strcat_s(tmp_dir_path, MAX_FILE_LEN, fdbuf);                \
    strcat_s(tmp_dir_path, MAX_FILE_LEN, "/");

#define CREATE_FILE_PATH(tmp_dir_path, key_file, TPM2_QUOTE_INFO)     \
    memset_s(key_file, sizeof(key_file), 0);                          \
    memcpy_s(key_file, MAX_FILE_LEN, tmp_dir_path, sizeof(key_file)); \
    strcat_s(key_file, MAX_FILE_LEN, TPM2_QUOTE_INFO);

#define TPM2_QUOTE_MSG   "pcr_quote.plain"
#define TPM2_QUOTE_SIG   "pcr_quote.signature"
#define TPM2_QUOTE_PCR   "pcr.bin"
#define TPM2_SESSION_CTX "session.ctx"
#define TPM2_NONCE_FILE  "nonce"
#define MAX_FILE_LEN     64

#define TPM2_AK_PUB_KEY "/var/OVSA/Quote/tpm_ak.pub.pem"
#define TPM2_EK_PUB_KEY "/var/OVSA/Quote/tpm_ek.pub.pem"
#define TPM2_EK_CERT    "/var/OVSA/Quote/tpm_ek_cert.pem"

#define MAX_COMMAND_TYPE_LENGTH 64

typedef enum { OVSA_SEND_HW_QUOTE, OVSA_INVALID_CMD } ovsa_host_cmd_t;

typedef struct ovsa_hw_quote_info {
    char* hw_quote_message;
    char* hw_quote_sig;
    char* hw_quote_pcr;
    char* hw_ak_pub_key;
    char* hw_ek_pub_key;
    char* hw_ek_cert;
} ovsa_hw_quote_info_t;

typedef enum {
    OVSA_OK                = 0,
    OVSA_INVALID_PARAMETER = -1,
    OVSA_INVALID_FILE_PATH = -2,
    OVSA_FILEOPEN_FAIL     = -3,
    OVSA_FILEIO_FAIL       = -4,
    OVSA_MEMORY_ALLOC_FAIL = -5,
    OVSA_MEMIO_ERROR       = -6,
    OVSA_NOTIMPL           = -7,

    /* CRYPTO */
    OVSA_CRYPTO_BIO_ERROR = -8,

    /* JSON ERRORS */
    OVSA_JSON_ERROR_ADD_ELEMENT   = -9,
    OVSA_JSON_MEMORY_ALLOC_FAIL   = -10,
    OVSA_JSON_ERROR_CREATE_OBJECT = -11,
    OVSA_JSON_ERROR_CREATE_DATA   = -12,
    OVSA_JSON_UNSUPPORTED_DATA    = -13,
    OVSA_JSON_INVALID_INPUT       = -14,
    OVSA_JSON_PARSE_FAIL          = -15,
    OVSA_JSON_PRINT_FAIL          = -16,

    /* SYSCALL EXECUTION ERRORS */
    OVSA_SYSCALL_EXECVE_FAIL      = -17,
    OVSA_SYSCALL_CREATE_PIPE_FAIL = -18,
    OVSA_SYSCALL_READ_PIPE_FAIL   = -19,
    OVSA_SYSCALL_FORK_FAIL        = -20,
    OVSA_SYSCALL_DUP2_FAIL        = -21,
    OVSA_SYSCALL_WAITPID_FAIL     = -22,

    OVSA_SOCKET_CONN_CLOSED = -23,
    OVSA_SOCKET_READ_FAIL   = -24,
    OVSA_SOCKET_WRITE_FAIL  = -25,

    /* TPM ERRORS */
    OVSA_TPM2_CMD_EXEC_FAIL = -26,
    OVSA_TPM2_GENERIC_ERROR = -27,

    OVSA_INVALID_HOST_CMD = -28,
    OVSA_RMDIR_FAIL       = -29,
    OVSA_RMFILE_FAIL      = -30,
    OVSA_CLOSEDIR_FAIL    = -31,
    OVSA_FAIL             = -99
} ovsa_status_t;
#endif
