/*
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
 *
 */

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cJSON.h"
#include "db.h"
#include "json.h"
#include "license_service.h"
#include "mbedtls/certs.h"
#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "safe_str_lib.h"
#include "utils.h"

#define mbedtls_printf      printf
#define READ_TIMEOUT_MS     20000 /* 20 seconds */
#define MBEDTLS_DEBUG_LEVEL 0

static const char* g_cipher_suitename[CIPHER_SUITE_SIZE] = {
    "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"};
static int g_cipher_suite[CIPHER_SUITE_SIZE];
static mbedtls_ecp_group_id g_curve_list[CURVE_LIST_SIZE];

static pthread_mutex_t g_print_lock;
static mbedtls_ssl_config g_conf;

static ovsa_status_t ovsa_license_service_write(void* ssl, const uint8_t* buf, size_t len);
static ovsa_status_t ovsa_license_service_read(void* ssl, uint8_t* buf, size_t len);
static ovsa_status_t ovsa_license_service_start(const char* in_servers,
                                                const char* in_ca_chain_path, void** out_ssl);
static ovsa_status_t ovsa_license_service_start_server(const char* cert_path, const char* key_path,
                                                       ovsa_license_service_cb_t f_cb);
static ovsa_status_t ovsa_license_service_close(void* ssl);

static char g_port[MAX_LEN];

static void ovsa_mbedtls_debug_cb(void* ctx, int level, const char* file, int line,
                                  const char* str) {
    const char *p, *basename;
    (void)ctx;

    /* Extract basename from file */
    for (p = basename = file; *p != '\0'; p++) {
        if (*p == '/' || *p == '\\') {
            basename = p + 1;
        }
    }

    mbedtls_printf("%s:%04d: |%d| %s", basename, line, level, str);
}
static ovsa_status_t remove_directory(const char* path) {
    ovsa_status_t ret = OVSA_OK;
    size_t path_len   = 0;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    DIR* tmpdirectory = opendir(path);
    ret               = ovsa_server_get_string_length((char*)path, &path_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of path string %d\n", ret);
        return OVSA_FAIL;
    }
    if (tmpdirectory) {
        struct dirent* directory_entry;
        while (directory_entry = readdir(tmpdirectory)) {
            char* buf;
            size_t len;

            /* Skip the names "." and ".." */
            if (!strcmp(directory_entry->d_name, ".") || !strcmp(directory_entry->d_name, ".."))
                continue;
            len = path_len + strlen(directory_entry->d_name) + 2;
            ret = ovsa_server_safe_malloc(sizeof(char) * len, &buf);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "Error:memory alloc failed with code %d\n", ret);
                return OVSA_MEMORY_ALLOC_FAIL;
            }
            if (buf) {
                struct stat statbuf;
                snprintf(buf, len, "%s%s", path, directory_entry->d_name);
                OVSA_DBG(DBG_D, "OVSA:Deleting '%s' file \n", buf);

                if (!stat(buf, &statbuf)) {
                    ret = unlink(buf);
                    if (ret != OVSA_OK) {
                        ovsa_server_safe_free(&buf);
                        return OVSA_RMFILE_FAIL;
                    }
                }
                ovsa_server_safe_free(&buf);
            }
        }
        ret = closedir(tmpdirectory);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error:close directory  failed with code %d\n", ret);
            return OVSA_CLOSEDIR_FAIL;
        }
        OVSA_DBG(DBG_D, "OVSA:Deleting '%s' directory \n", path);
        ret = rmdir(path);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error:remove directory  failed with code %d\n", ret);
            return OVSA_RMDIR_FAIL;
        }
    }
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}
static void ovsa_remove_quote_files(int client_fd) {
    ovsa_status_t ret = OVSA_OK;
    char tmp_dir[MAX_FILE_LEN];

    CREATE_TMP_DIR_PATH(tmp_dir, client_fd);
    ret = remove_directory(tmp_dir);
    OVSA_DBG(DBG_D, "OVSA:Removed the Quote files from /tmp directory\n");
}
static ovsa_status_t ovsa_send_nonce_to_client(void** _ssl_session, const char* json_payload) {
    ovsa_status_t ret  = OVSA_OK;
    void* ssl_session  = NULL;
    ssl_session        = *_ssl_session;
    size_t payload_len = 0;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /*Send nonce for customer validation */
    ret = ovsa_server_get_string_length((char*)json_payload, &payload_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of json_payload string %d\n", ret);
        goto out;
    }
    ret = ovsa_license_service_write(ssl_session, json_payload, payload_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: license service write communicaton failed %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA:Sending nonce for customer license service\n");

out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static int ovsa_server_do_run_tpm2_command(char* const argv[], char* output) {
    ovsa_status_t ret     = OVSA_OK;
    size_t cmd_output_len = 0;
    int child_status = 0, nbytes = 0, link[2];
    pid_t child_pid;
    char cmd_output[MAX_BUF_SIZE];
    int dup2_ret    = 0;
    int waitpid_ret = 0;

    if ((argv == NULL) || (argv[0] == NULL)) {
        OVSA_DBG(DBG_E, "Error: tpm2 command failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    if (pipe(link) == -1) {
        OVSA_DBG(DBG_E, "Error: tpm2 command failed in creating pipe\n");
        return OVSA_SYSCALL_READ_PIPE_FAIL;
    }
    child_pid = fork();
    if (child_pid == 0) {
        int err = -1;
        if (dup2(link[1], STDOUT_FILENO) == -1) {
            OVSA_DBG(DBG_E, "Error: tpm2 command failed in dup2 syscall\n");
            return OVSA_SYSCALL_DUP2_FAIL;
        }
        close(link[0]);
        close(link[1]);
        err = execve(argv[0], argv, NULL);
        /* if it got here, it's an error */
        OVSA_DBG(DBG_E, "Error: Executing %s failed with error %s\n", argv[0], strerror(errno));
        return OVSA_SYSCALL_EXECVE_FAIL;
    } else if (child_pid < 0) {
        OVSA_DBG(DBG_E, "Error: TPM2 command failed in fork\n");
        return OVSA_SYSCALL_FORK_FAIL;
    }
    close(link[1]);

    if (output != NULL) {
        memset_s(cmd_output, sizeof(cmd_output), 0);
        nbytes = read(link[0], cmd_output, sizeof(cmd_output));
        if (nbytes > 0) {
            cmd_output_len = strnlen_s(cmd_output, MAX_BUF_SIZE);
            if (cmd_output_len == EOK) {
                OVSA_DBG(DBG_E,
                         "Error: tpm2 command failed in getting the size of the "
                         "command output\n");
                return OVSA_TPM2_GENERIC_ERROR;
            }
            if (memcpy_s(output, MAX_BUF_SIZE, cmd_output, cmd_output_len) != EOK) {
                OVSA_DBG(DBG_E, "Error: tpm2 command failed in getting the output\n");
                return OVSA_MEMIO_ERROR;
            }
        } else {
            OVSA_DBG(DBG_E, "Error: tpm2 command failed in executing the tpm2 command\n");
            return OVSA_TPM2_CMD_EXEC_FAIL;
        }
    }
    if ((waitpid(child_pid, &child_status, 0)) == -1) {
        OVSA_DBG(DBG_E, "Error: tpm2 command failed in waitpid\n");
        return OVSA_SYSCALL_WAITPID_FAIL;
    }
    if (WIFEXITED(child_status)) {
        int exit_status = WEXITSTATUS(child_status);
        if (exit_status != 0) {
            OVSA_DBG(DBG_E, "Error: Execution of TPM2 command %s failed\n", argv[1]);
            return OVSA_SYSCALL_WAITPID_FAIL;
        }
    }
    return ret;
}

static ovsa_status_t ovsa_server_tpm2_verifyquote(int client_fd) {
    ovsa_status_t ret = OVSA_OK;
    char tmp_dir[MAX_FILE_LEN];
    char ak_pub_pem_key_file[MAX_FILE_LEN];
    char quote_nonce_file[MAX_FILE_LEN];
    char swquote_sig_file[MAX_FILE_LEN];
    char swquote_pcr_file[MAX_FILE_LEN];
    char hwquote_pcr_file[MAX_FILE_LEN];
    char hwquote_msg_file[MAX_FILE_LEN];
    char hwquote_sig_file[MAX_FILE_LEN];
    char ak_hwpub_pem_key_file[MAX_FILE_LEN];
    char swquote_msg_file[MAX_FILE_LEN];

    CREATE_TMP_DIR_PATH(tmp_dir, client_fd);
    CREATE_FILE_PATH(tmp_dir, ak_pub_pem_key_file, TPM2_AK_PUB_PEM_KEY);
    CREATE_FILE_PATH(tmp_dir, quote_nonce_file, QUOTE_NONCE);
    CREATE_FILE_PATH(tmp_dir, swquote_sig_file, TPM2_SWQUOTE_SIG);
    CREATE_FILE_PATH(tmp_dir, swquote_pcr_file, TPM2_SWQUOTE_PCR);
    CREATE_FILE_PATH(tmp_dir, hwquote_pcr_file, TPM2_HWQUOTE_PCR);
    CREATE_FILE_PATH(tmp_dir, hwquote_msg_file, TPM2_HWQUOTE_MSG);
    CREATE_FILE_PATH(tmp_dir, hwquote_sig_file, TPM2_HWQUOTE_SIG);
    CREATE_FILE_PATH(tmp_dir, ak_hwpub_pem_key_file, TPM2_AK_HWPUB_PEM_KEY);
    CREATE_FILE_PATH(tmp_dir, swquote_msg_file, TPM2_SWQUOTE_MSG);
    char* const verify_sw_quote_argv[] = {
        "/usr/bin/sudo",   "tpm2_checkquote", "--public",       ak_pub_pem_key_file, "--message",
        swquote_msg_file,  "--signature",     swquote_sig_file, "--hash-algorithm",  "sha256",
        "--qualification", quote_nonce_file,  "--pcr",          swquote_pcr_file,    0};
#ifndef DISABLE_TPM2_HWQUOTE
    char* const verify_hw_quote_argv[] = {
        "/usr/bin/sudo",   "tpm2_checkquote", "--public",       ak_hwpub_pem_key_file, "--message",
        hwquote_msg_file,  "--signature",     hwquote_sig_file, "--hash-algorithm",    "sha256",
        "--qualification", quote_nonce_file,  "--pcr",          hwquote_pcr_file,      0};
#endif

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    /* Verify SW quote */
    ret = ovsa_server_do_run_tpm2_command(verify_sw_quote_argv, NULL);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Command %s failed to execute \n", verify_sw_quote_argv[1]);
        goto out;
    }
    OVSA_DBG(DBG_I, "SW Quote verification successful...\n");
#ifndef DISABLE_TPM2_HWQUOTE
    /* Verify HW quote */
    ret = ovsa_server_do_run_tpm2_command(verify_hw_quote_argv, NULL);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Command %s failed to execute \n", verify_hw_quote_argv[1]);
        goto out;
    }
    OVSA_DBG(DBG_I, "HW Quote verification successful...\n");
#endif
out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_do_validate_quote(ovsa_quote_info_t sw_quote_info,
                                            ovsa_quote_info_t hw_quote_info,
                                            ovsa_customer_license_sig_t customer_lic_sig) {
    ovsa_status_t ret             = OVSA_OK;
    ovsa_tcb_sig_list_t* tcb_list = NULL;
    char* tcb_signature           = NULL;
    ovsa_tcb_sig_t tsig;
    bool is_valid_TCB = false;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    tcb_list                     = customer_lic_sig.customer_lic.tcb_signatures;
    tsig.tcbinfo.isv_certificate = NULL;
    if (tcb_list == NULL) {
        OVSA_DBG(DBG_E, "Error: tcb signature empty  \n");
    } else {
        while (tcb_list != NULL) {
            tcb_signature = tcb_list->tcb_signature;
            /* Read TCB info from tcb_signature */
            memset_s(&tsig, sizeof(ovsa_tcb_sig_t), 0);
            ret = ovsa_server_json_extract_tcb_signature(tcb_signature, &tsig);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "Error: Read tcb_signature failed %d\n", ret);
                goto out;
            }
            ovsa_server_safe_free(&tsig.tcbinfo.isv_certificate);
            OVSA_DBG(DBG_D, "\n\n");
            OVSA_DBG(DBG_D, "OVSA:TCB_NAME    : '%s' \n", tsig.tcbinfo.tcb_name);
            OVSA_DBG(DBG_D, "OVSA:sw_quote    : '%s' \n", tsig.tcbinfo.sw_quote);
            OVSA_DBG(DBG_D, "OVSA:sw_pub_key  : '%s' \n", tsig.tcbinfo.sw_pub_key);
#ifndef DISABLE_TPM2_HWQUOTE
            OVSA_DBG(DBG_D, "OVSA:hw_quote    : '%s' \n", tsig.tcbinfo.hw_quote);
            OVSA_DBG(DBG_D, "OVSA:hw_pub_key  : '%s' \n", tsig.tcbinfo.hw_pub_key);
#endif
            OVSA_DBG(DBG_D, "\n");

            if (!(strcmp(tsig.tcbinfo.sw_quote, sw_quote_info.quote_pcr))
#ifndef DISABLE_TPM2_HWQUOTE
                && !(strcmp(tsig.tcbinfo.hw_quote, hw_quote_info.quote_pcr))
#endif
            ) {
                OVSA_DBG(DBG_I, "OVSA:Customer '%s' is valid\n\n", tsig.tcbinfo.tcb_name);
                is_valid_TCB = true;
                break;
            } else
                OVSA_DBG(DBG_I, "OVSA:Customer '%s' is not valid\n\n", tsig.tcbinfo.tcb_name);
            tcb_list = tcb_list->next;
        }
    }
    if (!is_valid_TCB) {
        OVSA_DBG(DBG_E, "Error: TCB Validation failed\n");
        ret = OVSA_TCB_VALIDATION_FAILED;
        goto out;
    } else {
        OVSA_DBG(DBG_I, "OVSA:TCB check PASS \n");
    }

out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_do_validate_secret(char* payload_quote_info, int client_fd) {
    ovsa_status_t ret    = OVSA_OK;
    char* secret_buf     = NULL;
    char* credsecret_buf = NULL;
    size_t file_size     = 0;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /* Read received secret from json file */
    ret = ovsa_server_json_extract_element(payload_quote_info, "Secret", (void**)&secret_buf);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
        goto out;
    }
    /* Read credential secret nonce */
    file_size = 0;
    char tmp_nonce_file[MAX_FILE_LEN];
    CREATE_TMP_DIR_PATH(tmp_nonce_file, client_fd);
    strcat(tmp_nonce_file, SECRET_NONCE);
    ret = ovsa_read_file_content(tmp_nonce_file, &credsecret_buf, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E,
                 "Error: Reading credential secret nonce file failed with error "
                 "code %d\n",
                 ret);
        goto out;
    }
    if (!(strcmp(secret_buf, credsecret_buf))) {
        OVSA_DBG(DBG_I, "\nOVSA: Secret Validation PASS\n\n");
    } else {
        ret = OVSA_TPM2_CREDENTIAL_SECRET_VALIDATION_FAILED;
        OVSA_DBG(DBG_E, "OVSA: Error: Secret Validation failed %d\n", ret);
    }
out:
    ovsa_server_safe_free(&secret_buf);
    ovsa_server_safe_free(&credsecret_buf);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

#ifndef DISABLE_TPM2_HWQUOTE
static ovsa_status_t ovsa_extract_HW_quote_info(char* payload_quote_info,
                                                ovsa_quote_info_t* hw_quote_info, int client_fd) {
    ovsa_status_t ret                     = OVSA_OK;
    char* pcr_quote_message_bin_buff      = NULL;
    size_t pcr_quote_message_bin_length   = 0;
    char* pcr_quote_signature_bin_buff    = NULL;
    size_t pcr_quote_signature_bin_length = 0;
    char* pcr_bin_buff                    = NULL;
    size_t pcr_bin_length                 = 0;
    size_t size                           = 0;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    char tmp_dir[MAX_FILE_LEN];
    char hwquote_pcr_file[MAX_FILE_LEN];
    char hwquote_msg_file[MAX_FILE_LEN];
    char hwquote_sig_file[MAX_FILE_LEN];
    char ak_hwpub_pem_key_file[MAX_FILE_LEN];
    CREATE_TMP_DIR_PATH(tmp_dir, client_fd);
    CREATE_FILE_PATH(tmp_dir, hwquote_pcr_file, TPM2_HWQUOTE_PCR);
    CREATE_FILE_PATH(tmp_dir, hwquote_msg_file, TPM2_HWQUOTE_MSG);
    CREATE_FILE_PATH(tmp_dir, hwquote_sig_file, TPM2_HWQUOTE_SIG);
    CREATE_FILE_PATH(tmp_dir, ak_hwpub_pem_key_file, TPM2_AK_HWPUB_PEM_KEY);
    /* Read quote_message from json file */
    ret = ovsa_server_json_extract_element(payload_quote_info, "HW_Quote_MSG",
                                           (void**)&hw_quote_info->quote_message);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
        goto out;
    }

    ret = ovsa_server_get_string_length(hw_quote_info->quote_message, &size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of payload string %d\n", ret);
        goto out;
    }
    ret = ovsa_server_safe_malloc((sizeof(char) * size), &pcr_quote_message_bin_buff);
    if (ret < OVSA_OK || pcr_quote_message_bin_buff == NULL) {
        OVSA_DBG(DBG_E, "OVSA: pcr quote buffer allocation failed %d\n", ret);
        goto out;
    }
    ret = ovsa_crypto_convert_base64_to_bin(hw_quote_info->quote_message, size,
                                            pcr_quote_message_bin_buff,
                                            &pcr_quote_message_bin_length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error Crypto convert_base64_to_bin failed with code %d\n", ret);
        goto out;
    }
    /* write pcr_quote_message to file */
    FILE* fptr_pcr_quote_message = fopen(hwquote_msg_file, "w");
    if (fptr_pcr_quote_message == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "Error: Opening file HW_pcr_quote.plain failed with code %d\n", ret);
        goto out;
    }
    fwrite(pcr_quote_message_bin_buff, pcr_quote_message_bin_length, 1, fptr_pcr_quote_message);
    fclose(fptr_pcr_quote_message);

    /* Read quote_signature from json file */
    ret = ovsa_server_json_extract_element(payload_quote_info, "HW_Quote_SIG",
                                           (void**)&hw_quote_info->quote_sig);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
        goto out;
    }

    size = 0;
    ret  = ovsa_server_get_string_length(hw_quote_info->quote_sig, &size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of payload string %d\n", ret);
        goto out;
    }
    ret = ovsa_server_safe_malloc((sizeof(char) * size), &pcr_quote_signature_bin_buff);
    if (ret < OVSA_OK || pcr_quote_signature_bin_buff == NULL) {
        OVSA_DBG(DBG_E, "OVSA: pcr quote buffer allocation failed %d\n", ret);
        goto out;
    }
    ret = ovsa_crypto_convert_base64_to_bin(hw_quote_info->quote_sig, size,
                                            pcr_quote_signature_bin_buff,
                                            &pcr_quote_signature_bin_length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error Crypto convert_base64_to_bin failed with code %d\n", ret);
        goto out;
    }
    /* write pcr_quote_signature to file */
    FILE* fptr_pcr_quote_signature = fopen(hwquote_sig_file, "wb");
    if (fptr_pcr_quote_signature == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "Error: Opening file pcr_quote.signature failed with code %d\n", ret);
        goto out;
    }
    fwrite(pcr_quote_signature_bin_buff, pcr_quote_signature_bin_length, 1,
           fptr_pcr_quote_signature);
    fclose(fptr_pcr_quote_signature);

    /* Read pcr_list from json file */
    ret = ovsa_server_json_extract_element(payload_quote_info, "HW_Quote_PCR",
                                           (void**)&hw_quote_info->quote_pcr);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
        goto out;
    }

    ret = ovsa_server_get_string_length(hw_quote_info->quote_pcr, &size);
    ret = ovsa_server_safe_malloc((sizeof(char) * size), &pcr_bin_buff);
    if (ret < OVSA_OK || pcr_bin_buff == NULL) {
        OVSA_DBG(DBG_E, "OVSA: pcr quote buffer allocation failed %d\n", ret);
        goto out;
    }
    ret = ovsa_crypto_convert_base64_to_bin(hw_quote_info->quote_pcr, size, pcr_bin_buff,
                                            &pcr_bin_length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error Crypto convert_base64_to_bin failed with code %d\n", ret);
        goto out;
    }
    /* write pcr_bin to file */
    FILE* fptr_pcr_bin = fopen(hwquote_pcr_file, "wb");
    if (fptr_pcr_bin == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "Error: Opening file pcr.bin failed with code %d\n", ret);
        goto out;
    }
    fwrite(pcr_bin_buff, pcr_bin_length, 1, fptr_pcr_bin);
    fclose(fptr_pcr_bin);

    /* Read SW_pub_key from json file */
    ret = ovsa_server_json_extract_element(payload_quote_info, "HW_AK_Pub_Key",
                                           (void**)&hw_quote_info->ak_pub_key);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
        goto out;
    }
    /* write SW_pub_key to file */
    FILE* fptr_HW_pub_key = fopen(ak_hwpub_pem_key_file, "w+");
    if (fptr_HW_pub_key == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "Error: Opening file SW_pub_key.pub failed with code %d\n", ret);
        goto out;
    }
    ret = ovsa_server_get_string_length(hw_quote_info->ak_pub_key, &size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of payload string %d\n", ret);
        fclose(fptr_HW_pub_key);
        goto out;
    }
    fwrite(hw_quote_info->ak_pub_key, size, 1, fptr_HW_pub_key);
    fclose(fptr_HW_pub_key);

out:

    ovsa_server_safe_free(&pcr_quote_message_bin_buff);
    ovsa_server_safe_free(&pcr_quote_signature_bin_buff);
    ovsa_server_safe_free(&pcr_bin_buff);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}
#endif

static ovsa_status_t ovsa_extract_SW_quote_info(char* payload_quote_info,
                                                ovsa_quote_info_t* sw_quote_info,
                                                char* cust_lic_payload,
                                                ovsa_customer_license_sig_t* customer_lic_sig,
                                                int client_fd) {
    ovsa_status_t ret                     = OVSA_OK;
    char* pcr_quote_message_bin_buff      = NULL;
    size_t pcr_quote_message_bin_length   = 0;
    char* pcr_quote_signature_bin_buff    = NULL;
    size_t pcr_quote_signature_bin_length = 0;
    char* pcr_bin_buff                    = NULL;
    size_t pcr_bin_length                 = 0;
    size_t size                           = 0;
    char tmp_dir[MAX_FILE_LEN];
    char swquote_sig_file[MAX_FILE_LEN];
    char ak_pub_pem_key_file[MAX_FILE_LEN];
    char swquote_pcr_file[MAX_FILE_LEN];
    char swquote_msg_file[MAX_FILE_LEN];

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    if (sw_quote_info == NULL) {
        OVSA_DBG(DBG_E, "Error: Invalid parameter while reading Quote info\n");
        ret = OVSA_INVALID_PARAMETER;
        goto out;
    }
    CREATE_TMP_DIR_PATH(tmp_dir, client_fd);
    CREATE_FILE_PATH(tmp_dir, swquote_sig_file, TPM2_SWQUOTE_SIG);
    CREATE_FILE_PATH(tmp_dir, ak_pub_pem_key_file, TPM2_AK_PUB_PEM_KEY);
    CREATE_FILE_PATH(tmp_dir, swquote_pcr_file, TPM2_SWQUOTE_PCR);
    CREATE_FILE_PATH(tmp_dir, swquote_msg_file, TPM2_SWQUOTE_MSG);
    /* Read quote_message from json file */
    ret = ovsa_server_json_extract_element(payload_quote_info, "SW_Quote_MSG",
                                           (void**)&sw_quote_info->quote_message);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
        goto out;
    }

    ret = ovsa_server_get_string_length(sw_quote_info->quote_message, &size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of payload string %d\n", ret);
        goto out;
    }
    ret = ovsa_server_safe_malloc((sizeof(char) * size), &pcr_quote_message_bin_buff);
    if (ret < OVSA_OK || pcr_quote_message_bin_buff == NULL) {
        OVSA_DBG(DBG_E, "OVSA: pcr quote buffer allocation failed %d\n", ret);
        goto out;
    }
    ret = ovsa_crypto_convert_base64_to_bin(sw_quote_info->quote_message, size,
                                            pcr_quote_message_bin_buff,
                                            &pcr_quote_message_bin_length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error Crypto convert_base64_to_bin failed with code %d\n", ret);
        goto out;
    }
    /* write pcr_quote_message to file */
    FILE* fptr_pcr_quote_message = fopen(swquote_msg_file, "w");
    if (fptr_pcr_quote_message == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "Error: Opening file pcr_quote.plain failed with code %d\n", ret);
        goto out;
    }
    fwrite(pcr_quote_message_bin_buff, pcr_quote_message_bin_length, 1, fptr_pcr_quote_message);
    fclose(fptr_pcr_quote_message);

    /* Read quote_signature from json file */
    ret = ovsa_server_json_extract_element(payload_quote_info, "SW_Quote_SIG",
                                           (void**)&sw_quote_info->quote_sig);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
        goto out;
    }

    ret = ovsa_server_get_string_length(sw_quote_info->quote_sig, &size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of payload string %d\n", ret);
        goto out;
    }
    ret = ovsa_server_safe_malloc((sizeof(char) * size), &pcr_quote_signature_bin_buff);
    if (ret < OVSA_OK || pcr_quote_signature_bin_buff == NULL) {
        OVSA_DBG(DBG_E, "OVSA: pcr quote buffer allocation failed %d\n", ret);
        goto out;
    }
    ret = ovsa_crypto_convert_base64_to_bin(sw_quote_info->quote_sig, size,
                                            pcr_quote_signature_bin_buff,
                                            &pcr_quote_signature_bin_length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error Crypto convert_base64_to_bin failed with code %d\n", ret);
        goto out;
    }
    /* write pcr_quote_signature to file */
    FILE* fptr_pcr_quote_signature = fopen(swquote_sig_file, "wb");
    if (fptr_pcr_quote_signature == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "Error: Opening file pcr_quote.signature failed with code %d\n", ret);
        goto out;
    }
    fwrite(pcr_quote_signature_bin_buff, pcr_quote_signature_bin_length, 1,
           fptr_pcr_quote_signature);
    fclose(fptr_pcr_quote_signature);

    /* Read pcr_list from json file */
    ret = ovsa_server_json_extract_element(payload_quote_info, "SW_Quote_PCR",
                                           (void**)&sw_quote_info->quote_pcr);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
        goto out;
    }

    ret = ovsa_server_get_string_length(sw_quote_info->quote_pcr, &size);
    ret = ovsa_server_safe_malloc((sizeof(char) * size), &pcr_bin_buff);
    if (ret < OVSA_OK || pcr_bin_buff == NULL) {
        OVSA_DBG(DBG_E, "OVSA: pcr quote buffer allocation failed %d\n", ret);
        goto out;
    }
    ret = ovsa_crypto_convert_base64_to_bin(sw_quote_info->quote_pcr, size, pcr_bin_buff,
                                            &pcr_bin_length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error Crypto convert_base64_to_bin failed with code %d\n", ret);
        goto out;
    }
    /* write pcr_bin to file */
    FILE* fptr_pcr_bin = fopen(swquote_pcr_file, "wb");
    if (fptr_pcr_bin == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "Error: Opening file pcr.bin failed with code %d\n", ret);
        goto out;
    }
    fwrite(pcr_bin_buff, pcr_bin_length, 1, fptr_pcr_bin);
    fclose(fptr_pcr_bin);

    /* Read SW_pub_key from json file */
    ret = ovsa_server_json_extract_element(payload_quote_info, "SW_AK_Pub_key",
                                           (void**)&sw_quote_info->ak_pub_key);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
        goto out;
    }
    /* Extract customer licensce json blob */
    ret = ovsa_server_json_extract_customer_license(cust_lic_payload, customer_lic_sig);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Extract customer license json blob failed with code %d\n", ret);
        goto out;
    }

    /* write SW_pub_key to file */
    FILE* fptr_SW_pub_key = fopen(ak_pub_pem_key_file, "w+");
    if (fptr_SW_pub_key == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "Error: Opening file SW_pub_key.pub failed with code %d\n", ret);
        goto out;
    }
    ret = ovsa_server_get_string_length(sw_quote_info->ak_pub_key, &size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of payload string %d\n", ret);
        fclose(fptr_SW_pub_key);
        goto out;
    }
    fwrite(sw_quote_info->ak_pub_key, size, 1, fptr_SW_pub_key);
    fclose(fptr_SW_pub_key);
out:
    ovsa_server_safe_free(&pcr_quote_message_bin_buff);
    ovsa_server_safe_free(&pcr_quote_signature_bin_buff);
    ovsa_server_safe_free(&pcr_bin_buff);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_extract_customer_license_validate_tcb(
    char* cust_lic_payload, ovsa_customer_license_sig_t* customer_lic_sig) {
    ovsa_status_t ret = OVSA_OK;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /* Extract customer licensce json blob */
    ret = ovsa_server_json_extract_customer_license(cust_lic_payload, customer_lic_sig);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Extract customer license json blob failed with code %d\n", ret);
        goto out;
    }

out:
    ovsa_server_safe_free(&customer_lic_sig->customer_lic.isv_certificate);
    ovsa_server_safe_free_url_list(&customer_lic_sig->customer_lic.license_url_list);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_send_license_check_response(void** _ssl_session, const char* response) {
    ovsa_status_t ret                = OVSA_OK;
    void* ssl_session                = NULL;
    ssl_session                      = *_ssl_session;
    size_t length                    = 0;
    char* lic_check_status_buf       = NULL;
    size_t license_check_payload_len = 0;
    char* license_check_json_payload = NULL;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /* create json message blob & send response result to client */
    ret = ovsa_server_json_create_message_blob(OVSA_SEND_LICENSE_CHECK_RESP, response,
                                               &lic_check_status_buf, &length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: response message blob failed with error code %d\n", ret);
        goto out;
    }
    /* Append payload length to json blob */
    license_check_payload_len = length + PAYLOAD_LENGTH + 1;
    ret                       = ovsa_server_safe_malloc((sizeof(char) * license_check_payload_len),
                                  &license_check_json_payload);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "Error: Create json blob memory init failed\n");
        goto out;
    }
    ret = ovsa_append_payload_len_to_blob(lic_check_status_buf, &license_check_json_payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:json_payload json blob creation failed with %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA:Sending TCB check/License check response to client\n");
    OVSA_DBG(DBG_I, "OVSA:CHECK_RESP_json_payload %s\n", license_check_json_payload);

    size_t payload_len = 0;
    ret                = ovsa_server_get_string_length(license_check_json_payload, &payload_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of payload string %d\n", ret);
        goto out;
    }
    /* Send License check result to lient */
    ret = ovsa_license_service_write(ssl_session, license_check_json_payload, payload_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Send response to client failed %d\n", ret);
        goto out;
    }

out:
    ovsa_server_safe_free(&license_check_json_payload);
    ovsa_server_safe_free(&lic_check_status_buf);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_command_type_t ovsa_get_command_type(const char* command) {
    ovsa_command_type_t cmd = OVSA_INVALID_CMD;

    if (!strcmp(command, "OVSA_SEND_SIGN_NONCE"))
        cmd = OVSA_SEND_SIGN_NONCE;
    else if (!strcmp(command, "OVSA_SEND_EK_AK_BIND_INFO"))
        cmd = OVSA_SEND_EK_AK_BIND_INFO;
    else if (!strcmp(command, "OVSA_SEND_QUOTE_INFO"))
        cmd = OVSA_SEND_QUOTE_INFO;
    else if (!strcmp(command, "OVSA_SEND_CUST_LICENSE"))
        cmd = OVSA_SEND_CUST_LICENSE;

    return cmd;
}

static ovsa_status_t ovsa_read_payload(void** _ssl_session, char** read_buf, char** command) {
    ovsa_status_t ret = OVSA_OK;
    void* ssl_session = NULL;
    ssl_session       = *_ssl_session;
    unsigned char payload_len_str[PAYLOAD_LENGTH + 1];
    size_t payload_size = 0;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    memset_s(payload_len_str, sizeof(payload_len_str), 0);

    /* Read payload length */
    ret = ovsa_license_service_read(ssl_session, payload_len_str, PAYLOAD_LENGTH);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: License service read communication failed  %d\n", ret);
        goto out;
    }
    payload_size = atoi(payload_len_str);
    if ((payload_size < OVSA_OK || payload_size > UINT_MAX)) {
        ret = OVSA_INVALID_PARAMETER;
        OVSA_DBG(DBG_E, "Error: License service read payload size '%ld'  invalid \n", payload_size);
        goto out;
    }
    ret = ovsa_server_safe_malloc((sizeof(char) * payload_size + 1), read_buf);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "Error: Memory init failed\n");
        goto out;
    }
    /* Read payload */
    ret = ovsa_license_service_read(ssl_session, *read_buf, payload_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:License service read communication failed with code %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_D, "OVSA:Received payload\n'%s'\n", *read_buf);
    /* Read command from json file */
    ret = ovsa_server_json_extract_element(*read_buf, "command", (void**)command);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read command from json failed %d\n", ret);
        goto out;
    }

out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_send_client_request_EK_AK_bind(void** _ssl_session) {
    ovsa_status_t ret    = OVSA_OK;
    void* ssl_session    = NULL;
    ssl_session          = *_ssl_session;
    char* json_buf       = NULL;
    char* json_payload   = NULL;
    char dummy_payload[] = "";
    size_t length        = 0;
    size_t payload_len   = 0;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /* create json meesage blob */
    ret = ovsa_server_json_create_message_blob(OVSA_SEND_EK_AK_BIND, dummy_payload, &json_buf,
                                               &length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Create message blob failed with error code %d\n", ret);
        goto out;
    }
    /* Append payload length to json blob */
    payload_len = length + PAYLOAD_LENGTH + 1;
    ret         = ovsa_server_safe_malloc((sizeof(char) * payload_len), &json_payload);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "Error: Memory init failed\n");
        goto out;
    }
    ret = ovsa_append_payload_len_to_blob(json_buf, &json_payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:json blob creation failed with %d\n", ret);
        goto out;
    }
    /* Send client domain query */
    ret = ovsa_server_get_string_length((char*)json_payload, &payload_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of json_payload string %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA:Sending client EK_AK_BIND info request ...!\n");
    ret = ovsa_license_service_write(ssl_session, json_payload, payload_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: License service write communication failed %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA:json payload %s\n", json_payload);

out:
    ovsa_server_safe_free(&json_buf);
    ovsa_server_safe_free(&json_payload);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_extract_EK_AK_bind_info(const char* payload_EK_AK_bind_info,
                                                  ovsa_sw_ek_ak_bind_info_t* sw_ek_ak_bind_info) {
    ovsa_status_t ret = OVSA_OK;

    /* Read AKname from json file */
    ret = ovsa_server_json_extract_element(payload_EK_AK_bind_info, "AK_name",
                                           (void**)&sw_ek_ak_bind_info->sw_ak_name);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
        goto out;
    }
    /* Read EKcert from json file */
    ret = ovsa_server_json_extract_element(payload_EK_AK_bind_info, "EK_cert",
                                           (void**)&sw_ek_ak_bind_info->sw_ek_cert);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
        goto out;
    }
    /* Read signed EKcertificate from json file */
    ret = ovsa_server_json_extract_element(payload_EK_AK_bind_info, "EKcert_signature",
                                           (void**)&sw_ek_ak_bind_info->sw_ek_cert_sig);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
        goto out;
    }
    /* Read EKpub from json file */
    ret = ovsa_server_json_extract_element(payload_EK_AK_bind_info, "EK_pub",
                                           (void**)&sw_ek_ak_bind_info->sw_ek_pub_key);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
        goto out;
    }
    /* Read signed EKpub from json file */
    ret = ovsa_server_json_extract_element(payload_EK_AK_bind_info, "EKpub_signature",
                                           (void**)&sw_ek_ak_bind_info->sw_ek_pub_sig);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
        goto out;
    }
    /* Read customer certificate from json file */
    ret = ovsa_server_json_extract_element(payload_EK_AK_bind_info, "certificate",
                                           (void**)&sw_ek_ak_bind_info->platform_cert);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
        goto out;
    }
out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}
static ovsa_status_t ovsa_convert_EKpub_to_DER_format(const char* ekpub, int client_fd) {
    ovsa_status_t ret       = OVSA_OK;
    char* ekpub_bin_buff    = NULL;
    size_t ekpub_size       = 0;
    size_t ekpub_bin_length = 0;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    ret = ovsa_server_get_string_length(ekpub, &ekpub_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of json_payload string %d\n", ret);
        goto out;
    }
    ret = ovsa_server_safe_malloc((sizeof(char) * ekpub_size), &ekpub_bin_buff);
    if (ret < OVSA_OK || ekpub_bin_buff == NULL) {
        OVSA_DBG(DBG_E, "OVSA: pcr quote buffer allocation failed %d\n", ret);
        goto out;
    }
    ret = ovsa_crypto_convert_base64_to_bin(ekpub, ekpub_size, ekpub_bin_buff, &ekpub_bin_length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error Crypto convert_base64_to_bin failed with code %d\n", ret);
        goto out;
    }
    char ek_pub_key_file[MAX_FILE_LEN];
    CREATE_TMP_DIR_PATH(ek_pub_key_file, client_fd);
    strcat(ek_pub_key_file, TPM2_EK_PUB_KEY);
    /* write EKpub_bin to file */
    FILE* fptr_EKpub_bin = fopen(ek_pub_key_file, "wb");
    if (fptr_EKpub_bin == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "Error: Opening file ek_pub failed with code %d\n", ret);
        goto out;
    }
    fwrite(ekpub_bin_buff, ekpub_bin_length, 1, fptr_EKpub_bin);
    fclose(fptr_EKpub_bin);

out:
    ovsa_server_safe_free(&ekpub_bin_buff);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_server_do_tpm2_makecredential(char* akname_hex, const char* ekpub,
                                                        int client_fd) {
    ovsa_status_t ret = OVSA_OK;
    size_t size = 0, buf_len = 0;
    char tmp_dir[MAX_FILE_LEN];
    char tmp_nonce_file[MAX_FILE_LEN];
    char credout_file[MAX_FILE_LEN];
    char ek_pub_key_file[MAX_FILE_LEN];
    char ak_name_hex[MAX_FILE_LEN];

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    strtok(akname_hex, "\n");
    /* Delete old quote files if already exsists */
    ovsa_remove_quote_files(client_fd);

    CREATE_TMP_DIR_PATH(tmp_dir, client_fd);
    ret = mkdir(tmp_dir, 0777);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: tmp directory %s creation failed ", tmp_dir);
        return OVSA_FILEOPEN_FAIL;
    }
    CREATE_FILE_PATH(tmp_dir, tmp_nonce_file, SECRET_NONCE);
    CREATE_FILE_PATH(tmp_dir, credout_file, TPM2_CREDOUT_FILE);
    CREATE_FILE_PATH(tmp_dir, ek_pub_key_file, TPM2_EK_PUB_KEY);
    CREATE_FILE_PATH(tmp_dir, ak_name_hex, TPM2_AK_NAME_HEX);
    /* write AKname hex to file */
    FILE* fptr_Akname_hex = fopen(ak_name_hex, "wb");
    if (fptr_Akname_hex == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "Error: Opening file tpm_ak.name_hex failed with code %d\n", ret);
        goto out;
    }
    ret = ovsa_server_get_string_length(akname_hex, &buf_len);
    if (ret < OVSA_OK) {
        fclose(fptr_Akname_hex);
        OVSA_DBG(DBG_E, "Error: Could not get length of string %d\n", ret);
        goto out;
    }
    fwrite(akname_hex, buf_len, 1, fptr_Akname_hex);
    fclose(fptr_Akname_hex);

    /* convert EKpub to DER format */
    ret = ovsa_convert_EKpub_to_DER_format(ekpub, client_fd);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Generate nonce failed with code %d\n", ret);
        goto out;
    }

    char* const getrand_cmd[] = {"/usr/bin/sudo",
                                 "tpm2_getrandom",
                                 "--hex",
                                 "-o",
                                 tmp_nonce_file,
                                 "16",
                                 "-T",
                                 "device:/dev/tpmrm0",
                                 0};
    if (ovsa_server_do_run_tpm2_command(getrand_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "Error: Command %s failed to execute \n", getrand_cmd[1]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }

    char* const makecredential_argv[] = {"/usr/bin/sudo",
                                         "tpm2_makecredential",
                                         "--encryption-key",
                                         ek_pub_key_file,
                                         "--secret",
                                         tmp_nonce_file,
                                         "--name",
                                         akname_hex,
                                         "--credential-blob",
                                         credout_file,
                                         "-T",
                                         "device:/dev/tpmrm0",
                                         0};

    /* Run makecredential */
    ret = ovsa_server_do_run_tpm2_command(makecredential_argv, NULL);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Command %s failed to execute \n", makecredential_argv[1]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }
    OVSA_DBG(DBG_I, "TPM2 makecredential successful...\n");

out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_server_send_credential_quote(void** _ssl_session, int client_fd) {
    ovsa_status_t ret        = OVSA_OK;
    void* ssl_session        = NULL;
    ssl_session              = *_ssl_session;
    size_t file_size         = 0;
    char* credout_buf        = NULL;
    char* credout_buf_pem    = NULL;
    char* quote_nonce        = NULL;
    char* quote_credout_info = NULL;
    char* json_buf           = NULL;
    char* json_payload       = NULL;
    size_t length            = 0;
    size_t payload_len       = 0;
    char* nonce_bin_buff     = NULL;
    size_t nonce_bin_length = 0, nonce_size = 0;
    char tmp_dir[MAX_FILE_LEN];
    char credout_file[MAX_FILE_LEN];
    char quote_nonce_file[MAX_FILE_LEN];

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    CREATE_TMP_DIR_PATH(tmp_dir, client_fd);
    CREATE_FILE_PATH(tmp_dir, credout_file, TPM2_CREDOUT_FILE);
    CREATE_FILE_PATH(tmp_dir, quote_nonce_file, QUOTE_NONCE);
    /* Read credential file */
    ret = ovsa_read_file_content(credout_file, &credout_buf, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Reading Opening file cred.out file failed with error code %d\n",
                 ret);
        goto out;
    }
    /* convert credout bin to pem */
    ret = ovsa_server_crypto_convert_bin_to_pem(credout_buf, file_size - 1, &credout_buf_pem);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error Crypto convert_bin_to_pem failed with code %d\n", ret);
        goto out;
    }
    /* Generate quote nonce */
    ret = ovsa_create_nonce(&quote_nonce);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error create nonce failed with code %d\n", ret);
        goto out;
    }
    ret = ovsa_server_get_string_length(quote_nonce, &nonce_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of quote_nonce string %d\n", ret);
        goto out;
    }
    ret = ovsa_server_safe_malloc((sizeof(char) * nonce_size), &nonce_bin_buff);
    if (ret < OVSA_OK || nonce_bin_buff == NULL) {
        OVSA_DBG(DBG_E, "OVSA: pcr quote buffer allocation failed %d\n", ret);
        goto out;
    }
    ret = ovsa_crypto_convert_base64_to_bin(quote_nonce, strnlen_s(quote_nonce, RSIZE_MAX_STR),
                                            nonce_bin_buff, &nonce_bin_length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error Crypto convert_base64_to_bin failed with code %d\n", ret);
        goto out;
    }

    /* write quote nounce to file */
    FILE* fquote_nonce = fopen(quote_nonce_file, "w");
    if (fquote_nonce == NULL) {
        OVSA_DBG(DBG_E, "Error: opening nonce.bin !");
        ret = OVSA_FILEOPEN_FAIL;
        goto out;
    }
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of quote_nonce string %d\n", ret);
        goto out;
    }
    fwrite(nonce_bin_buff, nonce_bin_length, 1, fquote_nonce);
    fclose(fquote_nonce);

    ret = ovsa_json_create_quote_cred_data_blob(credout_buf_pem, quote_nonce, &quote_credout_info,
                                                &length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error create_quote_creadout_info_blob failed with code %d\n", ret);
        goto out;
    }
    /* create json message blob */
    ret = ovsa_server_json_create_message_blob(OVSA_SEND_QUOTE_NONCE, quote_credout_info, &json_buf,
                                               &length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:Create SW quote message failed with error code %d\n", ret);
        goto out;
    }
    /* Append payload length to json blob */
    payload_len = length + PAYLOAD_LENGTH + 1;
    ret         = ovsa_server_safe_malloc((sizeof(char) * payload_len), &json_payload);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "Error: Memory init failed\n");
        goto out;
    }
    ret = ovsa_append_payload_len_to_blob(json_buf, &json_payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:json blob creation failed with %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA:json payload %s\n", json_payload);
    payload_len = 0;

    ret = ovsa_server_get_string_length((char*)json_payload, &payload_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of json_payload string %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA:Sending credout and quote nonce to client...!\n");
    ret = ovsa_license_service_write(ssl_session, json_payload, payload_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: License service write communicaton failed %d\n", ret);
        goto out;
    }

out:
    ovsa_server_safe_free(&credout_buf_pem);
    ovsa_server_safe_free(&credout_buf);
    ovsa_server_safe_free(&quote_nonce);
    ovsa_server_safe_free(&quote_credout_info);
    ovsa_server_safe_free(&json_buf);
    ovsa_server_safe_free(&nonce_bin_buff);
    ovsa_server_safe_free(&json_payload);

    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_do_validate_EK_AK_bind_info(void** _ssl_session,
                                                      const char* payload_EK_AK_bind_info,
                                                      int client_fd) {
    ovsa_status_t ret = OVSA_OK;
    void* ssl_session = NULL;
    ssl_session       = *_ssl_session;
    char public_key[MAX_KEY_SIZE];
    size_t ekpub_size   = 0;
    size_t ekcert_size  = 0;
    char* cert_bin_buff = NULL;
    size_t size         = 0;
    ovsa_sw_ek_ak_bind_info_t sw_ek_ak_bind_info;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    memset_s(&sw_ek_ak_bind_info, sizeof(ovsa_sw_ek_ak_bind_info_t), 0);

    ret = ovsa_extract_EK_AK_bind_info(payload_EK_AK_bind_info, &sw_ek_ak_bind_info);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E,
                 "Error: ovsa_extract_sw_quote_info failed with "
                 "error code %d\n",
                 ret);
    }
    /* Verify Platform certificate */
#ifndef ENABLE_SELF_SIGNED_CERT
    OVSA_DBG(DBG_I, "OVSA:Verify Platform certificate\n");
    ret = ovsa_server_crypto_verify_certificate(sw_ek_ak_bind_info.platform_cert);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Platform certificate verify failed %d\n", ret);
        goto out;
    }
#endif
    /************************************************************************************/
    /* Check if EK Certificate exists. If so, Verify EK certificate & extract
    /* public_key
    /************************************************************************************/
    if (!strcmp(sw_ek_ak_bind_info.sw_ek_cert, "")) {
        /* Verify EKPub */
        OVSA_DBG(DBG_I, "\nOVSA:Verify EKPub\n");
        ret = ovsa_server_get_string_length(sw_ek_ak_bind_info.sw_ek_pub_key, &ekpub_size);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Could not get length of json_payload string %d\n", ret);
            goto out;
        }
        ret = ovsa_server_crypto_verify_mem(sw_ek_ak_bind_info.platform_cert,
                                            sw_ek_ak_bind_info.sw_ek_pub_key, ekpub_size,
                                            sw_ek_ak_bind_info.sw_ek_pub_sig);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: EKpub verify failed %d\n", ret);
            goto out;
        }
        memset_s(public_key, sizeof(public_key), 0);
        memcpy_s(public_key, ekpub_size, sw_ek_ak_bind_info.sw_ek_pub_key, ekpub_size);
    } else { /* Verify EK certificate */
#ifndef ENABLE_SELF_SIGNED_CERT
        OVSA_DBG(DBG_I, "OVSA:Verify EK certificate\n");
        ret = ovsa_server_crypto_verify_certificate(sw_ek_ak_bind_info.sw_ek_cert);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Verify EK certificate verify failed %d\n", ret);
            goto out;
        }

        OVSA_DBG(DBG_I, "\nOVSA:Verify EKcert\n");
        ret = ovsa_server_get_string_length(sw_ek_ak_bind_info.sw_ek_cert, &ekpub_size);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Could not get length of json_payload string %d\n", ret);
            goto out;
        }
        ret = ovsa_server_crypto_verify_mem(sw_ek_ak_bind_info.platform_cert,
                                            sw_ek_ak_bind_info.sw_ek_cert, ekpub_size,
                                            sw_ek_ak_bind_info.sw_ek_cert_sig);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: EKcert verify failed %d\n", ret);
            goto out;
        }
        memset_s(public_key, sizeof(public_key), 0);
        ret = ovsa_server_crypto_extract_pubkey_certificate(sw_ek_ak_bind_info.sw_ek_cert,
                                                            public_key);
        if (ret < 0) {
            OVSA_DBG(DBG_E,
                     "Error: verifying the memory buffer failed in extracting "
                     "the public key\n");
            goto out;
        }
#endif
    }
    /* create wrapped credential and encryption key using tpm2_makecredential */
    ret = ovsa_server_do_tpm2_makecredential(sw_ek_ak_bind_info.sw_ak_name, public_key, client_fd);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error tpm2_makecredential failed with code %d\n", ret);
        goto out;
    }
    /* Send wrapped credential and quote nonce to client */
    ret = ovsa_server_send_credential_quote(&ssl_session, client_fd);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error send credential and quote nonce failed with code %d\n", ret);
        goto out;
    }

out:
    ovsa_server_safe_free(&sw_ek_ak_bind_info.sw_ak_name);
    ovsa_server_safe_free(&sw_ek_ak_bind_info.sw_ek_pub_key);
    ovsa_server_safe_free(&sw_ek_ak_bind_info.sw_ek_pub_sig);
    ovsa_server_safe_free(&sw_ek_ak_bind_info.sw_ek_cert);
    ovsa_server_safe_free(&sw_ek_ak_bind_info.sw_ek_cert_sig);
    ovsa_server_safe_free(&sw_ek_ak_bind_info.platform_cert);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_client_license_service_callback(void* ssl_session, int client_fd) {
    ovsa_status_t ret = OVSA_OK;

    char response[MAX_NAME_SIZE];
    bool lic_check_flag           = false;
    bool cert_check_flag          = false;
    bool tcb_check_flag           = false;
    char* nonce_buf               = NULL;
    char* json_payload            = NULL;
    char* cust_lic_payload        = NULL;
    char* cert                    = NULL;
    char* payload_signature       = NULL;
    char* payload_quote_info      = NULL;
    char* payload_EK_AK_bind_info = NULL;
    ovsa_customer_license_sig_t customer_lic_sig;
    char* license_guid                       = NULL;
    char* model_guid                         = NULL;
    char* read_buf                           = NULL;
    char* command                            = NULL;
    ovsa_command_type_t cmd                  = OVSA_INVALID_CMD;
    bool received_all_license_service_params = false;
    bool received_all_quote_params           = false;
    bool start_license_check                 = false;
    ovsa_quote_info_t sw_quote_info;
    ovsa_quote_info_t hw_quote_info;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    memset_s(response, sizeof(response), 0);
    memset_s(&customer_lic_sig, sizeof(ovsa_customer_license_sig_t), 0);

    /*Request EK_AK bind info from client*/
    ret = ovsa_send_client_request_EK_AK_bind(&ssl_session);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Request_EK_AK_BIND_info failed with error code %d\n", ret);
        goto out;
    }

start_license_check:

    if (start_license_check == true) {
        /* Generate nonce */
        ret = ovsa_generate_nonce_payload(&nonce_buf, &json_payload);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Generate nonce failed with error code %d\n", ret);
            goto out;
        }
        /* Send nonce to client */
        ret = ovsa_send_nonce_to_client(&ssl_session, json_payload);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: ovsa_send_nonce_to_client failed with error code %d\n", ret);
            goto out;
        }
    }
    do {
        /* Receive payload from client */
        ret = ovsa_read_payload(&ssl_session, &read_buf, &command);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Read payload from failed %d\n", ret);
            goto out;
        }

        cmd = ovsa_get_command_type(command);
        if (cmd < OVSA_OK) {
            ret = OVSA_INVALID_CMD_TYPE;
            OVSA_DBG(DBG_E, "Error: Read payload from failed %d\n", ret);
            goto out;
        }

        switch (cmd) {
            case OVSA_SEND_SIGN_NONCE:
                /* Read signed nonce from json file */
                ret = ovsa_server_json_extract_element(read_buf, "payload",
                                                       (void**)&payload_signature);
                if (ret < OVSA_OK) {
                    OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
                    memcpy_s(response,
                             strnlen_s("FAIL: Error in Sending Signed Nonce", MAX_NAME_SIZE),
                             "FAIL: Error in Sending Signed Nonce",
                             strnlen_s("FAIL: Error in Sending Signed Nonce", MAX_NAME_SIZE));
                    goto out1;
                }
                received_all_license_service_params = true;
                break;
            case OVSA_SEND_EK_AK_BIND_INFO:
                /* Read sw quote from json file */
                ret = ovsa_server_json_extract_element(read_buf, "payload",
                                                       (void**)&payload_EK_AK_bind_info);
                if (ret < OVSA_OK) {
                    OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
                    memcpy_s(response,
                             strnlen_s("FAIL: Error in Sending EK_AK_bind_info", MAX_NAME_SIZE),
                             "FAIL: Error in Sending Signed Nonce",
                             strnlen_s("FAIL: Error in Sending EK_AK_bind_info", MAX_NAME_SIZE));
                    goto out1;
                }
                ret = ovsa_do_validate_EK_AK_bind_info(&ssl_session, payload_EK_AK_bind_info,
                                                       client_fd);
                if (ret < OVSA_OK) {
                    OVSA_DBG(DBG_E,
                             "Error: ovsa_validate_EK_AK_BIND_info failed with "
                             "error code %d\n",
                             ret);
                }

                break;
            case OVSA_SEND_QUOTE_INFO:
                /* Read sw quote from json file */
                ret = ovsa_server_json_extract_element(read_buf, "payload",
                                                       (void**)&payload_quote_info);
                if (ret < OVSA_OK) {
                    OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
                    memcpy_s(response, strnlen_s("FAIL: Error in Sending SW quote", MAX_NAME_SIZE),
                             "FAIL: Error in Sending Signed Nonce",
                             strnlen_s("FAIL: Error in Sending SW quote", MAX_NAME_SIZE));
                    goto out1;
                }
                received_all_quote_params = true;
                break;
            case OVSA_SEND_CUST_LICENSE:
                /* Read customer license payload from json file */
                ret = ovsa_server_json_extract_element(read_buf, "payload",
                                                       (void**)&cust_lic_payload);
                if (ret < OVSA_OK) {
                    OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
                    memcpy_s(response,
                             strnlen_s("FAIL: Error in reading customer license", MAX_NAME_SIZE),
                             "FAIL: Error in reading customer license",
                             strnlen_s("FAIL: Error in reading customer license", MAX_NAME_SIZE));
                    goto out1;
                }
                received_all_license_service_params = true;
                break;
            default:
                ret = OVSA_INVALID_CMD_TYPE;
                OVSA_DBG(DBG_E, "Error: Received Invalid command %d from client\n", cmd);
                goto out1;
                break;
        }
        ovsa_server_safe_free((char**)&command);
        ovsa_server_safe_free((char**)&read_buf);

    } while (received_all_license_service_params == false);

    if (received_all_quote_params) {
        memset_s(&sw_quote_info, sizeof(ovsa_quote_info_t), 0);
        memset_s(&hw_quote_info, sizeof(ovsa_quote_info_t), 0);

        /* Extract SW_quote */
        ret = ovsa_extract_SW_quote_info(payload_quote_info, &sw_quote_info, cust_lic_payload,
                                         &customer_lic_sig, client_fd);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E,
                     "Error: ovsa_extract_sw_quote_info failed with "
                     "error code %d\n",
                     ret);
        }
#ifndef DISABLE_TPM2_HWQUOTE
        /* Extract HW_quote */
        ret = ovsa_extract_HW_quote_info(payload_quote_info, &hw_quote_info, client_fd);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E,
                     "Error: ovsa_extract_HW_quote_info failed with "
                     "error code %d\n",
                     ret);
        }
#endif
        /* Validate TCB */
        ret = ovsa_do_validate_quote(sw_quote_info, hw_quote_info, customer_lic_sig);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: validate TCB failed %d\n", ret);
            memcpy_s(response,
                     strnlen_s("FAIL: Error in TCB Validation Invalid runtime", MAX_NAME_SIZE),
                     "FAIL: Error in TCB Validation Invalid runtime",
                     strnlen_s("FAIL: Error in TCB Validation Invalid runtime", MAX_NAME_SIZE));
            goto out1;
        }
        /* Validate Secret */
        ret = ovsa_do_validate_secret(payload_quote_info, client_fd);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: validate secret failed %d\n", ret);
            memcpy_s(response,
                     strnlen_s("FAIL: Error in secret Validation Invalid runtime", MAX_NAME_SIZE),
                     "FAIL: Error in secret Validation Invalid runtime",
                     strnlen_s("FAIL: Error in secret Validation Invalid runtime", MAX_NAME_SIZE));
            goto out1;
        }
        /* Verify quote */
        ret = ovsa_server_tpm2_verifyquote(client_fd);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error Verify quote failed with code %d\n", ret);
            memcpy_s(response,
                     strnlen_s("FAIL: Error in Quote Validation Invalid runtime", MAX_NAME_SIZE),
                     "FAIL: Error in Quote Validation Invalid runtime",
                     strnlen_s("FAIL: Error in Quote Validation Invalid runtime", MAX_NAME_SIZE));
            goto out1;
        }
        /* remove quote files from tmp directory */
        ovsa_remove_quote_files(client_fd);
        received_all_quote_params = false;
        start_license_check       = true;
        goto start_license_check;
    }
    ovsa_server_safe_free(&sw_quote_info.quote_message);
    ovsa_server_safe_free(&sw_quote_info.quote_sig);
    ovsa_server_safe_free(&sw_quote_info.quote_pcr);
    ovsa_server_safe_free(&sw_quote_info.ak_pub_key);
#ifndef DISABLE_TPM2_HWQUOTE
    ovsa_server_safe_free(&hw_quote_info.quote_message);
    ovsa_server_safe_free(&hw_quote_info.quote_sig);
    ovsa_server_safe_free(&hw_quote_info.quote_pcr);
    ovsa_server_safe_free(&hw_quote_info.ak_pub_key);
#endif

    /* Extract customer certificate from Data Base */
    license_guid = customer_lic_sig.customer_lic.license_guid;
    model_guid   = customer_lic_sig.customer_lic.model_guid;
    OVSA_DBG(DBG_D,
             "OVSA:Customer license_guid: %s\n Customer model_guid: "
             "%s\n\nExtract customer certificate frm db\n",
             license_guid, model_guid);
    ret = ovsa_db_get_customer_certificate(OVSA_DB_PATH, license_guid, model_guid, &cert);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Retrieve customer certificate failed with error code  %d\n", ret);
        memcpy_s(response,
                 strnlen_s("FAIL: Error in Retrieving customer certificate", MAX_NAME_SIZE),
                 "FAIL: Error in Retrieving customer certificate",
                 strnlen_s("FAIL: Error in Retrieving customer certificate", MAX_NAME_SIZE));
        goto out1;
    }
    /* Verify Nonce */
    OVSA_DBG(DBG_I, "OVSA:Verify Nonce\n");
    ret = ovsa_server_crypto_verify_mem(cert, nonce_buf, NONCE_SIZE, payload_signature);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Nonce verify fail. Customer license service failed %d\n", ret);
        memcpy_s(response, strnlen_s("FAIL: Error in Nonce Verification", MAX_NAME_SIZE),
                 "FAIL: Error in Nonce Verification",
                 strnlen_s("FAIL: Error in Nonce Verification", MAX_NAME_SIZE));
        goto out1;
    }
    OVSA_DBG(DBG_I, "OVSA:Customer license service Successful\n");

    /* Perform License check */
    ret = ovsa_db_validate_license_usage(OVSA_DB_PATH, license_guid, model_guid);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: License check validation failed with error code %d\n", ret);
        if (ret == OVSA_DB_TIMELIMT_FAIL) {
            memcpy_s(response, strnlen_s("FAIL: License TimeLimit Exceeded", MAX_NAME_SIZE),
                     "FAIL: License TimeLimit Exceeded",
                     strnlen_s("FAIL: License TimeLimit Exceeded", MAX_NAME_SIZE));
        } else if (ret == OVSA_DB_USAGELIMIT_FAIL) {
            memcpy_s(response, strnlen_s("FAIL: License UsageLimit Exceeded", MAX_NAME_SIZE),
                     "FAIL: License UsageLimit Exceeded",
                     strnlen_s("FAIL: License UsageLimit Exceeded", MAX_NAME_SIZE));
        } else {
            memcpy_s(response, strnlen_s("FAIL: Error in License check", MAX_NAME_SIZE),
                     "FAIL: Error in License check",
                     strnlen_s("FAIL: Error in License check", MAX_NAME_SIZE));
        }
        goto out1;
    }
    memcpy_s(response, strnlen_s("PASS", MAX_NAME_SIZE), "PASS", strnlen_s("PASS", MAX_NAME_SIZE));

out1:

    OVSA_DBG(DBG_D, "OVSA:Customer TCB check /license check /quote check: '%s'\n", response);

    /* Send check response to client */
    ret = ovsa_send_license_check_response(&ssl_session, response);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: ovsa_send_license_check_response failed %d\n", ret);
        goto out;
    }

out:
    ret = ovsa_license_service_close(ssl_session);
    if (ret < OVSA_OK)
        OVSA_DBG(DBG_E, "Error:ovsa_license_service_close failed with code %d\n", ret);

    ovsa_server_safe_free(&payload_signature);
    ovsa_server_safe_free(&cust_lic_payload);
    ovsa_server_safe_free(&json_payload);
    ovsa_server_safe_free(&nonce_buf);
    ovsa_server_safe_free(&cert);
    ovsa_server_safe_free(&customer_lic_sig.customer_lic.isv_certificate);
    ovsa_server_safe_free(&payload_EK_AK_bind_info);
    ovsa_server_safe_free(&payload_quote_info);
    ovsa_server_safe_free_tcb_list(&customer_lic_sig.customer_lic.tcb_signatures);
    ovsa_server_safe_free_url_list(&customer_lic_sig.customer_lic.license_url_list);

    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static pthread_mutex_t g_handshake_lock;

struct ovsa_thread_info {
    mbedtls_net_context client_fd;
    mbedtls_ssl_config* conf;
    ovsa_license_service_cb_t f_cb;
};

static ovsa_status_t ovsa_license_service_write(void* ssl, const uint8_t* buf, size_t len) {
    ovsa_status_t ret         = OVSA_OK;
    mbedtls_ssl_context* _ssl = (mbedtls_ssl_context*)ssl;

    if (!_ssl || len > INT_MAX)
        return -EINVAL;

    size_t written = 0;
    while (written < len) {
        ret = mbedtls_ssl_write(_ssl, buf + written, len - written);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (ret < OVSA_OK) {
            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
                ret = -ECONNRESET;
            OVSA_DBG(DBG_E, "Error: mbedtls_ssl_write failed with error code %d\n", ret);
            return OVSA_MBEDTLS_SSL_WRITE_FAILED;
        }
        written += (size_t)ret;
    }
    assert(written == len);
    return (int)written;
}

static ovsa_status_t ovsa_license_service_read(void* ssl, uint8_t* buf, size_t len) {
    ovsa_status_t ret         = OVSA_OK;
    mbedtls_ssl_context* _ssl = (mbedtls_ssl_context*)ssl;

    if (!_ssl || len > INT_MAX) {
        OVSA_DBG(DBG_E, "Error: Input parameters invalid %d\n", ret);
        return OVSA_INVALID_PARAMETER;
    }

    size_t read = 0;
    while (read < len) {
        ret = mbedtls_ssl_read(_ssl, buf + read, len - read);
        if (!ret)
            return -ECONNRESET;
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (ret < OVSA_OK) {
            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
                ret = -ECONNRESET;
            OVSA_DBG(DBG_E, "Error: mbedtls_ssl_read failed with error code %d\n", ret);
            return OVSA_MBEDTLS_SSL_READ_FAILED;
        }
        read += (size_t)ret;
    }

    assert(read == len);
    return (int)read;
}

static ovsa_status_t ovsa_license_service_close(void* ssl) {
    ovsa_status_t ret         = OVSA_OK;
    mbedtls_ssl_context* _ssl = (mbedtls_ssl_context*)ssl;

    if (!_ssl)
        return ret;

    ret = -1;
    while (ret < OVSA_OK) {
        ret = mbedtls_ssl_close_notify(_ssl);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (ret < OVSA_OK) {
            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
                ret = -ECONNRESET;
            OVSA_DBG(DBG_E, "Error: ovsa_license_service_close failed with error code %d\n", ret);
            return OVSA_MBEDTLS_SSL_CLOSE_FAILED;
        }
    }
    return ret;
}

static void* ovsa_client_connection(void* data) {
    ovsa_status_t ret           = OVSA_OK;
    struct ovsa_thread_info* ti = (struct ovsa_thread_info*)data;
    int handshake_status        = 0;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);

    ret = mbedtls_ssl_setup(&ssl, ti->conf);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: mbedtls_ssl_setup failed with error code %d\n", ret);
        ret = OVSA_MBEDTLS_SSL_SETUP_FAILED;
        goto out;
    }
    mbedtls_ssl_conf_read_timeout(&g_conf, READ_TIMEOUT_MS);
    mbedtls_ssl_set_bio(&ssl, &ti->client_fd, mbedtls_net_send, mbedtls_net_recv,
                        mbedtls_net_recv_timeout);

    ret = -1;
    while (ret < OVSA_OK) {
        OVSA_DBG(DBG_I, "OVSA:Calling mbedtls_ssl_handshake\n");
        ret = pthread_mutex_lock(&g_handshake_lock);
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "Error:mutex lock failed %d\n", ret);
            goto out;
        }
        handshake_status = mbedtls_ssl_handshake(&ssl);
        ret              = pthread_mutex_unlock(&g_handshake_lock);
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "Error:mutex unlock failed %d\n", ret);
            goto out;
        }
        if (handshake_status == MBEDTLS_ERR_SSL_WANT_READ ||
            handshake_status == MBEDTLS_ERR_SSL_WANT_WRITE) {
            OVSA_DBG(DBG_I, "OVSA:MBEDTLS_ERR_SSL_WANT_READ_WRITE\n");
            continue;
        }
        if (handshake_status < OVSA_OK) {
            OVSA_DBG(DBG_I, "OVSA:mbedtls_ssl_handshake returned error %d\n", ret);
            ret = OVSA_MBEDTLS_SSL_HANDSHAKE_FAILED;
            goto out;
        }
    }

    if (ti->f_cb) {
        /* pass ownership of SSL session with client to the caller; it is caller's
         * responsibility to gracefully terminate the session using
         * ovsa_license_service_close() */
        ti->f_cb(&ssl, ti->client_fd.fd);
    } else {
        ret = ovsa_license_service_close(&ssl);
        if (ret < OVSA_OK)
            OVSA_DBG(DBG_E, "Error:ovsa_license_service_close failed with code %d\n", ret);
    }

out:
    mbedtls_ssl_free(&ssl);
    mbedtls_net_free(&ti->client_fd);
    ovsa_server_safe_free((char**)&ti);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return NULL;
}

static ovsa_status_t ovsa_license_service_start_server(const char* cert_path, const char* key_path,
                                                       ovsa_license_service_cb_t f_cb) {
    ovsa_status_t ret = OVSA_OK;
    int index         = 0;

    if (!cert_path || !key_path || !g_port) {
        OVSA_DBG(DBG_E, "Error: Input parameters invalid %d\n", ret);
        return OVSA_INVALID_PARAMETER;
    }

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    ret = pthread_mutex_init(&g_handshake_lock, NULL);
    if (ret < OVSA_OK)
        return ret;

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_pk_context srvkey;
    mbedtls_x509_crt srvcert;
    mbedtls_net_context client_fd;
    mbedtls_net_context listen_fd;

    mbedtls_ssl_config_init(&g_conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_pk_init(&srvkey);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_net_init(&client_fd);
    mbedtls_net_init(&listen_fd);

    const char pers[] = "ovsa-license-service";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const uint8_t*)pers,
                                sizeof(pers));
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:mbedtls_ctr_drbg_seed with failed code %d\n", ret);
        ret = OVSA_MBEDTLS_CTR_DRBG_SEED_FAILED;
        goto out;
    }

    OVSA_DBG(DBG_I, "OVSA:Calling mbedtls_x509_crt_parse_file\n");
    ret = mbedtls_x509_crt_parse_file(&srvcert, cert_path);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:mbedtls_x509_crt_parse_file failed with code %d\n", ret);
        ret = OVSA_MBEDTLS_x509_CERT_PARSE_FAILED;
        goto out;
    }

    ret = mbedtls_pk_parse_keyfile(&srvkey, key_path, NULL);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:mbedtls_pk_parse_keyfile failed with code %d\n", ret);
        ret = OVSA_MBEDTLS_PK_PARSE_KEYFILE_FAILED;
        goto out;
    }

    OVSA_DBG(DBG_I, "OVSA:Calling mbedtls_net_bind %s\n", g_port);
    ret = mbedtls_net_bind(&listen_fd, NULL, g_port, MBEDTLS_NET_PROTO_TCP);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:mbedtls_net_bind failed with code %d\n", ret);
        ret = OVSA_MBEDTLS_NET_BIND_FAILED;
        goto out;
    }
    ret = mbedtls_ssl_config_defaults(&g_conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:mbedtls_ssl_config_defaults failed with code %d\n", ret);
        ret = OVSA_MBEDTLS_SSL_CONFIG_DEFAULTS_FAILED;
        goto out;
    }
    mbedtls_ssl_conf_rng(&g_conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    /* mbedtls debug */
    mbedtls_ssl_conf_dbg(&g_conf, ovsa_mbedtls_debug_cb, NULL);
    mbedtls_debug_set_threshold(MBEDTLS_DEBUG_LEVEL);

    /* Add supported Cipher Suites */
    memset_s(g_cipher_suite, CIPHER_SUITE_SIZE, 0);
    memset_s(g_curve_list, CURVE_LIST_SIZE, 0);

    for (index = 0; index < CIPHER_SUITE_SIZE; index++) {
        g_cipher_suite[index] = mbedtls_ssl_get_ciphersuite_id(g_cipher_suitename[index]);
    }

    g_curve_list[0] = MBEDTLS_ECP_DP_SECP521R1;
    g_curve_list[1] = MBEDTLS_ECP_DP_NONE;

    mbedtls_ssl_conf_curves(&g_conf, g_curve_list);
    mbedtls_ssl_conf_ciphersuites(&g_conf, g_cipher_suite);

    mbedtls_ssl_conf_authmode(&g_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

    mbedtls_ssl_conf_ca_chain(&g_conf, &srvcert, NULL);

    ret = mbedtls_ssl_conf_own_cert(&g_conf, &srvcert, &srvkey);
    if (ret < OVSA_OK) {
        ret = OVSA_MBEDTLS_SSL_CONFIG_OWN_CERT;
        OVSA_DBG(DBG_E, "Error: mbedtls_ssl_conf_own_cert failed with error code %d\n", ret);
        goto out;
    }

new_client:
    OVSA_DBG(DBG_I, "OVSA:Waiting for Client connection\n");
    ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL);
    if (ret < OVSA_OK) {
        mbedtls_net_free(&client_fd);
        goto new_client;
    }

    OVSA_DBG(DBG_I, "OVSA:Client connection sucessfull\n");
    struct ovsa_thread_info* ti = calloc(1, sizeof(*ti));
    if (!ti) {
        mbedtls_net_free(&client_fd);
        goto new_client;
    }

    /* client_fd is reused for multiple threads, so pass ownership of its copy to
     * new thread */
    memcpy(&ti->client_fd, &client_fd, sizeof(client_fd));
    ti->conf = &g_conf;
    ti->f_cb = f_cb;

    pthread_attr_t tattr;
    ret = pthread_attr_init(&tattr);
    if (ret < OVSA_OK) {
        ovsa_server_safe_free((char**)&ti);
        mbedtls_net_free(&client_fd);
        goto new_client;
    }

    ret = pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
    if (ret < OVSA_OK) {
        ovsa_server_safe_free((char**)&ti);
        pthread_attr_destroy(&tattr);
        mbedtls_net_free(&client_fd);
        goto new_client;
    }

    pthread_t tid;
    ret = pthread_create(&tid, &tattr, ovsa_client_connection, ti);
    if (ret < OVSA_OK) {
        ovsa_server_safe_free((char**)&ti);
        mbedtls_net_free(&client_fd);
    }

    pthread_attr_destroy(&tattr);
    goto new_client;

    ret = pthread_mutex_destroy(&g_handshake_lock);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:mutex destroy failed %d\n", ret);
    }

out:
    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&srvkey);
    mbedtls_net_free(&listen_fd);
    mbedtls_net_free(&client_fd);
    mbedtls_ssl_config_free(&g_conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

int main(int argc, char** argv) {
    ovsa_status_t ret = OVSA_OK;
    void* ssl_session = NULL;

    ret = pthread_mutex_init(&g_print_lock, NULL);
    if (ret < OVSA_OK)
        return ret;

    OVSA_DBG(DBG_I, "OVSA:Starting the Ovsa license service");

    char* port_number = NULL;
    port_number       = secure_getenv("TLS_PORT_NUMBER");

    if (port_number == NULL)
        strcpy_s(g_port, sizeof(g_port), DEFAULT_PORT);
    else
        strcpy_s(g_port, sizeof(g_port), port_number);

    ret = ovsa_license_service_start_server(CERTIFICATE_PATH, KEY_PATH,
                                            ovsa_client_license_service_callback);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: ovsa_license_service_start_server() returned %d\n", ret);
        return ret;
    }

    ret = pthread_mutex_destroy(&g_print_lock);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:mutex destroy failed %d\n", ret);
    }
    return ret;
}
