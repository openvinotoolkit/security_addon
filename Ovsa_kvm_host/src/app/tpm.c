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

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ovsa.h"
#include "safe_mem_lib.h"
#include "utils.h"

#define MAX_BUF_SIZE 4096

static int ovsa_do_run_tpm2_command(char* const argv[], char* output) {
    ovsa_status_t ret     = OVSA_OK;
    size_t cmd_output_len = 0;
    int child_status = 0, nbytes = 0, link[2];
    pid_t child_pid;
    char cmd_output[MAX_BUF_SIZE];

    if ((argv == NULL) || (argv[0] == NULL)) {
        OVSA_DBG(DBG_E, "Error: TPM2 command failed with invalid parameter\n");
        ret = OVSA_INVALID_PARAMETER;
        return ret;
    }

    if (pipe(link) == -1) {
        OVSA_DBG(DBG_E, "Error: TPM2 command failed in creating pipe\n");
        ret = OVSA_SYSCALL_READ_PIPE_FAIL;
        return ret;
    }

    child_pid = fork();
    if (child_pid == 0) {
        int err = -1;

        if (dup2(link[1], STDOUT_FILENO) == -1) {
            OVSA_DBG(DBG_E, "Error: TPM2 command failed in dup2 syscall\n");
            ret = OVSA_SYSCALL_DUP2_FAIL;
            return ret;
        }
        close(link[0]);
        close(link[1]);

        err = execve(argv[0], argv, NULL);
        /* if it got here, it's an error */
        OVSA_DBG(DBG_E, "Error: Executing %s failed with error %s\n", argv[0], strerror(errno));
        ret = OVSA_SYSCALL_EXECVE_FAIL;
        return ret;
    } else if (child_pid < 0) {
        OVSA_DBG(DBG_E, "Error: TPM2 command failed in fork\n");
        ret = OVSA_SYSCALL_FORK_FAIL;
        return ret;
    }

    close(link[1]);

    if (output != NULL) {
        memset_s(cmd_output, sizeof(cmd_output), 0);
        nbytes = read(link[0], cmd_output, sizeof(cmd_output));
        if (nbytes > 0) {
            cmd_output_len = strnlen_s(cmd_output, MAX_BUF_SIZE);
            if (cmd_output_len == EOK) {
                OVSA_DBG(DBG_E,
                         "Error: TPM2 command failed in getting the size of the "
                         "command output\n");
                ret = OVSA_TPM2_GENERIC_ERROR;
                return ret;
            }

            if (memcpy_s(output, MAX_BUF_SIZE, cmd_output, cmd_output_len) != EOK) {
                OVSA_DBG(DBG_E, "Error: TPM2 command failed in getting the output\n");
                ret = OVSA_MEMIO_ERROR;
                return ret;
            }
        } else {
            OVSA_DBG(DBG_E, "Error: TPM2 command failed in executing the tpm2 command\n");
            ret = OVSA_TPM2_CMD_EXEC_FAIL;
            return ret;
        }
    }

    if ((waitpid(child_pid, &child_status, 0)) == -1) {
        OVSA_DBG(DBG_E, "Error: TPM2 command failed in waitpid\n");
        ret = OVSA_SYSCALL_WAITPID_FAIL;
        return ret;
    }
    if (WIFEXITED(child_status)) {
        int exit_status = WEXITSTATUS(child_status);
        if (exit_status != 0) {
            OVSA_DBG(DBG_E, "Error: Execution of TPM2 command %s failed\n", argv[1]);
            ret = OVSA_SYSCALL_WAITPID_FAIL;
            return ret;
        }
    }

    return ret;
}

static ovsa_status_t ovsa_do_load_EK_context_AKkeys(char* tmp_session_ctx) {
    ovsa_status_t ret = OVSA_OK;
    char load_cmd_session_ctx[MAX_FILE_LEN];

    OVSA_DBG(DBG_I, "OVSA:Entering %s\n", __func__);

    /* Clean up the previous context which are not flushed before starting */
    char* const flushall_context_cmd[] = {
        "/usr/bin/sudo", "tpm2_flushcontext", "-s", "-T", "device:/dev/tpmrm0", 0};
    if (ovsa_do_run_tpm2_command(flushall_context_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "Error: Command %s failed to execute \n", flushall_context_cmd[1]);
        ret = OVSA_TPM2_CMD_EXEC_FAIL;
        return ret;
    }

    /* load EK context */
    char* const createek_cmd[] = {"/usr/bin/sudo",
                                  "tpm2_createek",
                                  "--ek-context",
                                  "/var/OVSA/Quote/tpm_ek.ctx",
                                  "--key-algorithm",
                                  "rsa",
                                  "--public",
                                  "/var/OVSA/Quote/tpm_ek.pub",
                                  "-T",
                                  "device:/dev/tpmrm0",
                                  0};
    if (ovsa_do_run_tpm2_command(createek_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "Error: Command %s failed to execute \n", createek_cmd[1]);
        ret = OVSA_TPM2_CMD_EXEC_FAIL;
        return ret;
    }

    /* start authsession */
    char* const startauthsession_cmd[] = {"/usr/bin/sudo",      "tpm2_startauthsession",
                                          "--session",          tmp_session_ctx,
                                          "--policy-session",   "-T",
                                          "device:/dev/tpmrm0", 0};
    if (ovsa_do_run_tpm2_command(startauthsession_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "Error: Command %s failed to execute \n", startauthsession_cmd[1]);
        ret = OVSA_TPM2_CMD_EXEC_FAIL;
        return ret;
    }

    /* policy secret */
    char* const policysecret_cmd[] = {"/usr/bin/sudo",
                                      "tpm2_policysecret",
                                      "--session",
                                      tmp_session_ctx,
                                      "--object-context",
                                      "e",
                                      "-T",
                                      "device:/dev/tpmrm0",
                                      0};
    if (ovsa_do_run_tpm2_command(policysecret_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "Error: Command %s failed to execute \n", policysecret_cmd[1]);
        ret = OVSA_TPM2_CMD_EXEC_FAIL;
        return ret;
    }
    memset_s(load_cmd_session_ctx, sizeof(load_cmd_session_ctx), 0);
    strcpy_s(load_cmd_session_ctx, sizeof("session:"), "session:");
    strcat_s(load_cmd_session_ctx, MAX_FILE_LEN, tmp_session_ctx);

    /* tpm load */
    char* const load_cmd[] = {"/usr/bin/sudo",
                              "tpm2_load",
                              "--parent-context",
                              "/var/OVSA/Quote/tpm_ek.ctx",
                              "--public",
                              "/var/OVSA/Quote/tpm_ak.pub",
                              "--private",
                              "/var/OVSA/Quote/tpm_ak.priv",
                              "--key-context",
                              "/var/OVSA/Quote/tpm_ak.ctx",
                              "--auth",
                              load_cmd_session_ctx,
                              "-T",
                              "device:/dev/tpmrm0",
                              0};
    if (ovsa_do_run_tpm2_command(load_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "Error: Command %s failed to execute \n", load_cmd[1]);
        ret = OVSA_TPM2_CMD_EXEC_FAIL;
        return ret;
    }

    /* flushcontext */
    char* const flushcontext_cmd[] = {
        "/usr/bin/sudo", "tpm2_flushcontext", tmp_session_ctx, "-T", "device:/dev/tpmrm0", 0};

    if (ovsa_do_run_tpm2_command(flushcontext_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "Error: Command %s failed to execute \n", flushcontext_cmd[1]);
        ret = OVSA_TPM2_CMD_EXEC_FAIL;
        return ret;
    }
    OVSA_DBG(DBG_I, "OVSA: EK Context and AK Keys loaded into TPM\n");
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_tpm2_generate_quote(char* nonce, int sockfd) {
    ovsa_status_t ret = OVSA_OK;

    OVSA_DBG(DBG_I, "OVSA:Entering %s\n", __func__);

    char tmp_dir[MAX_FILE_LEN];
    char tmp_quote_msg[MAX_FILE_LEN];
    char tmp_quote_sig[MAX_FILE_LEN];
    char tmp_nonce_file[MAX_FILE_LEN];
    char tmp_quote_pcr[MAX_FILE_LEN];
    char tmp_session_ctx[MAX_FILE_LEN];

    /* Delete old quote files if already exsists */
    ret = ovsa_remove_quote_files(sockfd);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:remove quote files failed with code %d\n", ret);
        return ret;
    }

    CREATE_TMP_DIR_PATH(tmp_dir, sockfd);

    ret = mkdir(tmp_dir, 0777);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: tmp directory %s creation failed ", tmp_dir);
        return OVSA_FILEOPEN_FAIL;
    }
    CREATE_FILE_PATH(tmp_dir, tmp_quote_msg, TPM2_QUOTE_MSG);
    CREATE_FILE_PATH(tmp_dir, tmp_quote_sig, TPM2_QUOTE_SIG);
    CREATE_FILE_PATH(tmp_dir, tmp_nonce_file, TPM2_NONCE_FILE);
    CREATE_FILE_PATH(tmp_dir, tmp_quote_pcr, TPM2_QUOTE_PCR);
    CREATE_FILE_PATH(tmp_dir, tmp_session_ctx, TPM2_SESSION_CTX);

    /* Load primary EK ctx and AK keys */
    ret = ovsa_do_load_EK_context_AKkeys(tmp_session_ctx);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: load_EK_context_AKkeys failed %d\n", ret);
        ret = OVSA_TPM2_CMD_EXEC_FAIL;
        return ret;
    }

    char* nonce_bin_buff    = NULL;
    size_t nonce_bin_length = 0, nonce_length = 0;

    ret = ovsa_get_string_length(nonce, &nonce_length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of nonce %d\n", ret);
        return ret;
    }

    nonce_length += 1;
    ret = ovsa_safe_malloc(nonce_length, &nonce_bin_buff);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "Error:memory alloc failed with code %d\n", ret);
        return ret;
    }

    ret = ovsa_crypto_convert_base64_to_bin(nonce, nonce_length - 1, nonce_bin_buff,
                                            &nonce_bin_length);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: convert pem to bin failed with code %d\n", ret);
        return ret;
    }

    /* write quote nounce to file */
    FILE* fquote_nonce = fopen(tmp_nonce_file, "w");
    if (fquote_nonce == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "Error: Creating file %s failed with code %d\n", tmp_nonce_file, ret);
        return ret;
    }
    fwrite(nonce_bin_buff, nonce_bin_length, 1, fquote_nonce);
    fclose(fquote_nonce);

    /* Generate quote using tpm2_quote */
    char* const quote_cmd[] = {"/usr/bin/sudo",
                               "tpm2_quote",
                               "--key-context",
                               "/var/OVSA/Quote/tpm_ak.ctx",
                               "--pcr-list",
                               "sha256:all",
                               "--message",
                               tmp_quote_msg,
                               "--signature",
                               tmp_quote_sig,
                               "--qualification",
                               tmp_nonce_file,
                               "--hash-algorithm",
                               "sha256",
                               "--pcr",
                               tmp_quote_pcr,
                               "-T",
                               "device:/dev/tpmrm0",
                               0};

    if (ovsa_do_run_tpm2_command(quote_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "Error: Command %s failed to execute \n", quote_cmd[1]);
        ret = OVSA_TPM2_CMD_EXEC_FAIL;
        return ret;
    }
    OVSA_DBG(DBG_I,
             "\nOVSA:Generated successfully Message file: %s, Signature: %s, PCR "
             "file: %s\n",
             quote_cmd[7], quote_cmd[9], quote_cmd[15]);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}
