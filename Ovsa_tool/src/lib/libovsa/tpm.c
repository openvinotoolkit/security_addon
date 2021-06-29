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

#include "tpm.h"

#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "utils.h"

ovsa_status_t ovsa_do_load_EK_context_AKkeys() {
    ovsa_status_t ret = OVSA_OK;

    OVSA_DBG(DBG_D, "LibOVSA: Entering %s\n", __func__);

    /* Clean up the previous context which are not flushed before starting */
    char* const flushall_context_cmd[] = {"/usr/bin/tpm2_flushcontext", "-s", 0};

    if (ovsa_do_run_tpm2_command(flushall_context_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Error loading EK context AKkeys failed to execute %s command\n",
                 flushall_context_cmd[0]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }

    /* Load EK context */
    char* const createek_cmd[] = {"/usr/bin/tpm2_createek",
                                  "--ek-context",
                                  TPM2_EK_CTX,
                                  "--key-algorithm",
                                  "rsa",
                                  "--public",
                                  TPM2_EK_PUB_KEY,
                                  0};

    if (ovsa_do_run_tpm2_command(createek_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Error loading EK context AKkeys failed to execute %s command\n",
                 createek_cmd[0]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }

    /* Startauthsession */
    char* const startauthsession_cmd[] = {"/usr/bin/tpm2_startauthsession", "-S",
                                          TPM2_QUOTE_SESSION_CTX, "--policy-session", 0};

    if (ovsa_do_run_tpm2_command(startauthsession_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Error loading EK context AKkeys failed to execute %s command\n",
                 startauthsession_cmd[0]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }

    /* Policysecret */
    char* const policysecret_cmd[] = {
        "/usr/bin/tpm2_policysecret", "-S", TPM2_QUOTE_SESSION_CTX, "-c", "e", 0};

    if (ovsa_do_run_tpm2_command(policysecret_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Error loading EK context AKkeys failed to execute %s command\n",
                 policysecret_cmd[0]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }

    /* TPM load */
    char* const load_cmd[] = {"/usr/bin/tpm2_load",
                              "-C",
                              TPM2_EK_CTX,
                              "-u",
                              TPM2_AK_PUB,
                              "-r",
                              TPM2_AK_PRIV,
                              "-c",
                              TPM2_AK_CTX,
                              "-P",
                              "session:" TPM2_QUOTE_SESSION_CTX,
                              0};

    if (ovsa_do_run_tpm2_command(load_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Error loading EK context AKkeys failed to execute %s command\n",
                 load_cmd[0]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }

    /* Flushcontext */
    char* const flushcontext_cmd[] = {"/usr/bin/tpm2_flushcontext", TPM2_QUOTE_SESSION_CTX, 0};

    if (ovsa_do_run_tpm2_command(flushcontext_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Error loading EK context AKkeys failed to execute %s command\n",
                 flushcontext_cmd[0]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }

    OVSA_DBG(DBG_D, "LibOVSA: %s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_tpm2_generaterand() {
    ovsa_status_t ret = OVSA_OK;

    OVSA_DBG(DBG_D, "LibOVSA: Entering %s\n", __func__);

    /* Generate Nonce using TPM2_getrandom */
    char* const getrand_cmd[] = {"/usr/bin/tpm2_getrandom", "-o", TPM2_HW_QUOTE_NONCE, "32", 0};

    if (ovsa_do_run_tpm2_command(getrand_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Error generating rand failed to execute %s command\n",
                 getrand_cmd[0]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }

    OVSA_DBG(DBG_D, "LibOVSA: %s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_tpm2_generatequote(char* nonce) {
    ovsa_status_t ret = OVSA_OK;

    OVSA_DBG(DBG_D, "LibOVSA: Entering %s\n", __func__);

    if (nonce[0] == '\0') {
        nonce = TPM2_QUOTE_NONCE;

        /* Generate Nonce using TPM2_getrandom */
        char* const getrand_cmd[] = {"/usr/bin/tpm2_getrandom", "--output", nonce, "32", 0};

        if (ovsa_do_run_tpm2_command(getrand_cmd, NULL) != 0) {
            OVSA_DBG(DBG_E, "LibOVSA: Error generating quote failed to execute %s command\n",
                     getrand_cmd[0]);
            return OVSA_TPM2_CMD_EXEC_FAIL;
        }
    }

    /* Load primary EK ctx and AK keys */
    ret = ovsa_do_load_EK_context_AKkeys();
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E,
                 "LibOVSA: Error generating quote failed to load EK context AKkeys with code %d\n",
                 ret);
        return ret;
    }

    /* Generate quote using tpm2_quote */
    char* const quote_cmd[] = {"/usr/bin/tpm2_quote",
                               "--key-context",
                               TPM2_AK_CTX,
                               "--pcr-list",
                               "sha256:all",
                               "--message",
                               TPM2_SWQUOTE_MSG,
                               "--signature",
                               TPM2_SWQUOTE_SIG,
                               "--qualification",
                               nonce,
                               "--hash-algorithm",
                               "sha256",
                               "--pcr",
                               TPM2_SWQUOTE_PCR,
                               0};

    if (ovsa_do_run_tpm2_command(quote_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Error generating quote failed to execute %s command\n",
                 quote_cmd[0]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }

    OVSA_DBG(
        DBG_D,
        "\nLibOVSA: Generated quote successfully, message file: %s, signature: %s, PCR file: %s\n",
        quote_cmd[6], quote_cmd[8], quote_cmd[14]);
    OVSA_DBG(DBG_D, "LibOVSA: %s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_do_run_tpm2_command(char* const argv[], char* output) {
    ovsa_status_t ret     = OVSA_OK;
    size_t cmd_output_len = 0;
    int child_status = 0, nbytes = 0, link[2], err = -1;
    pid_t child_pid;
    char cmd_output[MAX_EKEY_SIZE];
    char error_output[MAX_BUF_SIZE];

    if ((argv == NULL) || (argv[0] == NULL)) {
        OVSA_DBG(DBG_E, "LibOVSA: Error tpm2 command failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    OVSA_DBG(DBG_D, "LibOVSA: %s: Loading object '%s' into TPM\n", __func__, argv[0]);
    if (pipe(link) == -1) {
        OVSA_DBG(DBG_E, "LibOVSA: Error tpm2 command failed in creating pipe\n");
        return OVSA_SYSCALL_READ_PIPE_FAIL;
    }

    child_pid = fork();
    if (child_pid == 0) {
        if (dup2(link[1], STDOUT_FILENO) == -1) {
            OVSA_DBG(DBG_E, "LibOVSA: Error tpm2 command failed in dup2 syscall\n");
            close(link[1]);
            return OVSA_SYSCALL_DUP2_FAIL;
        }
        close(link[0]);
        close(link[1]);

        err = execve(argv[0], argv, NULL);
        if (err == -1) {
            /* If it got here, it's an error */
            OVSA_DBG(DBG_E, "LibOVSA: Error executing %s failed with error %s\n", argv[0],
                     strerror(errno));
            return OVSA_SYSCALL_EXECVE_FAIL;
        }
    } else if (child_pid < 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Error TPM2 command failed in fork\n");
        close(link[0]);
        close(link[1]);
        return OVSA_SYSCALL_FORK_FAIL;
    }

    close(link[1]);

    if (output != NULL) {
        memset_s(cmd_output, sizeof(cmd_output), 0);
        nbytes = read(link[0], cmd_output, sizeof(cmd_output));
        if (nbytes > 0) {
            cmd_output_len = strnlen_s(cmd_output, MAX_EKEY_SIZE);
            if (cmd_output_len == EOK) {
                OVSA_DBG(DBG_E,
                         "LibOVSA: Error tpm2 command failed in getting the size of the "
                         "command output\n");
                return OVSA_TPM2_GENERIC_ERROR;
            }

            if (memcpy_s(output, MAX_EKEY_SIZE, cmd_output, cmd_output_len) != EOK) {
                OVSA_DBG(DBG_E, "LibOVSA: Error tpm2 command failed in getting the output\n");
                return OVSA_MEMIO_ERROR;
            }
        } else {
            OVSA_DBG(DBG_E, "LibOVSA: Error tpm2 command failed in executing the tpm2 command\n");
            return OVSA_TPM2_CMD_EXEC_FAIL;
        }
    }

    if ((waitpid(child_pid, &child_status, 0)) == -1) {
        OVSA_DBG(DBG_E, "LibOVSA: Error tpm2 command failed in waitpid\n");
        close(link[0]);
        return OVSA_SYSCALL_WAITPID_FAIL;
    }

    if (WIFEXITED(child_status)) {
        int exit_status = WEXITSTATUS(child_status);
        if (exit_status != 0) {
            OVSA_DBG(DBG_E, "LibOVSA: Error execution of TPM2 %s failed with exit_status %d \n",
                     argv[0], exit_status);
            memset_s(error_output, sizeof(error_output), 0);
            nbytes = read(link[0], error_output, (sizeof(error_output) - 1));
            if (nbytes > 0) {
                int output_len = strnlen_s(error_output, (sizeof(error_output) - 1));
                if (output_len == EOK) {
                    OVSA_DBG(DBG_E,
                             "LibOVSA: Error tpm2 command failed in getting the size of the "
                             "command output\n");
                    close(link[0]);
                    return OVSA_TPM2_GENERIC_ERROR;
                }
                /* Added for KW issue */
                output_len = (output_len == MAX_BUF_SIZE) ? (output_len - 1) : (output_len);
                error_output[output_len] = '\0';
                OVSA_DBG(DBG_E, "%s\n", error_output);
            }
            close(link[0]);
            return OVSA_SYSCALL_WAITPID_FAIL;
        }
    }
    close(link[0]);

    return ret;
}

ovsa_status_t ovsa_do_tpm2_activatecredential(char* cred_outbuf) {
    ovsa_status_t ret = OVSA_OK;

    OVSA_DBG(DBG_D, "LibOVSA: Entering %s\n", __func__);

    /* Load primary EK ctx and AK keys */
    ret = ovsa_do_load_EK_context_AKkeys();
    if (ret < OVSA_OK) {
        OVSA_DBG(
            DBG_E,
            "LibOVSA: Error activate credential failed to load EK context AKkeys with code %d\n",
            ret);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }

    /* Startauthsession */
    char* const startauthsession_argv[] = {"/usr/bin/tpm2_startauthsession", "--policy-session",
                                           "--session", TPM2_QUOTE_SESSION_CTX, 0};
    if (ovsa_do_run_tpm2_command(startauthsession_argv, NULL) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Error activate credential failed to execute %s command\n",
                 startauthsession_argv[0]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }

    /* Policysecret */
    char* const policysecret_argv[] = {
        "/usr/bin/tpm2_policysecret", "-S", TPM2_QUOTE_SESSION_CTX, "-c", TPM2_RH_ENDORSEMENT, 0};

    if (ovsa_do_run_tpm2_command(policysecret_argv, NULL) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Error activate credential failed to execute %s command\n",
                 policysecret_argv[0]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }

    /* Activatecredential */
    char* const activatecredential_argv[] = {"/usr/bin/tpm2_activatecredential",
                                             "--credentialedkey-context",
                                             TPM2_AK_CTX,
                                             "--credentialkey-context",
                                             TPM2_EK_CTX,
                                             "--credential-blob",
                                             TPM2_CREDOUT_FILE,
                                             "--certinfo-data",
                                             TPM2_ACTCRED_OUT,
                                             "--credentialkey-auth",
                                             "session:" TPM2_QUOTE_SESSION_CTX,
                                             0};

    /* Run activatecredential */
    if (ovsa_do_run_tpm2_command(activatecredential_argv, NULL) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Error activate credential failed to execute %s command\n",
                 activatecredential_argv[0]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }

    char* const flushcontext_argv[] = {"/usr/bin/tpm2_flushcontext", TPM2_QUOTE_SESSION_CTX, 0};

    if (ovsa_do_run_tpm2_command(flushcontext_argv, NULL) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Error activate credential failed to execute %s command\n",
                 flushcontext_argv[0]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }

    OVSA_DBG(DBG_I, "LibOVSA: TPM2 activatecredential successful...\n");
    OVSA_DBG(DBG_D, "LibOVSA: %s Exit\n", __func__);

    return ret;
}

ovsa_status_t ovsa_tpm2_unsealkey(char* encryption_key) {
    ovsa_status_t ret = OVSA_OK;

    if (encryption_key == NULL) {
        OVSA_DBG(DBG_E, "LibOVSA: Error tpm2 unsealing key failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    /* Load object to TPM */
    char* const loadexternal_cmd[] = {"/usr/bin/tpm2_loadexternal",
                                      "--key-algorithm=rsa",
                                      "--hierarchy=o",
                                      "--public=" TPM2_SEAL_SIGN_PUB_KEY,
                                      "--key-context=" TPM2_SIGNING_KEY_CTX,
                                      "--name=" TPM2_SIGNING_KEY_NAME,
                                      0,
                                      NULL};

    if (ovsa_do_run_tpm2_command(loadexternal_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Error tpm2 unsealing key failed to execute %s command\n",
                 loadexternal_cmd[0]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }

    /* Verify the signature on the pcr and get the tpm verification tkt */
    char* const verify_cmd[] = {"/usr/bin/tpm2_verifysignature",
                                "--key-context=" TPM2_SIGNING_KEY_CTX,
                                "--hash-algorithm=sha256",
                                "--message=" TPM2_SEAL_PCR_POLICY,
                                "--signature=" TPM2_SEAL_PCR_SIGN,
                                "--ticket=" TPM2_VERIFICATION_TKT,
                                "--scheme=rsassa",
                                0,
                                NULL};

    if (ovsa_do_run_tpm2_command(verify_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Error tpm2 unsealing key failed to execute %s command\n",
                 verify_cmd[0]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }

    /* Start session with TPM */
    char* const authsession_cmd[] = {"/usr/bin/tpm2_startauthsession", "--policy-session",
                                     "--session=" TPM2_SESSION_CTX, 0, NULL};

    if (ovsa_do_run_tpm2_command(authsession_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Error tpm2 unsealing key failed to execute %s command\n",
                 authsession_cmd[0]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }

    /* Create policy with PCR */
    char* const policypcr_cmd[] = {"/usr/bin/tpm2_policypcr",
                                   "--pcr-list=sha256:0",
                                   "--session=" TPM2_SESSION_CTX,
                                   "--policy=" TPM2_PCR_POLICY,
                                   0,
                                   NULL};

    if (ovsa_do_run_tpm2_command(policypcr_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Error tpm2 unsealing key failed to execute %s command\n",
                 policypcr_cmd[0]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }

    /* Run policyauthorize to Unseal */
    char* const policyauth_cmd[] = {"/usr/bin/tpm2_policyauthorize",
                                    "--session=" TPM2_SESSION_CTX,
                                    "--input=" TPM2_PCR_POLICY,
                                    "--name=" TPM2_SIGNING_KEY_NAME,
                                    "--ticket=" TPM2_VERIFICATION_TKT,
                                    0,
                                    NULL};

    if (ovsa_do_run_tpm2_command(policyauth_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Error tpm2 unsealing key failed to execute %s command\n",
                 policyauth_cmd[0]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }

    /* Unseal output to the file */
    char* const unseal_cmd[] = {"/usr/bin/tpm2_unseal", "--auth=session:" TPM2_SESSION_CTX,
                                "--object-context=0x81010001", 0, NULL};

    if (ovsa_do_run_tpm2_command(unseal_cmd, encryption_key) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Error tpm2 unsealing key failed to execute %s command\n",
                 unseal_cmd[0]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }

    char* const flushcontext_cmd[] = {"/usr/bin/tpm2_flushcontext", TPM2_SESSION_CTX, NULL};

    if (ovsa_do_run_tpm2_command(flushcontext_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Error tpm2 unsealing key failed to execute %s command\n",
                 flushcontext_cmd[0]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }

    if (remove(TPM2_SIGNING_KEY_NAME) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Warning could not delete %s file\n", TPM2_SIGNING_KEY_NAME);
    }

    if (remove(TPM2_SIGNING_KEY_CTX) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Warning could not delete %s file\n", TPM2_SIGNING_KEY_CTX);
    }

    if (remove(TPM2_VERIFICATION_TKT) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Warning could not delete %s file\n", TPM2_VERIFICATION_TKT);
    }

    if (remove(TPM2_SESSION_CTX) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Warning could not delete %s file\n", TPM2_SESSION_CTX);
    }

    if (remove(TPM2_PCR_POLICY) != 0) {
        OVSA_DBG(DBG_E, "LibOVSA: Warning could not delete %s file\n", TPM2_PCR_POLICY);
    }

    return ret;
}
