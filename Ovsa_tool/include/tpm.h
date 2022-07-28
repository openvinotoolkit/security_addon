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

#ifndef ENABLE_SGX_GRAMINE
#ifndef __OVSA_TPM_H_
#define __OVSA_TPM_H_

#include "ovsa_errors.h"

#define TPM2_CREDOUT_FILE_NAME     "cred.out.bin"
#define TPM2_ACTCRED_OUT_FILE_NAME "actcred.out"
#define CHALLENGE_NONCE_FILE_NAME  "challenge_nonce.bin"
#define TPM2_SWQUOTE_PCR_FILE_NAME "pcr.bin"
#define TPM2_SWQUOTE_MSG_FILE_NAME "pcr_quote.plain"
#define TPM2_SWQUOTE_SIG_FILE_NAME "pcr_quote.signature"

#define TPM2_PROVISION_DIR     "/var/OVSA/"
#define TPM2_EK_CERT           TPM2_PROVISION_DIR "Quote/tpm_ek_cert.pem"
#define TPM2_EK_PUB_KEY        TPM2_PROVISION_DIR "Quote/tpm_ek.pub"
#define TPM2_AK_NAME_HEX       TPM2_PROVISION_DIR "Quote/tpm_ak.name.hex"
#define TPM2_AK_PUB_PEM_KEY    TPM2_PROVISION_DIR "Quote/tpm_ak.pub.pem"
#define TPM2_QUOTE_SESSION_CTX TPM2_PROVISION_DIR "Quote/session.ctx"
#define TPM2_EK_CTX            TPM2_PROVISION_DIR "Quote/tpm_ek.ctx"
#define TPM2_AK_PUB            TPM2_PROVISION_DIR "Quote/tpm_ak.pub"
#define TPM2_AK_PRIV           TPM2_PROVISION_DIR "Quote/tpm_ak.priv"
#define TPM2_AK_CTX            TPM2_PROVISION_DIR "Quote/tpm_ak.ctx"
#define TPM2_HW_QUOTE_NONCE    TPM2_PROVISION_DIR "Quote/HW_QUOTE_nonce.bin"
#define TPM2_QUOTE_NONCE       TPM2_PROVISION_DIR "Quote/nonce.bin"

#define TPM2_EKCERT_CHAIN_ROM_CERT TPM2_PROVISION_DIR "Quote/ROM_cert.pem"
#define TPM2_EKCERT_ONDIE_CHAIN    TPM2_PROVISION_DIR "Quote/Ondie_chain.pem"

#define TPM2_SEAL_SIGN_PUB_KEY TPM2_PROVISION_DIR "Seal/signing_key_public.pem"
#define TPM2_SEAL_PCR_POLICY   TPM2_PROVISION_DIR "Seal/tpm_pcr.policy"
#define TPM2_SEAL_PCR_SIGN     TPM2_PROVISION_DIR "Seal/tpm_pcr.signature"

#define TPM2_RH_ENDORSEMENT "0x4000000B"
#define TPM2_UNSEALKEY_FILE "/opt/ovsa/mnt/unseal_key.bin"

/** \brief This function unseals the encryption key from tpm.
 *
 * \param[out] encryption_key   Pointer to store encryption key.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_tpm2_unsealkey(char* encryption_key);

/** \brief This function executes the tpm2 commands.
 *
 * \param[in]  argv     Commands to execute.
 * \param[out] output   Pointer to store the output of the executed command.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_do_run_tpm2_command(char* const argv[], char* output);

/** \brief This function generates quote for the tpm2 commands.
 *
 * \param[out] output   Pointer to store the quote.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_tpm2_generatequote(char* nonce);

#endif /* __OVSA_TPM_H_ */
#endif /* ENABLE_SGX_GRAMINE */
