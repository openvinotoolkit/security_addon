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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "runtime.h"
#include "tpm.h"
#include "utils.h"
/* json.h to be included at end due to dependencies */
#include "json.h"

extern ovsa_status_t ovsa_license_service_write(void* ssl, const char* buf, size_t len);
extern ovsa_status_t ovsa_do_tpm2_activatecredential(char* cred_outbuf);
extern ovsa_status_t ovsa_tpm2_generatequote(char* nonce);

static ovsa_status_t ovsa_do_read_runtime_quote(ovsa_quote_info_t* sw_quote_info) {
    ovsa_status_t ret       = OVSA_OK;
    char* pcr_list_buf      = NULL;
    char* pcr_quote_buf     = NULL;
    char* pcr_signature_buf = NULL;
    size_t file_size        = 0;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /* read pcr_list */
    ret = ovsa_read_file_content(TPM2_SWQUOTE_PCR, &pcr_list_buf, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error reading TPM2_SWQUOTE_PCR file failed with error code %d\n",
                 ret);
        goto out;
    }
    /* convert pcr bin to pem*/
    ret = ovsa_crypto_convert_bin_to_base64(pcr_list_buf, file_size - 1, &sw_quote_info->quote_pcr);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error crypto convert_bin_to_pem failed with code %d\n", ret);
        goto out;
    }
    /* read pcr quote */
    ret = ovsa_read_file_content(TPM2_SWQUOTE_MSG, &pcr_quote_buf, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error reading TPM2_SWQUOTE_PCR file failed with error code %d\n",
                 ret);
        goto out;
    }
    /* convert pcr_quote to pem*/
    ret = ovsa_crypto_convert_bin_to_base64(pcr_quote_buf, file_size - 1,
                                            &sw_quote_info->quote_message);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error crypto convert_bin_to_pem failed with code %d\n", ret);
        goto out;
    }
    /* read pcr signature */
    ret = ovsa_read_file_content(TPM2_SWQUOTE_SIG, &pcr_signature_buf, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error reading pcr signature file failed with error code %d\n", ret);
        goto out;
    }
    /* convert pcr_quote to pem*/
    ret = ovsa_crypto_convert_bin_to_base64(pcr_signature_buf, file_size - 1,
                                            &sw_quote_info->quote_sig);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error crypto convert_bin_to_pem failed with code %d\n", ret);
        goto out;
    }
    /*read Pub_key */
    ret = ovsa_read_file_content(TPM2_AK_PUB_PEM_KEY, &sw_quote_info->ak_pub_key, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error reading Pub_key file failed with error code %d\n", ret);
        goto out;
    }
out:
    ovsa_safe_free(&pcr_list_buf);
    ovsa_safe_free(&pcr_quote_buf);
    ovsa_safe_free(&pcr_signature_buf);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}
#ifdef ENABLE_QUOTE_FROM_NVRAM
static ovsa_status_t ovsa_extract_hw_quote(char* hw_quote_payload,
                                           ovsa_quote_info_t* hw_quote_info) {
    ovsa_status_t ret = OVSA_OK;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /* Read HW_quote_pcr from json file */
    ret = ovsa_json_extract_element(hw_quote_payload, "HW_Quote_PCR", &hw_quote_info->quote_pcr);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error read HW_Quote_PCR from json failed %d\n", ret);
        goto out;
    }
    /* Read HW_pub_key from json file */
    ret = ovsa_json_extract_element(hw_quote_payload, "HW_AK_Pub_Key", &hw_quote_info->ak_pub_key);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error read HW_AK_Pub_Key from json failed %d\n", ret);
        goto out;
    }
    /* Read HW_quote_msg from json file */
    ret =
        ovsa_json_extract_element(hw_quote_payload, "HW_Quote_MSG", &hw_quote_info->quote_message);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error read HW_Quote_MSG from json failed %d\n", ret);
        goto out;
    }
    /* Read HW_quote_sig from json file */
    ret = ovsa_json_extract_element(hw_quote_payload, "HW_Quote_SIG", &hw_quote_info->quote_sig);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error read HW_Quote_SIG from json failed %d\n", ret);
        goto out;
    }
    /* Read HW_ek_cert from json file */
    ret = ovsa_json_extract_element(hw_quote_payload, "HW_EK_Cert", &hw_quote_info->ek_cert);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error read HW_EK_Cert from json failed %d\n", ret);
        goto out;
    }
out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_tpm2_nvread(char* hw_quote_file, int nvindex, int size, int offset,
                               char* hwquote_buff) {
    OVSA_DBG(DBG_D, "OVSA: Entering %s\n", __func__);

    ovsa_status_t ret = OVSA_OK;
    char nvindex_buf[MAX_INDEX_LEN];
    char size_buf[MAX_INDEX_LEN];
    char offset_buf[MAX_INDEX_LEN];

    memset_s(nvindex_buf, sizeof(nvindex_buf), 0);
    memset_s(size_buf, sizeof(size_buf), 0);
    memset_s(offset_buf, sizeof(offset_buf), 0);

    snprintf(nvindex_buf, MAX_INDEX_LEN, "%d", nvindex);
    snprintf(size_buf, MAX_INDEX_LEN, "%d", size);
    snprintf(offset_buf, MAX_INDEX_LEN, "%d", offset);

    /* read hw quote info from NV memory */
    char* const nvread_cmd[] = {"/usr/bin/tpm2_nvread",
                                "-C",
                                "o",
                                "-s",
                                size_buf,
                                nvindex_buf,
                                "--offset",
                                offset_buf,
                                "-o",
                                hw_quote_file,
                                0};

    if (ovsa_do_run_tpm2_command(nvread_cmd, NULL) != 0) {
        OVSA_DBG(DBG_E, "OVSA: Error reading nv memory failed to execute %s command\n",
                 nvread_cmd[0]);
        return OVSA_TPM2_CMD_EXEC_FAIL;
    }
    /* Read hwquote info from diskfile */
    FILE* fptr_hwquote = fopen(hw_quote_file, "r");
    if (fptr_hwquote == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error opening hwquote length info file failed with code %d\n", ret);
        goto out;
    }
    ret = fread(hwquote_buff, 1, size, fptr_hwquote);
    fclose(fptr_hwquote);

out:
    OVSA_DBG(DBG_D, "OVSA: %s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_get_tpm2_base_host_quote(ovsa_quote_info_t* hw_quote_info) {
    OVSA_DBG(DBG_I, "OVSA: Entering %s\n", __func__);

    ovsa_status_t ret      = OVSA_OK;
    size_t size            = 0;
    size_t hwquote_bufsize = 0;
    char hwquote_len_buff[HW_QUOTE_SIZE_LENGTH + 1];
    char hwquote_buff_chunk[MAX_NV_INDEX_BUF_SIZE + 1];
    char* hwquote_buff  = NULL;
    int offset          = 0;
    int nv_index        = TPM2_NV_INDEX_START;
    int nv_index_toread = 0;
    int bytes_read      = 0;

    memset_s(hwquote_len_buff, sizeof(hwquote_len_buff), 0);

    /*Read length of hwquote blob from NV memory */
    ret = ovsa_tpm2_nvread(TPM2_NVM_HWQUOTE_LEN_FILE, TPM2_NV_INDEX_START, HW_QUOTE_SIZE_LENGTH,
                           offset, hwquote_len_buff);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error ovsa_tpm2_nvread failed with code %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_D, "OVSA:HW Quote Buf Len is %s\n", hwquote_len_buff);

    hwquote_bufsize = atoi(hwquote_len_buff);
    if ((hwquote_bufsize < OVSA_OK || hwquote_bufsize > UINT_MAX)) {
        ret = OVSA_INVALID_PARAMETER;
        OVSA_DBG(DBG_E, "OVSA: Error tpm2 nvread hwquote_bufsize size '%d'  invalid \n",
                 (int)hwquote_bufsize);
        goto out;
    }

    /*Allocate memory for hwquote buff*/
    hwquote_bufsize = hwquote_bufsize + 1;
    ret             = ovsa_safe_malloc(hwquote_bufsize + 1, &hwquote_buff);
    if (ret < OVSA_OK || hwquote_buff == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error hwquote buffer  allocation failed %d\n", ret);
        goto out;
    }

    if ((hwquote_bufsize % MAX_NV_INDEX_BUF_SIZE) == 0)
        nv_index_toread = TPM2_NV_INDEX_START + (hwquote_bufsize / MAX_NV_INDEX_BUF_SIZE) - 1;
    else
        nv_index_toread = TPM2_NV_INDEX_START + (hwquote_bufsize / MAX_NV_INDEX_BUF_SIZE);

    OVSA_DBG(DBG_D, "NV Index to Read is %d\n", nv_index_toread);

    char hwquote_file_name[MAX_FILE_NAME];
    char hwquote_file_index[MAX_FILE_NAME];

    memset_s(hwquote_file_name, sizeof(hwquote_file_name), 0);

    do {
        memset_s(hwquote_buff_chunk, sizeof(hwquote_buff_chunk), 0);
        memset_s(hwquote_file_index, sizeof(hwquote_file_index), 0);
        strcpy_s(hwquote_file_name, sizeof(hwquote_file_name), TPM2_NVM_HWQUOTE_BLOB_FILE);
        snprintf(hwquote_file_index, MAX_FILE_NAME, "file_%d", nv_index);
        strcat_s(hwquote_file_name, sizeof(hwquote_file_name), hwquote_file_index);

        OVSA_DBG(DBG_D, "HW Quote file name is %s\n", hwquote_file_name);

        if (nv_index == TPM2_NV_INDEX_START) {
            size   = (MAX_NV_INDEX_BUF_SIZE - HW_QUOTE_SIZE_LENGTH);
            offset = HW_QUOTE_SIZE_LENGTH;
        } else if (nv_index == nv_index_toread) {
            size   = ((hwquote_bufsize - 1) % MAX_NV_INDEX_BUF_SIZE) + HW_QUOTE_SIZE_LENGTH;
            offset = 0;
        } else {
            size   = MAX_NV_INDEX_BUF_SIZE;
            offset = 0;
        }

        ret = ovsa_tpm2_nvread(hwquote_file_name, nv_index, size, offset, hwquote_buff_chunk);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error ovsa_tpm2_nvread failed with code %d\n", ret);
            goto out;
        }
        remove(hwquote_file_name);
        memcpy_s((hwquote_buff + bytes_read), hwquote_bufsize, hwquote_buff_chunk, size);

        bytes_read += size;
        nv_index += 1;

    } while (nv_index <= nv_index_toread);

    OVSA_DBG(DBG_D, "OVSA:HW Quote Buf is %s\n", hwquote_buff);

    /* Update hw_quote_info */
    ret = ovsa_extract_hw_quote(hwquote_buff, hw_quote_info);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error update hw_quote info failed with code %d\n", ret);
        goto out;
    }

out:
    ovsa_safe_free(&hwquote_buff);
    OVSA_DBG(DBG_D, "LibOVSA: %s Exit\n", __func__);
    return ret;
}

#endif

static ovsa_status_t ovsa_extract_server_quote_nonce(char* payload, char** quote_nonce) {
    ovsa_status_t ret = OVSA_OK;
    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /* Read server nonce from json file */
    ret = ovsa_json_extract_element(payload, "quote_nonce", quote_nonce);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error read server nonce payload from json failed %d\n", ret);
        goto out;
    }
out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_read_ek_cert(ovsa_quote_info_t* sw_quote_info) {
    ovsa_status_t ret = OVSA_OK;
    size_t file_size  = 0;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    /* read ek_cert */
    ret = ovsa_read_file_content(TPM2_EK_CERT, &sw_quote_info->ek_cert, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error reading TPM2_EK_CERT file failed with error code %d\n", ret);
        goto out;
    }
out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_tpm2_generate_runtime_host_quote(char* quote_nonce,
                                                           ovsa_quote_info_t* quote_info
#ifdef ENABLE_QUOTE_FROM_NVRAM
                                                           ,
                                                           ovsa_quote_info_t* hw_quote_info
#endif

) {
    ovsa_status_t ret = OVSA_OK;
    size_t size = 0, nonce_bin_length = 0;
    char* nonce_bin_buff = NULL;
    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    ret = ovsa_get_string_length(quote_nonce, &size);
    ret = ovsa_safe_malloc((sizeof(char) * size), &nonce_bin_buff);
    if (ret < OVSA_OK || nonce_bin_buff == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error pcr quote buffer allocation failed %d\n", ret);
        goto out;
    }
    ret = ovsa_crypto_convert_base64_to_bin(quote_nonce, size, nonce_bin_buff, &nonce_bin_length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error crypto convert_base64_to_bin failed with code %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_D, "OVSA: nonce_bin_length %d\n", (int)nonce_bin_length);
    OVSA_DBG(DBG_D, "OVSA: quote_nonce %s\n", quote_nonce);
#ifdef ENABLE_QUOTE_FROM_NVRAM
    unsigned char swquote_hash_nonce[QUOTE_NONCE_HASH_SIZE];
    unsigned char hash[QUOTE_NONCE_HASH_SIZE];
    int i = 0;

    /* Generate HASH of hw quote details */

    /* 1. SHA-256 of HW Quote PCR */
    OVSA_DBG(DBG_I, "OVSA: Generate HASH of hw quote\n");
    memset_s(swquote_hash_nonce, sizeof(swquote_hash_nonce), 0);
    memset_s(hash, sizeof(hash), 0);
    ret = ovsa_crypto_compute_hash(hw_quote_info->quote_pcr, HASH_ALG_SHA256, hash,
                                   false /* FORMAT_BASE64 */);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error compute HW Quote PCR hash failed with code %d\n", ret);
        goto out;
    }

    OVSA_DBG(DBG_D, "hw_quote_info->quote_pcr: %s\n", hw_quote_info->quote_pcr);
    for (i = 0; i < QUOTE_NONCE_HASH_SIZE; i++) {
        OVSA_DBG(DBG_D, "hash[i=%d]=%02x\n", i, hash[i]);
        swquote_hash_nonce[i] |= hash[i];
        OVSA_DBG(DBG_D, "swquote_hash_nonce[i=%d]=%02x\n", i, swquote_hash_nonce[i]);
    }

    /* 2. SHA-256 of SW TPM cert */
    OVSA_DBG(DBG_I, "OVSA: Generate HASH of sw cert\n");
    memset_s(hash, sizeof(hash), 0);

    ret = ovsa_crypto_compute_hash(quote_info->ek_cert, HASH_ALG_SHA256, hash,
                                   false /* FORMAT_BASE64 */);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error compute SW TPM cert hash failed with code %d\n", ret);
        goto out;
    }

    OVSA_DBG(DBG_D, "quote_info->ek_cert: %s\n", quote_info->ek_cert);
    for (i = 0; i < QUOTE_NONCE_HASH_SIZE; i++) {
        OVSA_DBG(DBG_D, "hash[i=%d]=%02x\n", i, hash[i]);
        swquote_hash_nonce[i] |= hash[i];
        OVSA_DBG(DBG_D, "swquote_hash_nonce[i=%d]=%02x\n", i, swquote_hash_nonce[i]);
    }

    /* 3. SHA-256 of HW TPM Sig */
    OVSA_DBG(DBG_I, "OVSA: Generate HASH of Quote Sig..\n");
    memset_s(hash, sizeof(hash), 0);
    ret = ovsa_crypto_compute_hash(hw_quote_info->quote_sig, HASH_ALG_SHA256, hash,
                                   false /* FORMAT_BASE64 */);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error HW TPM Sig hash failed with code %d\n", ret);
        goto out;
    }

    OVSA_DBG(DBG_D, "hw_quote_info->quote_sig: %s\n", hw_quote_info->quote_sig);
    for (i = 0; i < QUOTE_NONCE_HASH_SIZE; i++) {
        OVSA_DBG(DBG_D, "hash[i=%d]=%02x\n", i, hash[i]);
        swquote_hash_nonce[i] |= hash[i];
        OVSA_DBG(DBG_D, "swquote_hash_nonce[i=%d]=%02x\n", i, swquote_hash_nonce[i]);
    }

    OVSA_DBG(DBG_I, "OVSA: Generate HASH of EK Cert ..\n");

    memset_s(hash, sizeof(hash), 0);

    /* 4. SHA-256 of HW ek_cert*/
    ret = ovsa_crypto_compute_hash(hw_quote_info->ek_cert, HASH_ALG_SHA256, hash,
                                   false /* FORMAT_BASE64 */);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error compute HW ek_cert hash failed with code %d\n", ret);
        goto out;
    }

    OVSA_DBG(DBG_D, "hw_quote_info->ek_cert: %s\n", hw_quote_info->ek_cert);
    for (i = 0; i < QUOTE_NONCE_HASH_SIZE; i++) {
        OVSA_DBG(DBG_D, "hash[i=%d]=%02x\n", i, hash[i]);
        swquote_hash_nonce[i] |= hash[i];
        OVSA_DBG(DBG_D, "swquote_hash_nonce[i=%d]=%02x\n", i, swquote_hash_nonce[i]);
    }

    OVSA_DBG(DBG_D, "Final HASH is\n");

    for (i = 0; i < QUOTE_NONCE_HASH_SIZE; i++) {
        swquote_hash_nonce[i] |= nonce_bin_buff[i];
        OVSA_DBG(DBG_D, "swquote_hash_nonce[i=%d]=%02x\n", i, swquote_hash_nonce[i]);
    }
#endif
    FILE* fquote_nonce = fopen(CHALLENGE_NONCE, "w");
    if (fquote_nonce == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error opening quote_nonce.bin !\n");
        ret = OVSA_FILEOPEN_FAIL;
        goto out;
    }
#ifdef ENABLE_QUOTE_FROM_NVRAM
    fwrite(swquote_hash_nonce, QUOTE_NONCE_HASH_SIZE, 1, fquote_nonce);
#else
    fwrite(nonce_bin_buff, nonce_bin_length, 1, fquote_nonce);
#endif
    fclose(fquote_nonce);

    /* Generate tpm2 quote*/
    ret = ovsa_tpm2_generatequote(CHALLENGE_NONCE);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error ovsa_tpm2_generatequote failed with code %d\n", ret);
        goto out;
    }
    /*Read SW quote info */
    ret = ovsa_do_read_runtime_quote(quote_info);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error read_SW_quote info failed with code %d\n", ret);
        goto out;
    }
out:
    ovsa_safe_free(&nonce_bin_buff);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_do_tpm2_activatecredential_quote_nonce(char* payload,
                                                                 char** actcred_buf) {
    ovsa_status_t ret         = OVSA_OK;
    char* cred_outbuf         = NULL;
    char* credout_bin         = NULL;
    size_t credout_bin_length = 0;
    size_t size               = 0;
    size_t file_size          = 0;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /* Read credout from json file */
    ret = ovsa_json_extract_element(payload, "cred_blob", &cred_outbuf);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error read credout payload from json failed %d\n", ret);
        goto out;
    }
    ret = ovsa_get_string_length(cred_outbuf, &size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of cred_outbuf payload string %d\n", ret);
        goto out;
    }
    ret = ovsa_safe_malloc((sizeof(char) * size), (char**)&credout_bin);
    if (ret < OVSA_OK || credout_bin == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error credout buffer allocation failed %d\n", ret);
        goto out;
    }
    ret = ovsa_crypto_convert_base64_to_bin(cred_outbuf, size, credout_bin, &credout_bin_length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error crypto convert_base64_to_bin failed with code %d\n", ret);
        goto out;
    }
    /* write credout bin to file  */
    FILE* fptr_credout = fopen(TPM2_CREDOUT_FILE, "wb");
    if (fptr_credout == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error opening file cred.out.bin failed with code %d\n", ret);
        goto out;
    }
    fwrite(credout_bin, credout_bin_length, 1, fptr_credout);
    fclose(fptr_credout);

    /* process tpm2_activatecredential*/
    ret = ovsa_do_tpm2_activatecredential(credout_bin);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error ovsa_do_tpm2_activatecredential failed %d\n", ret);
        goto out;
    }
    /* read decrypted secret */
    file_size = 0;
    ret       = ovsa_read_file_content(TPM2_ACTCRED_OUT, actcred_buf, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error reading TPM2_ACTCRED_OUT file failed with error code %d\n",
                 ret);
        goto out;
    }

out:
    ovsa_safe_free(&credout_bin);
    ovsa_safe_free(&cred_outbuf);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_do_get_quote_nounce(const int asym_keyslot, char* quote_credout_blob,
                                       char* cust_lic_sig_buf, void** _ssl_session) {
    ovsa_status_t ret           = OVSA_OK;
    void* ssl_session           = NULL;
    size_t length               = 0;
    size_t quote_payload_len    = 0;
    unsigned char* json_payload = NULL;
    char* payload               = NULL;
    char* quote_blob            = NULL;
    char* quote_buf             = NULL;
    char* actcred_buf           = NULL;
    char* quote_nonce           = NULL;
    size_t buf_len              = 0;
    ovsa_quote_info_t hw_quote_info;
    ovsa_quote_info_t quote_info;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    ssl_session = *_ssl_session;
    memset_s(&quote_info, sizeof(ovsa_quote_info_t), 0);
    memset_s(&hw_quote_info, sizeof(ovsa_quote_info_t), 0);

    /* Read quote_credout_blob payload from json file*/
    ret = ovsa_json_extract_element((char*)quote_credout_blob, "payload", &payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error read quote_credout_blob payload from json failed %d\n", ret);
        goto out;
    }
    ret = ovsa_do_tpm2_activatecredential_quote_nonce(payload, &actcred_buf);
    if (ret < OVSA_OK) {
        OVSA_DBG(
            DBG_E,
            "OVSA: Error ovsa_do_tpm2_activatecredential_quote_nonce failed with error code %d\n",
            ret);
        goto out;
    }
    ret = ovsa_extract_server_quote_nonce(payload, &quote_nonce);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error extract server quote nonce failed with error code %d\n", ret);
        goto out;
    }

#ifdef ENABLE_QUOTE_FROM_NVRAM
    /* Read hw quote from NV memory  */
    ret = ovsa_get_tpm2_base_host_quote(&hw_quote_info);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E,
                 "OVSA: Error get Hw quote measurements from NV memory failed with error code %d\n",
                 ret);
        goto out;
    }
#endif
#ifndef KVM
    quote_info = hw_quote_info;
#endif
    /*Read ek_cert*/
    ret = ovsa_read_ek_cert(&quote_info);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error read_ek_cert failed with code %d\n", ret);
        goto out;
    }

    ret = ovsa_tpm2_generate_runtime_host_quote(quote_nonce, &quote_info
#ifdef ENABLE_QUOTE_FROM_NVRAM
                                                ,
                                                &hw_quote_info
#endif
    );
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error get SW quote measurements failed with error code %d\n", ret);
        goto out;
    }
    ret = ovsa_json_create_quote_info_blob(actcred_buf, quote_info, hw_quote_info, &quote_blob,
                                           &length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error create quote update info blob failed with error code %d\n",
                 ret);
        goto out;
    }
    /* create json message blob */
    ret = ovsa_json_create_message_blob(OVSA_SEND_QUOTE_INFO, quote_blob, &quote_buf, &length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error create SW quote message failed with error code %d\n", ret);
        goto out;
    }
    /* Append payload length to json blob*/
    quote_payload_len = length + PAYLOAD_LENGTH + 1;
    ret               = ovsa_safe_malloc(sizeof(char) * quote_payload_len, (char**)&json_payload);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error create json blob memory init failed\n");
        goto out;
    }

    ret = ovsa_append_json_payload_len_to_blob(quote_buf, (char**)&json_payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error quote_buf json blob creation failed with %d\n", ret);
        goto out;
    }
    ret = ovsa_get_string_length((char*)json_payload, &buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of json_payload string %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA:Send quote to server\n%s", json_payload);
    /* Send pcr quote to Server */
    ret = ovsa_license_service_write(ssl_session, (char*)json_payload, buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error ovsa_license_service_write() returned %d\n", ret);
        goto out;
    }
out:
    ovsa_safe_free(&quote_buf);
    ovsa_safe_free(&payload);
    ovsa_safe_free(&quote_info.quote_pcr);
    ovsa_safe_free(&quote_info.quote_message);
    ovsa_safe_free(&quote_info.quote_sig);
    ovsa_safe_free(&quote_info.ak_pub_key);
    ovsa_safe_free(&quote_info.ek_cert);
#ifdef ENABLE_QUOTE_FROM_NVRAM
    ovsa_safe_free(&hw_quote_info.quote_pcr);
    ovsa_safe_free(&hw_quote_info.quote_message);
    ovsa_safe_free(&hw_quote_info.quote_sig);
    ovsa_safe_free(&hw_quote_info.ak_pub_key);
    ovsa_safe_free(&hw_quote_info.ek_pub_key);
    ovsa_safe_free(&hw_quote_info.ek_cert);
#endif
    ovsa_safe_free(&quote_blob);
    ovsa_safe_free((char**)&json_payload);
    ovsa_safe_free(&actcred_buf);
    ovsa_safe_free(&quote_nonce);

    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

#ifdef PTT_EK_ONDIE_CA
static ovsa_status_t ovsa_do_read_EK_cert_chain_file(ovsa_ek_ak_bind_info_t* ek_ak_bind_info) {
    ovsa_status_t ret = OVSA_OK;
    size_t file_size  = 0;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    /*
     * Check if EK_cert_chain ROM Certificate exists. If so, read and send it to server
     */
    if (ovsa_check_if_file_exists(TPM2_EKCERT_CHAIN_ROM_CERT) == true) {
        OVSA_DBG(DBG_D, "OVSA:TPM2_SW_EK_Chain ROM certificate file exists \n");
        /* Read ROM cert */
        ret = ovsa_read_file_content(TPM2_EKCERT_CHAIN_ROM_CERT, &ek_ak_bind_info->ROM_cert,
                                     &file_size);
        if (ret < OVSA_OK) {
            OVSA_DBG(
                DBG_E,
                "OVSA: Error reading TPM2_SW_EK_Chain ROM certificate failed with error code %d\n",
                ret);
            goto out;
        }
        OVSA_DBG(DBG_I, "OVSA:EKcert Chain ROM_cert read...!:%s\n", ek_ak_bind_info->ROM_cert);
    } else {
        OVSA_DBG(DBG_E, "OVSA: Error TPM2_SW_EK_Chain ROM certificate doesn't exists\n");
        ret = OVSA_INVALID_PARAMETER;
        goto out;
    }
    /*
     * Check if EKcert on_diechain_certificate exists. If so, read and send it to server
     */
    if (ovsa_check_if_file_exists(TPM2_EKCERT_ONDIE_CHAIN) == true) {
        OVSA_DBG(DBG_D, "OVSA:TPM2_SW_EKcert on_diechain_certificate file exists \n");
        /* Read ROM cert */
        ret = ovsa_read_file_content(TPM2_EKCERT_ONDIE_CHAIN, &ek_ak_bind_info->Chain_cert,
                                     &file_size);
        if (ret < OVSA_OK) {
            OVSA_DBG(
                DBG_E,
                "OVSA: Error reading EKcert on_diechain_certificate failed with error code %d\n",
                ret);
            goto out;
        }
        OVSA_DBG(DBG_I, "OVSA:EKcert on_diechain_certificate read...!:%s\n",
                 ek_ak_bind_info->Chain_cert);
    } else {
        OVSA_DBG(DBG_E, "OVSA: Error TTPM2_SW_EKcert on_diechain_certificate:%s doesn't exists\n",
                 TPM2_EKCERT_ONDIE_CHAIN);
        ret = OVSA_INVALID_PARAMETER;
        goto out;
    }

out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}
#endif

static ovsa_status_t ovsa_do_sign_EKpub_EKcert(const int asym_keyslot,
                                               ovsa_ek_ak_bind_info_t* ek_ak_bind_info) {
    ovsa_status_t ret = OVSA_OK;
    size_t file_size  = 0;
    char* ekpub_buf   = NULL;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /*
     * Check if EK Certificate exists. If so, read and send it to server
     */
    if (ovsa_check_if_file_exists(TPM2_EK_CERT) == true) {
        OVSA_DBG(DBG_D, "OVSA:TPM2_SW_EK certificate file exists \n");
        /* Read EK cert */
        ret = ovsa_read_file_content(TPM2_EK_CERT, &ek_ak_bind_info->ek_cert, &file_size);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E,
                     "OVSA: Error reading TPM2_SW_EK Certificate failed with error code %d\n", ret);
            goto out;
        }
        ret = ovsa_safe_malloc(sizeof(char) * MAX_SIGNATURE_SIZE, &ek_ak_bind_info->ek_cert_sig);
        if (ret < OVSA_OK) {
            ret = OVSA_MEMORY_ALLOC_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Error create ek_ak_bind_info memory init failed\n");
            goto out;
        }
        if ((!file_size) || (file_size > MAX_CERT_SIZE)) {
            OVSA_DBG(DBG_E, "OVSA: Error sw_ek_cert length is invalid \n");
            ret = OVSA_INVALID_PARAMETER;
            goto out;
        }
        /* Sign Ekcert */
        ret = ovsa_crypto_sign_mem(asym_keyslot, ek_ak_bind_info->ek_cert, file_size - 1,
                                   ek_ak_bind_info->ek_cert_sig);
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error EKCert Signing failed with code %d\n", ret);
            goto out;
        }
        OVSA_DBG(DBG_I, "OVSA:EKcertificate signed...!\n");
    } else {
        OVSA_DBG(DBG_E, "OVSA: Error SW_EK_certificate doesn't exists\n");
        ret = OVSA_INVALID_PARAMETER;
        goto out;
    }

out:
    ovsa_safe_free(&ekpub_buf);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_do_read_AK_pubkey_AKname(ovsa_ek_ak_bind_info_t* ek_ak_bind_info) {
    ovsa_status_t ret = OVSA_OK;
    size_t file_size  = 0;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /* Read AKpub pem */
    ret = ovsa_read_file_content(TPM2_AK_PUB_PEM_KEY, &ek_ak_bind_info->ak_pub_key, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error reading TPM2_AK_PUB_PEM_KEY file failed with error code %d\n",
                 ret);
        goto out;
    }
    /* Read AKname */
    file_size = 0;
    ret       = ovsa_read_file_content(TPM2_AK_NAME_HEX, &ek_ak_bind_info->ak_name, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error reading TPM2_AK_NAME_HEX file failed with error code %d\n",
                 ret);
        goto out;
    }
out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_send_EK_AK_bind_info(const int asym_keyslot, void** _ssl_session) {
    ovsa_status_t ret          = OVSA_OK;
    void* ssl_session          = NULL;
    char* EK_AK_bind_info_json = NULL;
    size_t length              = 0;
    char* json_buf             = NULL;
    char* json_payload         = NULL;
    size_t payload_len         = 0;
    size_t buf_len             = 0;
    ovsa_ek_ak_bind_info_t ek_ak_bind_info;

    ssl_session = *_ssl_session;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    memset_s(&ek_ak_bind_info, sizeof(ovsa_ek_ak_bind_info_t), 0);

    /* Read and sign EKpub/EKcert */
    ret = ovsa_do_sign_EKpub_EKcert(asym_keyslot, &ek_ak_bind_info);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error sign EK_pub using platform priv key failed with code %d\n",
                 ret);
        goto out;
    }
    /* Read AKpub and AKname */
    ret = ovsa_do_read_AK_pubkey_AKname(&ek_ak_bind_info);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error read_AK_pubkey_AKname failed with code %d\n", ret);
        goto out;
    }
    /* Get customer certificate from key slot */
    ret = ovsa_crypto_get_certificate(asym_keyslot, &ek_ak_bind_info.platform_cert);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error get customer certificate failed with code %d\n", ret);
        goto out;
    }

#ifdef PTT_EK_ONDIE_CA
    /* ROM_cert and chain file */
    ret = ovsa_do_read_EK_cert_chain_file(&ek_ak_bind_info);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error Read_EK_cert_chain_file failed with code %d\n", ret);
        goto out;
    }
#endif

    ret = ovsa_json_create_EK_AK_binding_info_blob(ek_ak_bind_info, &EK_AK_bind_info_json, &length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E,
                 "OVSA: Error create EK_AK_binding_info info blob failed with error code %d\n",
                 ret);
        goto out;
    }
    /* create json message blob */
    ret = ovsa_json_create_message_blob(OVSA_SEND_EK_AK_BIND_INFO, EK_AK_bind_info_json, &json_buf,
                                        &length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error create EK_AK_BIND_INFO message failed with error code %d\n",
                 ret);
        goto out;
    }
    /* Append payload length to json blob */
    payload_len = length + PAYLOAD_LENGTH + 1;
    ret         = ovsa_safe_malloc(sizeof(char) * payload_len, (char**)&json_payload);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error create json blob memory init failed\n");
        goto out;
    }
    ret = ovsa_append_json_payload_len_to_blob(json_buf, (char**)&json_payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error json blob creation failed with %d\n", ret);
        goto out;
    }
    ret = ovsa_get_string_length((char*)json_payload, &buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of json_payload string %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA:Send EK_AK_BIND_INFO to server\n%s", json_payload);
    /* Send EK_AK_BIND_INFO to Server */
    ret = ovsa_license_service_write(ssl_session, (char*)json_payload, buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error ovsa_license_service_write() returned %d\n", ret);
        goto out;
    }
out:
    ovsa_safe_free(&ek_ak_bind_info.ak_pub_key);
    ovsa_safe_free(&ek_ak_bind_info.ak_name);
    ovsa_safe_free(&ek_ak_bind_info.ek_pub_key);
    ovsa_safe_free(&ek_ak_bind_info.ek_pub_sig);
    ovsa_safe_free(&ek_ak_bind_info.ek_cert);
    ovsa_safe_free(&ek_ak_bind_info.ek_cert_sig);
    ovsa_safe_free(&ek_ak_bind_info.platform_cert);
#ifdef PTT_EK_ONDIE_CA
    ovsa_safe_free(&ek_ak_bind_info.ROM_cert);
    ovsa_safe_free(&ek_ak_bind_info.Chain_cert);
#endif
    ovsa_safe_free(&json_buf);
    ovsa_safe_free(&json_payload);
    ovsa_safe_free(&EK_AK_bind_info_json);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

void ovsa_remove_quote_files(void) {
    remove(TPM2_SWQUOTE_PCR);
    remove(TPM2_SWQUOTE_MSG);
    remove(TPM2_SWQUOTE_SIG);
    remove(CHALLENGE_NONCE);
    remove(TPM2_CREDOUT_FILE);
    remove(TPM2_ACTCRED_OUT);
    remove(TPM2_NVM_HWQUOTE_LEN_FILE);

    OVSA_DBG(DBG_D, "OVSA:Removed the Quote files from /opt/ovsa/tmp_dir directory\n");
}

ovsa_status_t ovsa_get_pcr_exclusion_set(char* optarg, int* pcr_id_set) {
    ovsa_status_t ret = OVSA_OK;
    static char pcr_id[TPM2_MAX_PCRS];
    char* pcr_id_endptr = NULL;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    memset_s(pcr_id, sizeof(pcr_id), 0);
    strcpy_s(pcr_id, sizeof(pcr_id), optarg);

    *pcr_id_set = (int)strtol(pcr_id, &pcr_id_endptr, 16);
    if (*pcr_id_endptr != '\0') {
        OVSA_DBG(DBG_I, "OVSA:WARNING: pcr_id='%s' is not valid hex value \n", pcr_id);
        OVSA_DBG(DBG_I, "OVSA:Validate PCR_ID_SET is set to default value 0xFFFFFF\n");
        *pcr_id_set = (int)strtol(DEFAULT_PCR_ID_SET, NULL, 16);
    }
    if (!((*pcr_id_set > 0) && (*pcr_id_set <= 0xffffff))) {
        OVSA_DBG(DBG_I,
                 "OVSA: WARNING: pcr_id=%s is not valid [valid range=0x1:0xffffff] "
                 "\nValidate PCR_ID_SET is set to default value 0xFFFFFF\n",
                 pcr_id);
        *pcr_id_set = (int)strtol(DEFAULT_PCR_ID_SET, NULL, 16);
    }

    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_do_read_quote_pubkey(ovsa_quote_info_t* sw_quote_info) {
    ovsa_status_t ret = OVSA_OK;
    size_t file_size  = 0;
    char* pcr_buf     = NULL;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /* read pcr */
    ret = ovsa_read_file_content(TPM2_SWQUOTE_PCR, &pcr_buf, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error reading TPM2_SWQUOTE_PCR file failed with error code %d\n",
                 ret);
        goto out;
    }
    /* convert pcr bin to pem*/
    ret = ovsa_crypto_convert_bin_to_base64(pcr_buf, file_size - 1, &sw_quote_info->quote_pcr);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error crypto convert_bin_to_pem failed with code %d\n", ret);
        goto out;
    }
    /*read public key */
    ret = ovsa_read_file_content(TPM2_AK_PUB_PEM_KEY, &sw_quote_info->ak_pub_key, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error reading TPM2_AK_PUB_PEM_KEY file failed with error code %d\n",
                 ret);
        goto out;
    }
out:
    ovsa_safe_free(&pcr_buf);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_get_tpm2_host_quote(ovsa_quote_info_t* sw_quote_info) {
    ovsa_status_t ret         = OVSA_OK;
    char nonce[MAX_NAME_SIZE] = {'\0'};

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    /* Generate tpm2 quote */
    ret = ovsa_tpm2_generatequote(nonce);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error ovsa_tpm2_generatequote failed with code %d\n", ret);
        goto out;
    }
    ret = ovsa_do_read_quote_pubkey(sw_quote_info);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error read_SW_quote failed with code %d\n", ret);
        goto out;
    }
out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_generate_reference_tcb(ovsa_tcb_info_t* tcb_info, int sw_pcr_reg_id,
                                          int hw_pcr_reg_id) {
    ovsa_status_t ret          = OVSA_OK;
    size_t quote_pcr_file_size = 0;
    size_t pub_key_file_size   = 0;
    ovsa_quote_info_t hw_quote_info;
    ovsa_quote_info_t quote_info;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    memset_s(&quote_info, sizeof(ovsa_quote_info_t), 0);
    memset_s(&hw_quote_info, sizeof(ovsa_quote_info_t), 0);

    ret = ovsa_get_tpm2_host_quote(&quote_info);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error : Get tpm2 SW quote failed with code %d\n", ret);
        goto out;
    }
    ret = ovsa_get_string_length(quote_info.quote_pcr, &quote_pcr_file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of sw_quote_pcr string %d\n", ret);
        goto out;
    }

    ret = ovsa_get_string_length(quote_info.ak_pub_key, &pub_key_file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of sw_pub_key string %d\n", ret);
        goto out;
    }
#if !defined KVM || defined ENABLE_QUOTE_FROM_NVRAM
    static char hw_pcr_id[TPM2_MAX_PCRS];
#endif
#ifdef KVM
    static char sw_pcr_id[TPM2_MAX_PCRS];
    memcpy_s(tcb_info->sw_quote, TPM2_QUOTE_SIZE, quote_info.quote_pcr, quote_pcr_file_size);
    memcpy_s(tcb_info->sw_pub_key, TPM2_PUBKEY_SIZE, quote_info.ak_pub_key, pub_key_file_size);
    memset_s(sw_pcr_id, sizeof(sw_pcr_id), 0);
    snprintf(sw_pcr_id, TPM2_MAX_PCRS, "0x%02X", sw_pcr_reg_id);
    memcpy_s(tcb_info->sw_pcr_reg_id, TPM2_MAX_PCRS, sw_pcr_id, TPM2_MAX_PCRS);
#endif

#if !defined KVM && !defined ENABLE_QUOTE_FROM_NVRAM
    memcpy_s(tcb_info->hw_quote, TPM2_QUOTE_SIZE, quote_info.quote_pcr, quote_pcr_file_size);
    memcpy_s(tcb_info->hw_pub_key, TPM2_PUBKEY_SIZE, quote_info.ak_pub_key, pub_key_file_size);
    memset_s(hw_pcr_id, sizeof(hw_pcr_id), 0);
    snprintf(hw_pcr_id, TPM2_MAX_PCRS, "0x%02X", hw_pcr_reg_id);
    memcpy_s(tcb_info->hw_pcr_reg_id, TPM2_MAX_PCRS, hw_pcr_id, TPM2_MAX_PCRS);
#endif

#ifdef ENABLE_QUOTE_FROM_NVRAM
    size_t file_size = 0;
    /* Read hw quote from NV memory  */
    ret = ovsa_get_tpm2_base_host_quote(&hw_quote_info);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error read hw quote from NV memory failed with code %d\n", ret);
        goto out;
    }
    ret = ovsa_get_string_length(hw_quote_info.quote_pcr, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of HW_quote_pcr string %d\n", ret);
        goto out;
    }
    memcpy_s(tcb_info->hw_quote, TPM2_QUOTE_SIZE, hw_quote_info.quote_pcr, file_size);

    ret = ovsa_get_string_length(hw_quote_info.ak_pub_key, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of HW_ak_pub_key string %d\n", ret);
        goto out;
    }
    memcpy_s(tcb_info->hw_pub_key, TPM2_PUBKEY_SIZE, hw_quote_info.ak_pub_key, file_size);
    memset_s(hw_pcr_id, sizeof(hw_pcr_id), 0);
    snprintf(hw_pcr_id, TPM2_MAX_PCRS, "0x%02X", hw_pcr_reg_id);
    memcpy_s(tcb_info->hw_pcr_reg_id, TPM2_MAX_PCRS, hw_pcr_id, TPM2_MAX_PCRS);
    OVSA_DBG(DBG_D, "OVSA: hw_pcr_reg_id = 0x%s\n", hw_pcr_id);
#endif

out:
    ovsa_safe_free(&quote_info.quote_pcr);
    ovsa_safe_free(&quote_info.ak_pub_key);
#ifdef ENABLE_QUOTE_FROM_NVRAM
    ovsa_safe_free(&hw_quote_info.quote_pcr);
    ovsa_safe_free(&hw_quote_info.ak_pub_key);
    ovsa_safe_free(&hw_quote_info.quote_message);
    ovsa_safe_free(&hw_quote_info.quote_sig);
    ovsa_safe_free(&hw_quote_info.ek_cert);
#endif
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}
