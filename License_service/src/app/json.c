/*
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
 *
 */

#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "license_service.h"
#include "safe_mem_lib.h"
#include "safe_str_lib.h"
#include "snprintf_s.h"
#include "utils.h"

ovsa_license_type_t ovsa_license_service_json_map_license_type(const char* lictype) {
    static const char* license_type[] = {"Sale", "InstanceLimit", "TimeLimit"};

    if (!(strcmp(lictype, license_type[SALE]))) {
        OVSA_DBG(DBG_D, "OVSA:SALE\n");
        return SALE;
    } else if (!(strcmp(lictype, license_type[INSTANCELIMIT]))) {
        OVSA_DBG(DBG_D, "OVSA:INSTANCELIMIT\n");
        return INSTANCELIMIT;
    } else if (!(strcmp(lictype, license_type[TIMELIMIT]))) {
        OVSA_DBG(DBG_D, "OVSA:TIMELIMIT\n");
        return TIMELIMIT;
    } else {
        OVSA_DBG(DBG_E, "OVSA: Error invalid option for license type\n");
        return MAXLICENSETYPE;
    }
}

ovsa_status_t ovsa_license_service_json_extract_customer_license(
    const char* inputBuf, ovsa_customer_license_sig_t* cust_lic_sig) {
    ovsa_status_t ret      = OVSA_OK;
    cJSON* creation_date   = NULL;
    cJSON* isv_certificate = NULL;
    cJSON* model_hash      = NULL;
    cJSON* signature       = NULL;
    cJSON* name            = NULL;
    cJSON* version         = NULL;
    cJSON* license_guid    = NULL;
    cJSON* model_guid      = NULL;
    cJSON* encryption_key  = NULL;
    cJSON* license_type    = NULL;
    cJSON* usage_count     = NULL;
    cJSON* time_limit      = NULL;
    cJSON* parse_json      = NULL;
    int i                  = 0;
    char fname[MAX_FILE_NAME_LEN];
    ovsa_license_serv_url_list_t* head = NULL;
    ovsa_license_serv_url_list_t* cur  = NULL;
    ovsa_license_serv_url_list_t* tail = NULL;
    ovsa_tcb_sig_list_t* tcb_head      = NULL;
    ovsa_tcb_sig_list_t* tcb_cur       = NULL;
    ovsa_tcb_sig_list_t* tcb_tail      = NULL;
    char* tcb_tail_signature           = NULL;

    OVSA_DBG(DBG_D, "\nOVSA:%s entry\n", __func__);

    if (inputBuf == NULL || cust_lic_sig == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error input is null %d\n", ret);
        ret = OVSA_JSON_INVALID_INPUT;
        goto end;
    }
    memset_s(fname, sizeof(fname), 0);
    parse_json = cJSON_Parse(inputBuf);
    if (parse_json == NULL) {
        ret = OVSA_JSON_PARSE_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error could not parse %d\n", ret);
        goto end;
    }

    creation_date = cJSON_GetObjectItemCaseSensitive(parse_json, "creation_date");
    if (cJSON_IsString(creation_date) && (creation_date->valuestring != NULL)) {
        memcpy_s(cust_lic_sig->customer_lic.creation_date, MAX_NAME_SIZE,
                 creation_date->valuestring, strnlen_s(creation_date->valuestring, MAX_NAME_SIZE));
        OVSA_DBG(DBG_D, "OVSA:creation_date %s\n", creation_date->valuestring);
    }

    isv_certificate = cJSON_GetObjectItemCaseSensitive(parse_json, "isv_certificate");
    if (cJSON_IsString(isv_certificate) && (isv_certificate->valuestring != NULL)) {
        size_t str_len = 0;
        ret = ovsa_license_service_get_string_length(isv_certificate->valuestring, &str_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error could not get length of isv_certificate string %d\n", ret);
            goto end;
        }
        /* Memory allocated and this needs to be freed by consumer */
        ret = ovsa_license_service_safe_malloc(str_len + 1,
                                               &cust_lic_sig->customer_lic.isv_certificate);
        if (ret < OVSA_OK || cust_lic_sig->customer_lic.isv_certificate == NULL) {
            OVSA_DBG(DBG_E, "OVSA: Error could not allocate memory %d\n", ret);
            goto end;
        }
        memcpy_s(cust_lic_sig->customer_lic.isv_certificate, str_len, isv_certificate->valuestring,
                 str_len);
        cust_lic_sig->customer_lic.isv_certificate[str_len] = '\0';
        OVSA_DBG(DBG_D, "isv_certificate %s\n", isv_certificate->valuestring);
    }

    model_hash = cJSON_GetObjectItemCaseSensitive(parse_json, "model_hash");
    if (cJSON_IsString(model_hash) && (model_hash->valuestring != NULL)) {
        memcpy_s(cust_lic_sig->customer_lic.model_hash, HASH_B64_SIZE, model_hash->valuestring,
                 strnlen_s(model_hash->valuestring, HASH_B64_SIZE));
        OVSA_DBG(DBG_D, "OVSA:model_hash %s\n", model_hash->valuestring);
    }

    signature = cJSON_GetObjectItemCaseSensitive(parse_json, "signature");
    if (cJSON_IsString(signature) && (signature->valuestring != NULL)) {
        memcpy_s(cust_lic_sig->signature, MAX_SIGNATURE_SIZE, signature->valuestring,
                 strnlen_s(signature->valuestring, MAX_SIGNATURE_SIZE));
        OVSA_DBG(DBG_D, "OVSA:signature %s\n", cust_lic_sig->signature);
    }

    name = cJSON_GetObjectItemCaseSensitive(parse_json, "license_name");
    if (cJSON_IsString(name) && (name->valuestring != NULL)) {
        memcpy_s(cust_lic_sig->customer_lic.license_name, MAX_NAME_SIZE, name->valuestring,
                 strnlen_s(name->valuestring, MAX_NAME_SIZE));
        OVSA_DBG(DBG_D, "OVSA:name %s\n", name->valuestring);
    }

    version = cJSON_GetObjectItemCaseSensitive(parse_json, "license_version");
    if (cJSON_IsString(version) && (version->valuestring != NULL)) {
        memcpy_s(cust_lic_sig->customer_lic.license_version, MAX_VERSION_SIZE, version->valuestring,
                 strnlen_s(version->valuestring, MAX_VERSION_SIZE));
        OVSA_DBG(DBG_D, "OVSA:version %s\n", version->valuestring);
    }

    license_guid = cJSON_GetObjectItemCaseSensitive(parse_json, "license_guid");
    if (cJSON_IsString(license_guid) && (license_guid->valuestring != NULL)) {
        memcpy_s(cust_lic_sig->customer_lic.license_guid, GUID_SIZE, license_guid->valuestring,
                 strnlen_s(license_guid->valuestring, GUID_SIZE));
        OVSA_DBG(DBG_D, "OVSA:license_guid %s\n", license_guid->valuestring);
    }

    model_guid = cJSON_GetObjectItemCaseSensitive(parse_json, "model_guid");
    if (cJSON_IsString(model_guid) && (model_guid->valuestring != NULL)) {
        memcpy_s(cust_lic_sig->customer_lic.model_guid, GUID_SIZE, model_guid->valuestring,
                 strnlen_s(model_guid->valuestring, GUID_SIZE));
        OVSA_DBG(DBG_D, "OVSA:model_guid %s\n", model_guid->valuestring);
    }

    encryption_key = cJSON_GetObjectItemCaseSensitive(parse_json, "encryption_key");
    if (cJSON_IsString(encryption_key) && (encryption_key->valuestring != NULL)) {
        memcpy_s(cust_lic_sig->customer_lic.encryption_key, MAX_EKEY_SIZE,
                 encryption_key->valuestring,
                 strnlen_s(encryption_key->valuestring, MAX_EKEY_SIZE));
    }

    cJSON* svrurl = cJSON_GetObjectItemCaseSensitive(parse_json, "license_serv_url");
    if (svrurl) {
        cJSON* device = svrurl->child;
        i             = 0;
        while (device) {
            snprintf_s_i(fname, MAX_FILE_NAME_LEN, "url_%d", (i++) % 100u);
            cJSON* url_struct = cJSON_GetObjectItemCaseSensitive(svrurl, fname);
            if (head == NULL) {
                /* Memory allocated and this needs to be freed by consumer */
                ret = ovsa_license_service_safe_malloc(sizeof(ovsa_license_serv_url_list_t),
                                                       (char**)&head);
                if (ret < OVSA_OK || head == NULL) {
                    OVSA_DBG(DBG_E, "OVSA: Error could not allocate memory %d\n", ret);
                    goto end;
                }
                head->next = NULL;
                tail       = head;
            } else {
                /* Memory allocated and this needs to be freed by consumer */
                ret = ovsa_license_service_safe_malloc(sizeof(ovsa_license_serv_url_list_t),
                                                       (char**)&cur);
                if (ret < OVSA_OK || cur == NULL) {
                    OVSA_DBG(DBG_E, "OVSA: Error could not allocate memory %d\n", ret);
                    goto end;
                }
                cur->next  = NULL;
                tail->next = cur;
                tail       = cur;
            }
            cJSON* url = cJSON_GetObjectItemCaseSensitive(url_struct, "url");
            if (cJSON_IsString(url) && (url->valuestring != NULL)) {
                memset_s(tail->license_serv_url, MAX_URL_SIZE, 0);
                memcpy_s(tail->license_serv_url, MAX_URL_SIZE, url->valuestring,
                         strnlen_s(url->valuestring, MAX_URL_SIZE));
                OVSA_DBG(DBG_D, "OVSA:%s\n", fname);
            }
            cJSON* cur_cert_hash = cJSON_GetObjectItemCaseSensitive(url_struct, "cur_cert_hash");
            if (cJSON_IsString(cur_cert_hash) && (cur_cert_hash->valuestring != NULL)) {
                memset_s(tail->cur_cert_hash, HASH_SIZE, 0);
                memcpy_s(tail->cur_cert_hash, HASH_SIZE, cur_cert_hash->valuestring,
                         strnlen_s(cur_cert_hash->valuestring, HASH_SIZE));
            }
            cJSON* fut_cert_hash = cJSON_GetObjectItemCaseSensitive(url_struct, "fut_cert_hash");
            if (cJSON_IsString(fut_cert_hash) && (fut_cert_hash->valuestring != NULL)) {
                memset_s(tail->fut_cert_hash, HASH_SIZE, 0);
                memcpy_s(tail->fut_cert_hash, HASH_SIZE, fut_cert_hash->valuestring,
                         strnlen_s(fut_cert_hash->valuestring, HASH_SIZE));
            }
            device = device->next;
        }
    }
    cust_lic_sig->customer_lic.license_url_list = head;

    license_type = cJSON_GetObjectItemCaseSensitive(parse_json, "license_type");
    if (cJSON_IsString(license_type) && (license_type->valuestring != NULL)) {
        cust_lic_sig->customer_lic.license_type =
            ovsa_license_service_json_map_license_type(license_type->valuestring);
        OVSA_DBG(DBG_D, "OVSA:license_type %s\n", license_type->valuestring);
    }

    usage_count = cJSON_GetObjectItemCaseSensitive(parse_json, "usage_count");
    if (cJSON_IsNumber(usage_count)) {
        cust_lic_sig->customer_lic.usage_count = usage_count->valueint;
        OVSA_DBG(DBG_D, "OVSA:usage_count %d\n", usage_count->valueint);
    }

    time_limit = cJSON_GetObjectItemCaseSensitive(parse_json, "time_limit");
    if (cJSON_IsNumber(time_limit)) {
        cust_lic_sig->customer_lic.time_limit = time_limit->valueint;
        OVSA_DBG(DBG_D, "OVSA:time_limit %d\n", time_limit->valueint);
    }
    cJSON* tcb_sig = cJSON_GetObjectItemCaseSensitive(parse_json, "tcb_signature");
    if (tcb_sig) {
        cJSON* device = tcb_sig->child;
        i             = 0;
        while (device) {
            snprintf_s_i(fname, MAX_FILE_NAME_LEN, "sig_%d", (i++) % 100u);
            cJSON* sig = cJSON_GetObjectItemCaseSensitive(tcb_sig, fname);
            if (tcb_head == NULL) {
                /* Memory allocated and this needs to be freed by consumer */
                ret = ovsa_license_service_safe_malloc(sizeof(ovsa_tcb_sig_list_t),
                                                       (char**)&tcb_head);
                if (ret < OVSA_OK || tcb_head == NULL) {
                    OVSA_DBG(DBG_E, "OVSA: Error could not allocate memory %d\n", ret);
                    goto end;
                }
                tcb_head->next = NULL;
                tcb_tail       = tcb_head;
            } else {
                /* Memory allocated and this needs to be freed by consumer */
                ret =
                    ovsa_license_service_safe_malloc(sizeof(ovsa_tcb_sig_list_t), (char**)&tcb_cur);
                if (ret < OVSA_OK || tcb_cur == NULL) {
                    OVSA_DBG(DBG_E, "OVSA: Error could not allocate memory %d\n", ret);
                    goto end;
                }
                tcb_cur->next  = NULL;
                tcb_tail->next = tcb_cur;
                tcb_tail       = tcb_cur;
            }
            if (cJSON_IsString(sig) && (sig->valuestring != NULL)) {
                size_t str_len = 0;
                ret            = ovsa_license_service_get_string_length(sig->valuestring, &str_len);
                if (ret < OVSA_OK) {
                    OVSA_DBG(DBG_E,
                             "OVSA: Error could not get length of isv_certificate string %d\n",
                             ret);
                    goto end;
                }
                /* Memory allocated and this needs to be freed by consumer */
                ret = ovsa_license_service_safe_malloc(str_len + 1, &tcb_tail_signature);
                tcb_tail->tcb_signature = tcb_tail_signature;
                if (ret < OVSA_OK || tcb_tail->tcb_signature == NULL) {
                    OVSA_DBG(DBG_E, "OVSA: Error could not allocate memory %d\n", ret);
                    goto end;
                }
                memcpy_s(tcb_tail->tcb_signature, str_len, sig->valuestring, str_len);
                OVSA_DBG(DBG_D, "%s\n", fname);
            }
            device = device->next;
        }
    }
    cust_lic_sig->customer_lic.tcb_signatures = tcb_head;
end:
    cJSON_Delete(parse_json);
    OVSA_DBG(DBG_D, "OVSA:%s exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_license_service_json_extract_tcb_signature(const char* inputBuf,
                                                              ovsa_tcb_sig_t* tsig) {
    ovsa_status_t ret = OVSA_OK;
    cJSON* name       = NULL;
    cJSON* version    = NULL;
    cJSON* hw_quote   = NULL;
    cJSON* sw_quote   = NULL;
    cJSON* hw_pub_key = NULL;
    cJSON* sw_pub_key = NULL;
#ifdef ENABLE_SGX_GRAMINE
    cJSON* mrenclave   = NULL;
    cJSON* mrsigner    = NULL;
    cJSON* isv_svn     = NULL;
    cJSON* isv_prod_id = NULL;
#endif
    cJSON* isv_certificate = NULL;
    cJSON* signature       = NULL;
    cJSON* parse_json      = NULL;

    OVSA_DBG(DBG_D, "\nOVSA:%s entry\n", __func__);

    if (inputBuf == NULL || tsig == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error input is null %d\n", ret);
        ret = OVSA_JSON_INVALID_INPUT;
        goto end;
    }

    parse_json = cJSON_Parse(inputBuf);
    if (parse_json == NULL) {
        ret = OVSA_JSON_PARSE_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error could not parse %d\n", ret);
        goto end;
    }

    name = cJSON_GetObjectItemCaseSensitive(parse_json, "name");
    if (cJSON_IsString(name) && (name->valuestring != NULL)) {
        memcpy_s(tsig->tcbinfo.tcb_name, MAX_NAME_SIZE, name->valuestring,
                 strnlen_s(name->valuestring, MAX_NAME_SIZE));
        OVSA_DBG(DBG_D, "OVSA:name %s\n", name->valuestring);
    }

    version = cJSON_GetObjectItemCaseSensitive(parse_json, "version");
    if (cJSON_IsString(version) && (version->valuestring != NULL)) {
        memcpy_s(tsig->tcbinfo.tcb_version, MAX_VERSION_SIZE, version->valuestring,
                 strnlen_s(version->valuestring, MAX_VERSION_SIZE));
        OVSA_DBG(DBG_D, "OVSA:version %s\n", version->valuestring);
    }

    cJSON* tcb_sign = cJSON_GetObjectItemCaseSensitive(parse_json, "TCB Signature");

    cJSON* sw_tpm_quote = cJSON_GetObjectItemCaseSensitive(tcb_sign, "SW_TPM_Quote");
    cJSON* quote_sw     = cJSON_GetObjectItemCaseSensitive(sw_tpm_quote, "Quote");

    sw_pub_key = cJSON_GetObjectItemCaseSensitive(quote_sw, "SW_AK_Pub_key");
    if (cJSON_IsString(sw_pub_key) && (sw_pub_key->valuestring != NULL)) {
        memcpy_s(tsig->tcbinfo.sw_pub_key, TCB_INFO_MAX_PUBKEY_SIZE, sw_pub_key->valuestring,
                 strnlen_s(sw_pub_key->valuestring, TCB_INFO_MAX_PUBKEY_SIZE));
        OVSA_DBG(DBG_D, "OVSA:SW_AK_Pub_key %s\n", sw_pub_key->valuestring);
    }

    sw_quote = cJSON_GetObjectItemCaseSensitive(quote_sw, "SW_Quote_PCR");

    if (cJSON_IsString(sw_quote) && (sw_quote->valuestring != NULL)) {
        memcpy_s(tsig->tcbinfo.sw_quote, TCB_INFO_MAX_QUOTE_SIZE, sw_quote->valuestring,
                 strnlen_s(sw_quote->valuestring, TCB_INFO_MAX_QUOTE_SIZE));
        OVSA_DBG(DBG_D, "OVSA: SW_Quote_PCR %s\n", sw_quote->valuestring);
    }
    cJSON* sw_pcr_exclusion = cJSON_GetObjectItemCaseSensitive(sw_tpm_quote, "PCR_Exclusion");

    if (cJSON_IsString(sw_pcr_exclusion) && (sw_pcr_exclusion->valuestring != NULL)) {
        memcpy_s(tsig->tcbinfo.sw_pcr_id_set, TCB_INFO_MAX_QUOTE_SIZE,
                 sw_pcr_exclusion->valuestring,
                 strnlen_s(sw_pcr_exclusion->valuestring, TCB_INFO_MAX_QUOTE_SIZE));
        OVSA_DBG(DBG_D, "OVSA: PCR_Exclusion %s\n", sw_pcr_exclusion->valuestring);
    }

    cJSON* hw_tpm_quote = cJSON_GetObjectItemCaseSensitive(tcb_sign, "HW_TPM_Quote");
    cJSON* quote_hw     = cJSON_GetObjectItemCaseSensitive(hw_tpm_quote, "Quote");

    hw_pub_key = cJSON_GetObjectItemCaseSensitive(quote_hw, "HW_AK_Pub_Key");
    if (cJSON_IsString(hw_pub_key) && (hw_pub_key->valuestring != NULL)) {
        memcpy_s(tsig->tcbinfo.hw_pub_key, TCB_INFO_MAX_PUBKEY_SIZE, hw_pub_key->valuestring,
                 strnlen_s(hw_pub_key->valuestring, TCB_INFO_MAX_PUBKEY_SIZE));
        OVSA_DBG(DBG_D, "OVSA:HW_AK_Pub_Key %s\n", hw_pub_key->valuestring);
    }

    hw_quote = cJSON_GetObjectItemCaseSensitive(quote_hw, "HW_Quote_PCR");
    if (cJSON_IsString(hw_quote) && (hw_quote->valuestring != NULL)) {
        memcpy_s(tsig->tcbinfo.hw_quote, TCB_INFO_MAX_QUOTE_SIZE, hw_quote->valuestring,
                 strnlen_s(hw_quote->valuestring, TCB_INFO_MAX_QUOTE_SIZE));
        OVSA_DBG(DBG_D, "OVSA:HW_Quote_PCR %s\n", hw_quote->valuestring);
    }

    cJSON* hw_pcr_exclusion = cJSON_GetObjectItemCaseSensitive(hw_tpm_quote, "PCR_Exclusion");

    if (cJSON_IsString(hw_pcr_exclusion) && (hw_pcr_exclusion->valuestring != NULL)) {
        memcpy_s(tsig->tcbinfo.hw_pcr_id_set, TCB_INFO_MAX_QUOTE_SIZE,
                 hw_pcr_exclusion->valuestring,
                 strnlen_s(hw_pcr_exclusion->valuestring, TCB_INFO_MAX_QUOTE_SIZE));
        OVSA_DBG(DBG_D, "OVSA: PCR_Exclusion %s\n", hw_pcr_exclusion->valuestring);
    }
#ifdef ENABLE_SGX_GRAMINE
    cJSON* sgx_quote = cJSON_GetObjectItemCaseSensitive(tcb_sign, "SGX_ENCLAVE_Quote");
    mrenclave        = cJSON_GetObjectItemCaseSensitive(sgx_quote, "mrenclave");
    if (cJSON_IsString(mrenclave) && (mrenclave->valuestring != NULL)) {
        memcpy_s(tsig->tcbinfo.mrenclave, strnlen_s(mrenclave->valuestring, SGX_ENCLAVE_HASH_SIZE),
                 mrenclave->valuestring, strnlen_s(mrenclave->valuestring, SGX_ENCLAVE_HASH_SIZE));
        OVSA_DBG(DBG_D, "OVSA:mrenclave %s\n", mrenclave->valuestring);
    }

    mrsigner = cJSON_GetObjectItemCaseSensitive(sgx_quote, "mrsigner");
    if (cJSON_IsString(mrsigner) && (mrsigner->valuestring != NULL)) {
        memcpy_s(tsig->tcbinfo.mrsigner, strnlen_s(mrsigner->valuestring, SGX_ENCLAVE_HASH_SIZE),
                 mrsigner->valuestring, strnlen_s(mrsigner->valuestring, SGX_ENCLAVE_HASH_SIZE));
        OVSA_DBG(DBG_D, "OVSA:mrsigner %s\n", mrsigner->valuestring);
    }

    isv_svn = cJSON_GetObjectItemCaseSensitive(sgx_quote, "isv_svn");
    if (cJSON_IsNumber(isv_svn)) {
        tsig->tcbinfo.isv_svn = isv_svn->valueint;
        OVSA_DBG(DBG_D, "OVSA:isv_svn %d\n", isv_svn->valueint);
    }

    isv_prod_id = cJSON_GetObjectItemCaseSensitive(sgx_quote, "isv_prod_id");
    if (cJSON_IsNumber(isv_prod_id)) {
        tsig->tcbinfo.isv_prod_id = isv_prod_id->valueint;
        OVSA_DBG(DBG_D, "OVSA:isv_prod_id %d\n", isv_prod_id->valueint);
    }
#endif
    isv_certificate = cJSON_GetObjectItemCaseSensitive(parse_json, "isv_certificate");
    if (cJSON_IsString(isv_certificate) && (isv_certificate->valuestring != NULL)) {
        size_t str_len = 0;
        ret = ovsa_license_service_get_string_length(isv_certificate->valuestring, &str_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error could not get length of isv_certificate string %d\n", ret);
            goto end;
        }
        /* Memory allocated and this needs to be freed by consumer */
        ret = ovsa_license_service_safe_malloc(str_len + 1, &tsig->tcbinfo.isv_certificate);
        if (ret < OVSA_OK || tsig->tcbinfo.isv_certificate == NULL) {
            OVSA_DBG(DBG_E, "OVSA: Error could not allocate memory %d\n", ret);
            goto end;
        }
        memcpy_s(tsig->tcbinfo.isv_certificate, str_len, isv_certificate->valuestring, str_len);
        tsig->tcbinfo.isv_certificate[str_len] = '\0';
        OVSA_DBG(DBG_D, "OVSA:isv_certificate %s\n", isv_certificate->valuestring);
    }

    signature = cJSON_GetObjectItemCaseSensitive(parse_json, "signature");
    if (cJSON_IsString(signature) && (signature->valuestring != NULL)) {
        memcpy_s(tsig->signature, MAX_SIGNATURE_SIZE, signature->valuestring,
                 strnlen_s(signature->valuestring, MAX_SIGNATURE_SIZE));
        OVSA_DBG(DBG_D, "OVSA:signature %s\n", signature->valuestring);
    }

end:
    cJSON_Delete(parse_json);
    OVSA_DBG(DBG_D, "OVSA:%s exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_license_service_json_extract_element(const char* inputBuf, const char* keyName,
                                                        char** keyValue) {
    ovsa_status_t ret = OVSA_OK;
    cJSON* parse_json = NULL;
    cJSON* key        = NULL;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    if (inputBuf == NULL || keyName == NULL) {
        ret = OVSA_JSON_INVALID_INPUT;
        OVSA_DBG(DBG_E, "OVSA: Error input parameters invalid %d\n", ret);
        goto end;
    }

    parse_json = cJSON_Parse(inputBuf);
    if (parse_json == NULL) {
        ret = OVSA_JSON_PARSE_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error json parse failed %d\n", ret);
        goto end;
    }
    key = cJSON_GetObjectItemCaseSensitive(parse_json, keyName);
    if (cJSON_IsString(key) && (key->valuestring != NULL)) {
        size_t str_len = 0;
        ret            = ovsa_license_service_get_string_length(key->valuestring, &str_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error could not get length of key string %d\n", ret);
            goto end;
        }
        ret = ovsa_license_service_safe_malloc(str_len + 1, (char**)keyValue);
        if (ret < OVSA_OK) {
            ret = OVSA_JSON_MEMORY_ALLOC_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Error could not allocate memory %d\n", ret);
            goto end;
        }
        memcpy_s(*keyValue, str_len, key->valuestring, str_len);
    }

end:
    cJSON_Delete(parse_json);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_license_service_json_create_message_blob(ovsa_command_type_t cmdtype,
                                                            const char* payload, char** outputBuf,
                                                            size_t* valuelen) {
    ovsa_status_t ret = OVSA_OK;
    cJSON* message    = NULL;
    size_t len        = 0;
    size_t str_len    = 0;
    char command[MAX_COMMAND_TYPE_LENGTH];
    char* str_print            = NULL;
    const char* command_type[] = {"OVSA_SEND_NONCE",
                                  "OVSA_SEND_EK_AK_BIND",
                                  "OVSA_SEND_EK_AK_BIND_INFO",
                                  "OVSA_SEND_QUOTE_NONCE",
                                  "OVSA_SEND_SIGN_NONCE",
                                  "OVSA_SEND_QUOTE_INFO",
                                  "OVSA_SEND_CUST_LICENSE",
                                  "OVSA_SEND_UPDATE_CUST_LICENSE",
                                  "OVSA_SEND_UPDATE_CUST_LICENSE_ACK",
                                  "OVSA_SEND_LICENSE_CHECK_RESP"};

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    if (cmdtype < 0 || payload == NULL) {
        ret = OVSA_JSON_INVALID_INPUT;
        OVSA_DBG(DBG_E, "OVSA: Error input parameters invalid %d\n", ret);
        goto end;
    }
    memset_s(command, sizeof(command), 0);
    switch (cmdtype) {
        case OVSA_SEND_NONCE:
            memcpy_s(command, MAX_COMMAND_TYPE_LENGTH, command_type[OVSA_SEND_NONCE],
                     strnlen_s(command_type[OVSA_SEND_NONCE], MAX_COMMAND_TYPE_LENGTH));
            break;
        case OVSA_SEND_EK_AK_BIND:
            memcpy_s(command, MAX_COMMAND_TYPE_LENGTH, command_type[OVSA_SEND_EK_AK_BIND],
                     strnlen_s(command_type[OVSA_SEND_EK_AK_BIND], MAX_COMMAND_TYPE_LENGTH));
            break;
        case OVSA_SEND_QUOTE_NONCE:
            memcpy_s(command, MAX_COMMAND_TYPE_LENGTH, command_type[OVSA_SEND_QUOTE_NONCE],
                     strnlen_s(command_type[OVSA_SEND_QUOTE_NONCE], MAX_COMMAND_TYPE_LENGTH));
            break;

        case OVSA_SEND_UPDATE_CUST_LICENSE:
            memcpy_s(command, MAX_COMMAND_TYPE_LENGTH, command_type[OVSA_SEND_UPDATE_CUST_LICENSE],
                     strnlen_s((char*)command_type[OVSA_SEND_UPDATE_CUST_LICENSE],
                               MAX_COMMAND_TYPE_LENGTH));
            break;

        case OVSA_SEND_LICENSE_CHECK_RESP:
            memcpy_s(command, MAX_COMMAND_TYPE_LENGTH, command_type[OVSA_SEND_LICENSE_CHECK_RESP],
                     strnlen_s((char*)command_type[OVSA_SEND_LICENSE_CHECK_RESP],
                               MAX_COMMAND_TYPE_LENGTH));
            break;
        default:
            OVSA_DBG(DBG_E, "OVSA: Error json message command not valid \n");
            goto end;
    }

    /* create json object */
    message = cJSON_CreateObject();
    if (message == NULL) {
        ret = OVSA_JSON_ERROR_CREATE_OBJECT;
        OVSA_DBG(DBG_E, "OVSA: Error create json object failed %d\n", ret);
        goto end;
    }
    /* populate the json */
    if (cJSON_AddStringToObject(message, "command", command) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "OVSA: Error add command to message info failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(message, "payload", payload) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "OVSA: Error add payload to json failed %d\n", ret);
        goto end;
    }
    str_print = cJSON_Print(message);
    if (str_print == NULL) {
        ret = OVSA_JSON_PRINT_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error print message json to buffer failed %d\n", ret);
        goto end;
    }
    ret = ovsa_license_service_get_string_length(str_print, &len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of string %d\n", ret);
        goto end;
    }
    len = len + 1; /* for NULL termination */
    ret = ovsa_license_service_safe_malloc(len, (char**)outputBuf);
    if (ret < OVSA_OK || *outputBuf == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error could not allocate memory %d\n", ret);
        goto end;
    }
    *valuelen = len;
    memcpy_s(*outputBuf, len, str_print, len);
end:
    cJSON_Delete(message);
    ovsa_license_service_safe_free(&str_print);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}
ovsa_status_t ovsa_license_service_json_create_quote_cred_data_blob(const char* cred_out,
                                                                    const char* quote_nonce,
                                                                    char** outputBuf,
                                                                    size_t* valuelen) {
    ovsa_status_t ret = OVSA_OK;
    cJSON* message    = NULL;
    size_t len        = 0;
    char* str_print   = NULL;

    OVSA_DBG(DBG_D, "%s entry\n", __func__);
    if (cred_out == NULL || quote_nonce == NULL) {
        ret = OVSA_JSON_INVALID_INPUT;
        OVSA_DBG(DBG_E, "OVSA: Error input parameters invalid %d\n", ret);
        goto end;
    }
    /* create json object */
    message = cJSON_CreateObject();
    if (message == NULL) {
        ret = OVSA_JSON_ERROR_CREATE_OBJECT;
        OVSA_DBG(DBG_E, "OVSA: Error create json message object failed %d\n", ret);
        goto end;
    }
    /* populate the json */
    if (cJSON_AddStringToObject(message, "cred_blob", cred_out) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "OVSA: Error add command to message info failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(message, "quote_nonce", quote_nonce) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "OVSA: Error add payload to json failed %d\n", ret);
        goto end;
    }
    str_print = cJSON_Print(message);
    if (str_print == NULL) {
        ret = OVSA_JSON_PRINT_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error print message json to buffer failed %d\n", ret);
        goto end;
    }
    ret = ovsa_license_service_get_string_length(str_print, &len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of string %d\n", ret);
        goto end;
    }
    len = len + 1; /* for NULL termination */
    ret = ovsa_license_service_safe_malloc(len, (char**)outputBuf);
    if (ret < OVSA_OK || *outputBuf == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error could not allocate memory %d\n", ret);
        goto end;
    }
    *valuelen = len;
    memcpy_s(*outputBuf, len, str_print, len);

end:
    cJSON_Delete(message);
    ovsa_license_service_safe_free(&str_print);
    OVSA_DBG(DBG_D, "%s exit\n", __func__);
    return ret;
}
