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
#include <stdlib.h>
#include <string.h>
#ifdef OVSA_RUNTIME
#include "runtime.h"
#endif
#include "cJSON.h"
#include "libovsa.h"
#include "ovsa_tool.h"
#include "safe_mem_lib.h"
#include "safe_str_lib.h"
#include "snprintf_s.h"
#include "utils.h"
/* json.h to be included at end due to dependencies */
#include "json.h"

static const char* license_type[] = {"Sale", "InstanceLimit", "TimeLimit"};

static const char* ovsa_json_get_license_type_string(const ovsa_license_type_t type) {
    switch (type) {
        case SALE:
            OVSA_DBG(DBG_D, "SALE\n");
            return license_type[SALE];
        case INSTANCELIMIT:
            OVSA_DBG(DBG_D, "INSTANCELIMIT\n");
            return license_type[INSTANCELIMIT];
        case TIMELIMIT:
            OVSA_DBG(DBG_D, "TIMELIMIT\n");
            return license_type[TIMELIMIT];
        default:
            return NULL;
    }
}

ovsa_license_type_t ovsa_json_map_license_type(const char* lictype) {
    if (!(strcmp(lictype, license_type[SALE]))) {
        OVSA_DBG(DBG_D, "SALE\n");
        return SALE;
    } else if (!(strcmp(lictype, license_type[INSTANCELIMIT]))) {
        OVSA_DBG(DBG_D, "INSTANCELIMIT\n");
        return INSTANCELIMIT;
    } else if (!(strcmp(lictype, license_type[TIMELIMIT]))) {
        OVSA_DBG(DBG_D, "TIMELIMIT\n");
        return TIMELIMIT;
    } else {
        OVSA_DBG(DBG_E, "Error: Invalid option for license type\n");
        return MAXLICENSETYPE;
    }
}

/* Create json blob */
ovsa_status_t ovsa_json_create_license_config(const ovsa_license_config_sig_t* lic_conf_sig,
                                              char* outputBuf) {
    ovsa_status_t ret     = OVSA_OK;
    cJSON* license_config = NULL;
    char* str_print       = NULL;

    OVSA_DBG(DBG_D, "%s entry\n", __func__);

    if (lic_conf_sig == NULL || outputBuf == NULL) {
        ret = OVSA_JSON_INVALID_INPUT;
        OVSA_DBG(DBG_E, "Error: Input parameters invalid %d\n", ret);
        goto end;
    }

    /* Create json object */
    license_config = cJSON_CreateObject();
    if (license_config == NULL) {
        ret = OVSA_JSON_ERROR_CREATE_OBJECT;
        OVSA_DBG(DBG_E, "Error: Create license config Json object failed %d\n", ret);
        goto end;
    }

    /* Populate the json structure */
    if (cJSON_AddStringToObject(license_config, "name", lic_conf_sig->lic_config.license_name) ==
        NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add name to license config failed %d\n", ret);
        goto end;
    }

    const char* lic_type = ovsa_json_get_license_type_string(lic_conf_sig->lic_config.license_type);
    if (cJSON_AddStringToObject(license_config, "license_type", lic_type) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add license_type to license config failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(license_config, "license_version",
                                lic_conf_sig->lic_config.license_version) == NULL) {
        OVSA_DBG(DBG_E, "Error: Could not add number object version \n");
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        goto end;
    }

    cJSON* srvurl = cJSON_CreateObject();
    if (srvurl == NULL) {
        ret = OVSA_JSON_ERROR_CREATE_OBJECT;
        OVSA_DBG(DBG_E, "Error: Could not create object srvurl\n");
        goto end;
    }
    cJSON_AddItemToObject(license_config, "license_serv_url", srvurl);

    ovsa_license_serv_url_list_t* list = lic_conf_sig->lic_config.license_url_list;
    if (list != NULL) {
        int i = 0;
        char fname[10];
        while (list->license_serv_url != NULL) {
            snprintf_s_i(fname, 10, "url_%d", (i++) % 100u);
            cJSON* url = cJSON_CreateString(list->license_serv_url);
            if (url == NULL) {
                ret = OVSA_JSON_ERROR_CREATE_OBJECT;
                OVSA_DBG(DBG_E, "Error: Could not create string url\n");
                goto end;
            }
            OVSA_DBG(DBG_D, "%s\n", fname);
            cJSON_AddItemToObject(srvurl, fname, url);
            if (list->next != NULL) {
                list = list->next;
            } else {
                break;
            }
        }
    }

    if (cJSON_AddNumberToObject(license_config, "usage_count",
                                lic_conf_sig->lic_config.usage_count) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add usage_count to license config failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddNumberToObject(license_config, "time_limit",
                                lic_conf_sig->lic_config.time_limit) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add time_limit to license config failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(license_config, "isv_certificate",
                                lic_conf_sig->lic_config.isv_certificate) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add isv_certificate to license config failed\n");
        goto end;
    }

    str_print = cJSON_Print(license_config);
    if (str_print == NULL) {
        ret = OVSA_JSON_PRINT_FAIL;
        OVSA_DBG(DBG_E, "Error: Print json to buffer failed %d\n", ret);
        goto end;
    }
    size_t str_len = 0;
    ret            = ovsa_get_string_length(str_print, &str_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of string %d\n", ret);
        goto end;
    }
    memcpy_s(outputBuf, str_len, str_print, str_len);
    outputBuf[str_len] = '\0';

end:
    cJSON_Delete(license_config);
    ovsa_safe_free(&str_print);
    OVSA_DBG(DBG_D, "%s exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_json_create_protected_model(const ovsa_protected_model_sig_t* prot_model_sig,
                                               size_t size, char* outputBuf) {
    ovsa_status_t ret      = OVSA_OK;
    cJSON* protected_model = NULL;
    char* str_print        = NULL;

    OVSA_DBG(DBG_D, "%s entry\n", __func__);

    if (prot_model_sig == NULL || outputBuf == NULL) {
        ret = OVSA_JSON_INVALID_INPUT;
        OVSA_DBG(DBG_E, "Error: Input parameters invalid %d\n", ret);
        goto end;
    }

    /* Create json object */
    protected_model = cJSON_CreateObject();
    if (protected_model == NULL) {
        ret = OVSA_JSON_ERROR_CREATE_OBJECT;
        OVSA_DBG(DBG_E, "Error: Create protected model Json object failed %d\n", ret);
        goto end;
    }

    /* Populate the json structure */
    if (cJSON_AddStringToObject(protected_model, "name",
                                prot_model_sig->protect_model.model_name) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add name to protected model failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(protected_model, "description",
                                prot_model_sig->protect_model.description) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add description to protected model failed failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(protected_model, "version",
                                prot_model_sig->protect_model.version) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add version to protected model failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(protected_model, "model_guid",
                                prot_model_sig->protect_model.model_guid) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add model_guid to protected model failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(protected_model, "isv_certificate",
                                prot_model_sig->protect_model.isv_certificate) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add isv_certificate to protected model failed %d\n", ret);
        goto end;
    }
    cJSON* model_files = cJSON_CreateArray();
    if (model_files == NULL) {
        OVSA_DBG(DBG_E, "Error: Could not create object model_files\n");
        ret = OVSA_JSON_ERROR_CREATE_OBJECT;
        goto end;
    }
    cJSON_AddItemToObject(protected_model, "files", model_files);

    struct ovsa_enc_models* list = prot_model_sig->protect_model.enc_model;
    if (list != NULL) {
        int i = 0;
        char name[20];
        errno_t ret      = EOK;
        char* filename   = NULL;
        cJSON* file_name = NULL;
        while (list->enc_model != NULL) {
            snprintf_s_i(name, 20, "file_name_%d", (i) % 100u);

            cJSON* enc_file = cJSON_CreateObject();
            if (enc_file == NULL) {
                OVSA_DBG(DBG_E, "Error: Could not create object enc_file\n");
                ret = OVSA_JSON_ERROR_CREATE_OBJECT;
                goto end;
            }
            cJSON_AddItemToArray(model_files, enc_file);

            /* Extract only the filename */
            ret = strlastchar_s(list->file_name, strnlen_s(list->file_name, MAX_NAME_SIZE), '/',
                                &filename);
            if (ret == EOK) {
                file_name = cJSON_CreateString(filename + 1);
                printf("Filename is %s\n", filename + 1);
            } else if (ret == ESNOTFND) {
                file_name = cJSON_CreateString(list->file_name);
                printf("Filename is %s\n", list->file_name);
            } else {
                ret = OVSA_JSON_ERROR_CREATE_OBJECT;
                OVSA_DBG(DBG_E, "Error: Could not create string file\n");
                goto end;
            }

            if (file_name == NULL) {
                ret = OVSA_JSON_ERROR_CREATE_OBJECT;
                OVSA_DBG(DBG_E, "Error: Could not create string file\n");
                goto end;
            }
            cJSON_AddItemToObject(enc_file, name, file_name);

            snprintf_s_i(name, 20, "file_body_%d", (i++) % 100u);
            cJSON* file = cJSON_CreateString(list->enc_model);
            if (file == NULL) {
                ret = OVSA_JSON_ERROR_CREATE_OBJECT;
                OVSA_DBG(DBG_E, "Error: Could not create string file\n");
                goto end;
            }
            cJSON_AddItemToObject(enc_file, name, file);

            OVSA_DBG(DBG_D, "%s\n", name);
            if (list->next != NULL) {
                list = list->next;
            } else {
                break;
            }
        }
    }

    str_print = cJSON_Print(protected_model);
    if (str_print == NULL) {
        ret = OVSA_JSON_PRINT_FAIL;
        OVSA_DBG(DBG_E, "Error: Print json to buffer failed %d\n", ret);
        goto end;
    }
    size_t str_len = 0;
    ret            = ovsa_get_string_length(str_print, &str_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of string %d\n", ret);
        goto end;
    }
    memcpy_s(outputBuf, str_len, str_print, str_len);
    outputBuf[str_len] = '\0';

end:
    cJSON_Delete(protected_model);
    ovsa_safe_free(&str_print);
    OVSA_DBG(DBG_D, "%s exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_json_create_tcb_signature(const ovsa_tcb_sig_t* tsig, char* outputBuf) {
    ovsa_status_t ret = OVSA_OK;
    cJSON* tcb_sig    = NULL;
    char* str_print   = NULL;

    OVSA_DBG(DBG_D, "%s entry\n", __func__);

    if (tsig == NULL || outputBuf == NULL) {
        ret = OVSA_JSON_INVALID_INPUT;
        OVSA_DBG(DBG_E, "Error: Input parameters invalid %d\n", ret);
        goto end;
    }

    /* Create json object */
    tcb_sig = cJSON_CreateObject();
    if (tcb_sig == NULL) {
        ret = OVSA_JSON_ERROR_CREATE_OBJECT;
        OVSA_DBG(DBG_E, "Error: Create license config Json object failed %d\n", ret);
        goto end;
    }

    /* Populate the json structure */
    if (cJSON_AddStringToObject(tcb_sig, "name", tsig->tcbinfo.tcb_name) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add name to tcb info failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(tcb_sig, "version", tsig->tcbinfo.tcb_version) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add version to tcb info failed %d\n", ret);
        goto end;
    }
#ifndef DISABLE_TPM2_HWQUOTE
    if (cJSON_AddStringToObject(tcb_sig, "HW_Quote_PCR", tsig->tcbinfo.hw_quote) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add HW_quote to tcb info failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(tcb_sig, "HW_AK_Pub_Key", tsig->tcbinfo.hw_pub_key) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add HW_pub_key to tcb info failed %d\n", ret);
        goto end;
    }
#endif
    if (cJSON_AddStringToObject(tcb_sig, "SW_Quote_PCR", tsig->tcbinfo.sw_quote) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add SW_quote to tcb info failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(tcb_sig, "SW_AK_Pub_key", tsig->tcbinfo.sw_pub_key) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add SW_pub_key to tcb info failed %d\n", ret);
        goto end;
    }

    if (cJSON_AddStringToObject(tcb_sig, "isv_certificate", tsig->tcbinfo.isv_certificate) ==
        NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add isv_certificate to tcb info failed %d\n", ret);
        goto end;
    }

    str_print = cJSON_Print(tcb_sig);
    if (str_print == NULL) {
        ret = OVSA_JSON_PRINT_FAIL;
        OVSA_DBG(DBG_E, "Error: Print json to buffer failed %d\n", ret);
        goto end;
    }
    size_t str_len = 0;
    ret            = ovsa_get_string_length(str_print, &str_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of string %d\n", ret);
        goto end;
    }
    memcpy_s(outputBuf, str_len, str_print, str_len);
    outputBuf[str_len] = '\0';

end:
    cJSON_Delete(tcb_sig);
    ovsa_safe_free(&str_print);
    OVSA_DBG(DBG_D, "%s exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_json_create_master_license(const ovsa_master_license_sig_t* master_lic_sig,
                                              char* outputBuf) {
    ovsa_status_t ret     = OVSA_OK;
    cJSON* master_license = NULL;
    char* str_print       = NULL;

    OVSA_DBG(DBG_D, "%s entry\n", __func__);

    if (outputBuf == NULL || master_lic_sig == NULL) {
        ret = OVSA_JSON_INVALID_INPUT;
        OVSA_DBG(DBG_E, "Error: Input parameters invalid %d\n", ret);
        goto end;
    }

    /* Create json object */
    master_license = cJSON_CreateObject();
    if (master_license == NULL) {
        ret = OVSA_JSON_ERROR_CREATE_OBJECT;
        OVSA_DBG(DBG_E, "Error: Create master license Json object failed %d\n", ret);
        goto end;
    }

    /* Populate the json structure */
    if (cJSON_AddStringToObject(master_license, "creation_date",
                                master_lic_sig->master_lic.creation_date) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add creation_date to master license failed %d\n", ret);
        goto end;
    }

    if (cJSON_AddStringToObject(master_license, "model_hash",
                                master_lic_sig->master_lic.model_hash) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add model_hash to master license failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(master_license, "license_guid",
                                master_lic_sig->master_lic.license_guid) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add license_guid to master license failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(master_license, "model_guid",
                                master_lic_sig->master_lic.model_guid) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add model_guid to master license failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(master_license, "encryption_key",
                                master_lic_sig->master_lic.encryption_key) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add encryption_key to master license failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(master_license, "isv_certificate",
                                master_lic_sig->master_lic.isv_certificate) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add isv_certificate to master license failed %d\n", ret);
        goto end;
    }

    str_print = cJSON_Print(master_license);
    if (str_print == NULL) {
        ret = OVSA_JSON_PRINT_FAIL;
        OVSA_DBG(DBG_E, "Error: Print json to buffer failed %d\n", ret);
        goto end;
    }
    size_t str_len = 0;
    ret            = ovsa_get_string_length(str_print, &str_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of string %d\n", ret);
        goto end;
    }
    memcpy_s(outputBuf, str_len, str_print, str_len);
    outputBuf[str_len] = '\0';

end:
    cJSON_Delete(master_license);
    ovsa_safe_free(&str_print);
    OVSA_DBG(DBG_D, "%s exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_json_create_customer_license(const ovsa_customer_license_sig_t* cust_lic_sig,
                                                char* outputBuf) {
    ovsa_status_t ret       = OVSA_OK;
    cJSON* customer_license = NULL;
    char* str_print         = NULL;

    OVSA_DBG(DBG_D, "%s entry\n", __func__);

    if (cust_lic_sig == NULL || outputBuf == NULL) {
        ret = OVSA_JSON_INVALID_INPUT;
        OVSA_DBG(DBG_E, "Error: Input parameters invalid %d\n", ret);
        goto end;
    }

    /* Create json object */
    customer_license = cJSON_CreateObject();
    if (customer_license == NULL) {
        ret = OVSA_JSON_ERROR_CREATE_OBJECT;
        OVSA_DBG(DBG_E, "Error: Create customer license Json object failed %d\n", ret);
        goto end;
    }

    /* Populate the json structure */
    if (cJSON_AddStringToObject(customer_license, "creation_date",
                                cust_lic_sig->customer_lic.creation_date) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add creation_date to customer license failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(customer_license, "isv_certificate",
                                cust_lic_sig->customer_lic.isv_certificate) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add isv_certificate to customer license failed %d\n", ret);
        goto end;
    }

    if (cJSON_AddStringToObject(customer_license, "model_hash",
                                cust_lic_sig->customer_lic.model_hash) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add model_hash to customer license failed %d\n", ret);
        goto end;
    }

    if (cJSON_AddStringToObject(customer_license, "license_name",
                                cust_lic_sig->customer_lic.license_name) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add license_name to customer license failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(customer_license, "license_version",
                                cust_lic_sig->customer_lic.license_version) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add license_version to customer license failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(customer_license, "license_guid",
                                cust_lic_sig->customer_lic.license_guid) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add license_guid to customer license failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(customer_license, "model_guid",
                                cust_lic_sig->customer_lic.model_guid) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add model_guid to customer license failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(customer_license, "encryption_key",
                                cust_lic_sig->customer_lic.encryption_key) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add encryption_key to customer license failed %d\n", ret);
        goto end;
    }

    cJSON* srvurl = cJSON_CreateObject();
    if (srvurl == NULL) {
        ret = OVSA_JSON_ERROR_CREATE_OBJECT;
        OVSA_DBG(DBG_E, "Error: Could not create object srvurl\n");
        goto end;
    }
    cJSON_AddItemToObject(customer_license, "license_serv_url", srvurl);

    ovsa_license_serv_url_list_t* list = cust_lic_sig->customer_lic.license_url_list;
    if (list != NULL) {
        int i = 0;
        char fname[10];
        while (list->license_serv_url != NULL) {
            snprintf_s_i(fname, 10, "url_%d", (i++) % 100u);
            cJSON* url = cJSON_CreateString(list->license_serv_url);
            if (url == NULL) {
                ret = OVSA_JSON_ERROR_CREATE_OBJECT;
                OVSA_DBG(DBG_E, "Error: Could not create string url\n");
                goto end;
            }
            OVSA_DBG(DBG_D, "%s\n", fname);
            cJSON_AddItemToObject(srvurl, fname, url);
            if (list->next != NULL) {
                list = list->next;
            } else {
                break;
            }
        }
    }

    const char* lic_type =
        ovsa_json_get_license_type_string(cust_lic_sig->customer_lic.license_type);
    if (cJSON_AddStringToObject(customer_license, "license_type", lic_type) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add license_type to customer license failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddNumberToObject(customer_license, "usage_count",
                                cust_lic_sig->customer_lic.usage_count) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add usage_count to customer license failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddNumberToObject(customer_license, "time_limit",
                                cust_lic_sig->customer_lic.time_limit) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add time_limit to customer license failed %d\n", ret);
        goto end;
    }

    cJSON* tcb_list = cJSON_CreateObject();
    if (tcb_list == NULL) {
        ret = OVSA_JSON_ERROR_CREATE_OBJECT;
        OVSA_DBG(DBG_E, "Error: Could not create object tcb_list\n");
        goto end;
    }
    cJSON_AddItemToObject(customer_license, "tcb_signature", tcb_list);

    ovsa_tcb_sig_list_t* tlist = cust_lic_sig->customer_lic.tcb_signatures;
    if (tlist != NULL) {
        int i = 0;
        char fname[10];
        while (tlist->tcb_signature != NULL) {
            snprintf_s_i(fname, 10, "sig_%d", (i++) % 100u);
            cJSON* sig = cJSON_CreateString(tlist->tcb_signature);
            if (sig == NULL) {
                ret = OVSA_JSON_ERROR_CREATE_OBJECT;
                OVSA_DBG(DBG_E, "Error: Could  not create string sig %d\n", ret);
                goto end;
            }
            OVSA_DBG(DBG_D, "%s\n", fname);
            cJSON_AddItemToObject(tcb_list, fname, sig);
            if (tlist->next != NULL) {
                tlist = tlist->next;
            } else {
                break;
            }
        }
    }
    str_print = cJSON_Print(customer_license);
    if (str_print == NULL) {
        ret = OVSA_JSON_PRINT_FAIL;
        OVSA_DBG(DBG_E, "Error: Print json to buffer failed %d\n", ret);
        goto end;
    }
    size_t str_len = 0;
    ret            = ovsa_get_string_length(str_print, &str_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of string %d\n", ret);
        goto end;
    }
    memcpy_s(outputBuf, str_len, str_print, str_len);
    outputBuf[str_len] = '\0';

end:
    cJSON_Delete(customer_license);
    ovsa_safe_free(&str_print);
    OVSA_DBG(DBG_D, "%s exit\n", __func__);
    return ret;
}

/* Extract json blob */
ovsa_status_t ovsa_json_extract_license_config(const char* inputBuf,
                                               ovsa_license_config_sig_t* lic_conf_sig) {
    ovsa_status_t ret      = OVSA_OK;
    cJSON* name            = NULL;
    cJSON* license_type    = NULL;
    cJSON* usage_count     = NULL;
    cJSON* time_limit      = NULL;
    cJSON* isv_certificate = NULL;
    cJSON* version         = NULL;
    cJSON* parse_json      = NULL;
    int i                  = 0;
    char fname[10];
    ovsa_license_serv_url_list_t* head = NULL;
    ovsa_license_serv_url_list_t* cur  = NULL;
    ovsa_license_serv_url_list_t* tail = NULL;

    OVSA_DBG(DBG_D, "%s entry\n", __func__);

    if (inputBuf == NULL || lic_conf_sig == NULL) {
        OVSA_DBG(DBG_E, "Error: Input is null %d\n", ret);
        ret = OVSA_JSON_INVALID_INPUT;
        goto end;
    }

    parse_json = cJSON_Parse(inputBuf);
    if (parse_json == NULL) {
        ret = OVSA_JSON_PARSE_FAIL;
        OVSA_DBG(DBG_E, "Error: could not parse %d\n", ret);
        goto end;
    }

    name = cJSON_GetObjectItemCaseSensitive(parse_json, "name");
    if (cJSON_IsString(name) && (name->valuestring != NULL)) {
        memcpy_s(lic_conf_sig->lic_config.license_name, strnlen_s(name->valuestring, MAX_NAME_SIZE),
                 name->valuestring, strnlen_s(name->valuestring, MAX_NAME_SIZE));
        OVSA_DBG(DBG_D, "name: %s\n", name->valuestring);
    }

    license_type = cJSON_GetObjectItemCaseSensitive(parse_json, "license_type");
    if (cJSON_IsString(license_type) && (license_type->valuestring != NULL)) {
        lic_conf_sig->lic_config.license_type =
            ovsa_json_map_license_type(license_type->valuestring);
        OVSA_DBG(DBG_D, "license_type: %s\n", license_type->valuestring);
    }

    isv_certificate = cJSON_GetObjectItemCaseSensitive(parse_json, "isv_certificate");
    if (cJSON_IsString(isv_certificate) && (isv_certificate->valuestring != NULL)) {
        /* Memory allocated and this needs to be freed by consumer */
        size_t str_len = 0;
        ret            = ovsa_get_string_length(isv_certificate->valuestring, &str_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Could not get length of isv_certificate string %d\n", ret);
            goto end;
        }
        ret = ovsa_safe_malloc(str_len + 1, &lic_conf_sig->lic_config.isv_certificate);
        if (ret < OVSA_OK || lic_conf_sig->lic_config.isv_certificate == NULL) {
            OVSA_DBG(DBG_E, "Error: could not allocate memory %d\n", ret);
            goto end;
        }
        memcpy_s(lic_conf_sig->lic_config.isv_certificate, str_len, isv_certificate->valuestring,
                 str_len);
        lic_conf_sig->lic_config.isv_certificate[str_len] = '\0';
        OVSA_DBG(DBG_D, "isv_certificate: %s\n", isv_certificate->valuestring);
    }

    cJSON* svrurl = cJSON_GetObjectItemCaseSensitive(parse_json, "license_serv_url");
    if (svrurl) {
        cJSON* device = svrurl->child;
        i             = 0;
        while (device) {
            snprintf_s_i(fname, 10, "url_%d", (i++) % 100u);
            cJSON* url = cJSON_GetObjectItemCaseSensitive(svrurl, fname);
            if (head == NULL) {
                /* Memory allocated and this needs to be freed by consumer */
                ret = ovsa_safe_malloc(sizeof(ovsa_license_serv_url_list_t), (char**)&head);
                if (ret < OVSA_OK || head == NULL) {
                    OVSA_DBG(DBG_E, "Error: could not allocate memory %d\n", ret);
                    goto end;
                }
                head->next = NULL;
                tail       = head;
            } else {
                /* Memory allocated and this needs to be freed by consumer */
                ret = ovsa_safe_malloc(sizeof(ovsa_license_serv_url_list_t), (char**)&cur);
                if (ret < OVSA_OK || cur == NULL) {
                    OVSA_DBG(DBG_E, "Error: could not allocate memory %d\n", ret);
                    goto end;
                }
                cur->next  = NULL;
                tail->next = cur;
                tail       = cur;
            }
            if (cJSON_IsString(url) && (url->valuestring != NULL)) {
                memset_s(tail->license_serv_url, MAX_URL_SIZE, 0);
                memcpy_s(tail->license_serv_url, strnlen_s(url->valuestring, MAX_URL_SIZE),
                         url->valuestring, strnlen_s(url->valuestring, MAX_URL_SIZE));
                OVSA_DBG(DBG_D, "%s\n", fname);
            }
            device = device->next;
        }
    }
    lic_conf_sig->lic_config.license_url_list = head;

    usage_count = cJSON_GetObjectItemCaseSensitive(parse_json, "usage_count");
    if (cJSON_IsNumber(usage_count)) {
        lic_conf_sig->lic_config.usage_count = usage_count->valueint;
        OVSA_DBG(DBG_D, "usage_count: %d\n", usage_count->valueint);
    }

    time_limit = cJSON_GetObjectItemCaseSensitive(parse_json, "time_limit");
    if (cJSON_IsNumber(time_limit)) {
        lic_conf_sig->lic_config.time_limit = time_limit->valueint;
        OVSA_DBG(DBG_D, "time_limit: %d\n", time_limit->valueint);
    }

    version = cJSON_GetObjectItemCaseSensitive(parse_json, "license_version");
    if (cJSON_IsString(version) && (version->valuestring != NULL)) {
        memcpy_s(lic_conf_sig->lic_config.license_version,
                 strnlen_s(version->valuestring, MAX_VERSION_SIZE), version->valuestring,
                 strnlen_s(version->valuestring, MAX_VERSION_SIZE));
        OVSA_DBG(DBG_D, "version: %s\n", version->valuestring);
    }

end:
    cJSON_Delete(parse_json);
    OVSA_DBG(DBG_D, "%s exit\n", __func__);
    return ret;
}

#ifdef OVSA_RUNTIME
ovsa_status_t ovsa_json_extract_protected_model(const char* inputBuf,
                                                ovsa_protected_model_sig_t* prot_model_sig) {
    ovsa_status_t ret       = OVSA_OK;
    cJSON* name             = NULL;
    cJSON* description      = NULL;
    cJSON* version          = NULL;
    cJSON* model_guid       = NULL;
    cJSON* isv_certificate  = NULL;
    cJSON* signature        = NULL;
    cJSON* parse_json       = NULL;
    cJSON* file             = NULL;
    ovsa_enc_models_t* head = NULL;
    ovsa_enc_models_t* cur  = NULL;
    ovsa_enc_models_t* tail = NULL;
    char* tail_enc_model    = NULL;
    int i                   = 0;
    char fname[20];

    OVSA_DBG(DBG_D, "%s entry\n", __func__);

    if (inputBuf == NULL || prot_model_sig == NULL) {
        OVSA_DBG(DBG_E, "Error: Input is null %d\n", ret);
        ret = OVSA_JSON_INVALID_INPUT;
        goto end;
    }

    parse_json = cJSON_Parse(inputBuf);
    if (parse_json == NULL) {
        ret = OVSA_JSON_PARSE_FAIL;
        OVSA_DBG(DBG_E, "Error: could not parse %d\n", ret);
        goto end;
    }

    name = cJSON_GetObjectItemCaseSensitive(parse_json, "name");
    if (cJSON_IsString(name) && (name->valuestring != NULL)) {
        memcpy_s(prot_model_sig->protect_model.model_name,
                 strnlen_s(name->valuestring, MAX_NAME_SIZE), name->valuestring,
                 strnlen_s(name->valuestring, MAX_NAME_SIZE));
        OVSA_DBG(DBG_D, "name %s\n", name->valuestring);
    }

    description = cJSON_GetObjectItemCaseSensitive(parse_json, "description");
    if (cJSON_IsString(description) && (description->valuestring != NULL)) {
        memcpy_s(prot_model_sig->protect_model.description,
                 strnlen_s(description->valuestring, MAX_NAME_SIZE), description->valuestring,
                 strnlen_s(description->valuestring, MAX_NAME_SIZE));
        OVSA_DBG(DBG_D, "description %s\n", description->valuestring);
    }

    version = cJSON_GetObjectItemCaseSensitive(parse_json, "version");
    if (cJSON_IsString(version) && (version->valuestring != NULL)) {
        memcpy_s(prot_model_sig->protect_model.version,
                 strnlen_s(version->valuestring, MAX_VERSION_SIZE), version->valuestring,
                 strnlen_s(version->valuestring, MAX_VERSION_SIZE));
        OVSA_DBG(DBG_D, "version %s\n", version->valuestring);
    }

    model_guid = cJSON_GetObjectItemCaseSensitive(parse_json, "model_guid");
    if (cJSON_IsString(model_guid) && (model_guid->valuestring != NULL)) {
        memcpy_s(prot_model_sig->protect_model.model_guid,
                 strnlen_s(model_guid->valuestring, GUID_SIZE), model_guid->valuestring,
                 strnlen_s(model_guid->valuestring, GUID_SIZE));
        OVSA_DBG(DBG_D, "model_guid %s\n", model_guid->valuestring);
    }

    isv_certificate = cJSON_GetObjectItemCaseSensitive(parse_json, "isv_certificate");
    if (cJSON_IsString(isv_certificate) && (isv_certificate->valuestring != NULL)) {
        /* Memory allocated and this needs to be freed by consumer */
        size_t str_len = 0;
        ret            = ovsa_get_string_length(isv_certificate->valuestring, &str_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Could not get length of isv_certificate string %d\n", ret);
            goto end;
        }
        ret = ovsa_safe_malloc(str_len + 1, &prot_model_sig->protect_model.isv_certificate);
        if (ret < OVSA_OK || prot_model_sig->protect_model.isv_certificate == NULL) {
            OVSA_DBG(DBG_E, "Error: could not allocate memory %d\n", ret);
            goto end;
        }
        memcpy_s(prot_model_sig->protect_model.isv_certificate, str_len,
                 isv_certificate->valuestring, str_len);
        prot_model_sig->protect_model.isv_certificate[str_len] = '\0';
        OVSA_DBG(DBG_D, "isv_certificate %s\n", isv_certificate->valuestring);
    }

    signature = cJSON_GetObjectItemCaseSensitive(parse_json, "signature");
    if (cJSON_IsString(signature) && (signature->valuestring != NULL)) {
        memcpy_s(prot_model_sig->signature, strnlen_s(signature->valuestring, MAX_SIGNATURE_SIZE),
                 signature->valuestring, strnlen_s(signature->valuestring, MAX_SIGNATURE_SIZE));
        OVSA_DBG(DBG_D, "signature %s\n", signature->valuestring);
    }

    cJSON* model_files = cJSON_GetObjectItemCaseSensitive(parse_json, "files");
    cJSON_ArrayForEach(file, model_files) {
        snprintf_s_i(fname, 20, "file_name_%d", (i) % 100u);
        cJSON* file_name = cJSON_GetObjectItemCaseSensitive(file, fname);

        snprintf_s_i(fname, 20, "file_body_%d", (i++) % 100u);
        cJSON* file_body = cJSON_GetObjectItemCaseSensitive(file, fname);

        if (cJSON_IsString(file_body) && (file_body->valuestring != NULL) &&
            cJSON_IsString(file_name) && (file_name->valuestring != NULL)) {
            if (head == NULL) {
                /* Memory allocated and this needs to be freed by consumer */
                ret = ovsa_safe_malloc(sizeof(ovsa_enc_models_t), (char**)&head);
                if (ret < OVSA_OK || head == NULL) {
                    OVSA_DBG(DBG_E, "Error: could not allocate memory %d\n", ret);
                    goto end;
                }
                head->enc_model = NULL;
                head->next      = NULL;
                tail            = head;
            } else {
                /* Memory allocated and this needs to be freed by consumer */
                ret = ovsa_safe_malloc(sizeof(ovsa_enc_models_t), (char**)&cur);
                if (ret < OVSA_OK || cur == NULL) {
                    OVSA_DBG(DBG_E, "Error: could not allocate memory %d\n", ret);
                    goto end;
                }
                cur->enc_model = NULL;
                cur->next      = NULL;
                tail->next     = cur;
                tail           = cur;
            }
            /* Memory allocated and this needs to be freed by consumer */
            size_t str_len = 0;
            ret            = ovsa_get_string_length(file_body->valuestring, &str_len);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "Error: Could not get length of file_body string %d\n", ret);
                goto end;
            }
            ret             = ovsa_safe_malloc(str_len + 1, &tail_enc_model);
            tail->enc_model = tail_enc_model;
            if (ret < OVSA_OK || tail->enc_model == NULL) {
                OVSA_DBG(DBG_E, "Error: could not allocate memory %d\n", ret);
                goto end;
            }
            memcpy_s(tail->enc_model, str_len, file_body->valuestring, str_len);
            tail->enc_model[str_len] = '\0';
            memcpy_s(tail->file_name, strnlen_s(file_name->valuestring, MAX_NAME_SIZE),
                     file_name->valuestring, strnlen_s(file_name->valuestring, MAX_NAME_SIZE));
            OVSA_DBG(DBG_D, "%s\n", file_name->valuestring);
        }
    }
    prot_model_sig->protect_model.enc_model = head;

end:
    cJSON_Delete(parse_json);
    OVSA_DBG(DBG_D, "%s exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_json_extract_tcb_signature(const char* inputBuf, ovsa_tcb_sig_t* tsig) {
    ovsa_status_t ret = OVSA_OK;
    cJSON* name       = NULL;
    cJSON* version    = NULL;
#ifndef DISABLE_TPM2_HWQUOTE
    cJSON* hw_quote   = NULL;
    cJSON* hw_pub_key = NULL;
#endif
    cJSON* sw_quote        = NULL;
    cJSON* sw_pub_key      = NULL;
    cJSON* isv_certificate = NULL;
    cJSON* signature       = NULL;
    cJSON* parse_json      = NULL;

    OVSA_DBG(DBG_D, "%s entry\n", __func__);

    if (inputBuf == NULL || tsig == NULL) {
        OVSA_DBG(DBG_E, "Error: Input is null %d\n", ret);
        ret = OVSA_JSON_INVALID_INPUT;
        goto end;
    }

    parse_json = cJSON_Parse(inputBuf);
    if (parse_json == NULL) {
        ret = OVSA_JSON_PARSE_FAIL;
        OVSA_DBG(DBG_E, "Error: could not parse %d\n", ret);
        goto end;
    }

    name = cJSON_GetObjectItemCaseSensitive(parse_json, "name");
    if (cJSON_IsString(name) && (name->valuestring != NULL)) {
        memcpy_s(tsig->tcbinfo.tcb_name, strnlen_s(name->valuestring, MAX_NAME_SIZE),
                 name->valuestring, strnlen_s(name->valuestring, MAX_NAME_SIZE));
        OVSA_DBG(DBG_D, "name %s\n", name->valuestring);
    }

    version = cJSON_GetObjectItemCaseSensitive(parse_json, "version");
    if (cJSON_IsString(version) && (version->valuestring != NULL)) {
        memcpy_s(tsig->tcbinfo.tcb_version, strnlen_s(version->valuestring, MAX_VERSION_SIZE),
                 version->valuestring, strnlen_s(version->valuestring, MAX_VERSION_SIZE));
        OVSA_DBG(DBG_D, "version %s\n", version->valuestring);
    }
#ifndef DISABLE_TPM2_HWQUOTE
    hw_quote = cJSON_GetObjectItemCaseSensitive(parse_json, "HW_Quote_PCR");
    if (cJSON_IsString(hw_quote) && (hw_quote->valuestring != NULL)) {
        size_t str_len = 0;
        ret            = ovsa_get_string_length(hw_quote->valuestring, &str_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Could not get length of HW_quote string %d\n", ret);
            goto end;
        }
        memcpy_s(tsig->tcbinfo.hw_quote, TPM2_QUOTE_SIZE, hw_quote->valuestring, str_len);
        OVSA_DBG(DBG_D, "HW_quote %s\n", hw_quote->valuestring);
    }
    hw_pub_key = cJSON_GetObjectItemCaseSensitive(parse_json, "HW_AK_Pub_Key");
    if (cJSON_IsString(hw_pub_key) && (hw_pub_key->valuestring != NULL)) {
        memcpy_s(tsig->tcbinfo.hw_pub_key, strnlen_s(hw_pub_key->valuestring, TPM2_PUBKEY_SIZE),
                 hw_pub_key->valuestring, strnlen_s(hw_pub_key->valuestring, TPM2_PUBKEY_SIZE));
        OVSA_DBG(DBG_D, "hw_pub_key %s\n", hw_pub_key->valuestring);
    }
#endif
    sw_quote = cJSON_GetObjectItemCaseSensitive(parse_json, "SW_Quote_PCR");
    if (cJSON_IsString(sw_quote) && (sw_quote->valuestring != NULL)) {
        size_t str_len = 0;
        ret            = ovsa_get_string_length(sw_quote->valuestring, &str_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Could not get length of SW_quote string %d\n", ret);
            goto end;
        }
        memcpy_s(tsig->tcbinfo.sw_quote, TPM2_QUOTE_SIZE, sw_quote->valuestring, str_len);
        OVSA_DBG(DBG_D, "SW_quote %s\n", sw_quote->valuestring);
    }
    sw_pub_key = cJSON_GetObjectItemCaseSensitive(parse_json, "SW_AK_Pub_key");
    if (cJSON_IsString(sw_pub_key) && (sw_pub_key->valuestring != NULL)) {
        memcpy_s(tsig->tcbinfo.sw_pub_key, strnlen_s(sw_pub_key->valuestring, TPM2_PUBKEY_SIZE),
                 sw_pub_key->valuestring, strnlen_s(sw_pub_key->valuestring, TPM2_PUBKEY_SIZE));
        OVSA_DBG(DBG_D, "SW_pub_key %s\n", sw_pub_key->valuestring);
    }

    isv_certificate = cJSON_GetObjectItemCaseSensitive(parse_json, "isv_certificate");
    if (cJSON_IsString(isv_certificate) && (isv_certificate->valuestring != NULL)) {
        size_t str_len = 0;
        ret            = ovsa_get_string_length(isv_certificate->valuestring, &str_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Could not get length of isv_certificate string %d\n", ret);
            goto end;
        }
        /* Memory allocated and this needs to be freed by consumer */
        ret = ovsa_safe_malloc(str_len + 1, &tsig->tcbinfo.isv_certificate);
        if (ret < OVSA_OK || tsig->tcbinfo.isv_certificate == NULL) {
            OVSA_DBG(DBG_E, "Error: could not allocate memory %d\n", ret);
            goto end;
        }
        memcpy_s(tsig->tcbinfo.isv_certificate, str_len, isv_certificate->valuestring, str_len);
        tsig->tcbinfo.isv_certificate[str_len] = '\0';
        OVSA_DBG(DBG_D, "isv_certificate %s\n", isv_certificate->valuestring);
    }

    signature = cJSON_GetObjectItemCaseSensitive(parse_json, "signature");
    if (cJSON_IsString(signature) && (signature->valuestring != NULL)) {
        memcpy_s(tsig->signature, strnlen_s(signature->valuestring, MAX_SIGNATURE_SIZE),
                 signature->valuestring, strnlen_s(signature->valuestring, MAX_SIGNATURE_SIZE));
        OVSA_DBG(DBG_D, "signature %s\n", signature->valuestring);
    }

end:
    cJSON_Delete(parse_json);
    OVSA_DBG(DBG_D, "%s exit\n", __func__);
    return ret;
}
#endif

ovsa_status_t ovsa_json_extract_master_license(const char* inputBuf,
                                               ovsa_master_license_sig_t* master_lic_sig) {
    ovsa_status_t ret      = OVSA_OK;
    cJSON* creation_date   = NULL;
    cJSON* isv_certificate = NULL;
    cJSON* model_hash      = NULL;
    cJSON* signature       = NULL;
    cJSON* license_guid    = NULL;
    cJSON* model_guid      = NULL;
    cJSON* encryption_key  = NULL;
    cJSON* parse_json      = NULL;

    OVSA_DBG(DBG_D, "%s entry\n", __func__);

    if (inputBuf == NULL || master_lic_sig == NULL) {
        OVSA_DBG(DBG_E, "Error: Input is null %d\n", ret);
        ret = OVSA_JSON_INVALID_INPUT;
        goto end;
    }

    parse_json = cJSON_Parse(inputBuf);
    if (parse_json == NULL) {
        ret = OVSA_JSON_PARSE_FAIL;
        OVSA_DBG(DBG_E, "Error: could not parse %d\n", ret);
        goto end;
    }

    creation_date = cJSON_GetObjectItemCaseSensitive(parse_json, "creation_date");
    if (cJSON_IsString(creation_date) && (creation_date->valuestring != NULL)) {
        memcpy_s(master_lic_sig->master_lic.creation_date,
                 strnlen_s(creation_date->valuestring, MAX_NAME_SIZE), creation_date->valuestring,
                 strnlen_s(creation_date->valuestring, MAX_NAME_SIZE));
        OVSA_DBG(DBG_D, "creation_date %s\n", creation_date->valuestring);
    }

    isv_certificate = cJSON_GetObjectItemCaseSensitive(parse_json, "isv_certificate");
    if (cJSON_IsString(isv_certificate) && (isv_certificate->valuestring != NULL)) {
        size_t str_len = 0;
        ret            = ovsa_get_string_length(isv_certificate->valuestring, &str_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Could not get length of isv_certificate string %d\n", ret);
            goto end;
        }
        /* Memory allocated and this needs to be freed by consumer */
        ret = ovsa_safe_malloc(str_len + 1, &master_lic_sig->master_lic.isv_certificate);
        if (ret < OVSA_OK || master_lic_sig->master_lic.isv_certificate == NULL) {
            OVSA_DBG(DBG_E, "Error: could not allocate memory %d\n", ret);
            goto end;
        }
        memcpy_s(master_lic_sig->master_lic.isv_certificate, str_len, isv_certificate->valuestring,
                 str_len);
        master_lic_sig->master_lic.isv_certificate[str_len] = '\0';
    }

    model_hash = cJSON_GetObjectItemCaseSensitive(parse_json, "model_hash");
    if (cJSON_IsString(model_hash) && (model_hash->valuestring != NULL)) {
        memcpy_s(master_lic_sig->master_lic.model_hash,
                 strnlen_s(model_hash->valuestring, HASH_SIZE), model_hash->valuestring,
                 strnlen_s(model_hash->valuestring, HASH_SIZE));
        OVSA_DBG(DBG_D, "model_hash %s\n", model_hash->valuestring);
    }

    signature = cJSON_GetObjectItemCaseSensitive(parse_json, "signature");
    if (cJSON_IsString(signature) && (signature->valuestring != NULL)) {
        memcpy_s(master_lic_sig->signature, strnlen_s(signature->valuestring, MAX_SIGNATURE_SIZE),
                 signature->valuestring, strnlen_s(signature->valuestring, MAX_SIGNATURE_SIZE));
        OVSA_DBG(DBG_D, "signature %s\n", master_lic_sig->signature);
    }

    license_guid = cJSON_GetObjectItemCaseSensitive(parse_json, "license_guid");
    if (cJSON_IsString(license_guid) && (license_guid->valuestring != NULL)) {
        memcpy_s(master_lic_sig->master_lic.license_guid,
                 strnlen_s(license_guid->valuestring, GUID_SIZE), license_guid->valuestring,
                 strnlen_s(license_guid->valuestring, GUID_SIZE));
        OVSA_DBG(DBG_D, "license_guid %s\n", license_guid->valuestring);
    }

    model_guid = cJSON_GetObjectItemCaseSensitive(parse_json, "model_guid");
    if (cJSON_IsString(model_guid) && (model_guid->valuestring != NULL)) {
        memcpy_s(master_lic_sig->master_lic.model_guid,
                 strnlen_s(model_guid->valuestring, GUID_SIZE), model_guid->valuestring,
                 strnlen_s(model_guid->valuestring, GUID_SIZE));
        OVSA_DBG(DBG_D, "model_guid %s\n", model_guid->valuestring);
    }

    encryption_key = cJSON_GetObjectItemCaseSensitive(parse_json, "encryption_key");
    if (cJSON_IsString(encryption_key) && (encryption_key->valuestring != NULL)) {
        memcpy_s(master_lic_sig->master_lic.encryption_key,
                 strnlen_s(encryption_key->valuestring, MAX_EKEY_SIZE), encryption_key->valuestring,
                 strnlen_s(encryption_key->valuestring, MAX_EKEY_SIZE));
        OVSA_DBG(DBG_D, "encryption_key %s\n", encryption_key->valuestring);
    }

end:
    cJSON_Delete(parse_json);
    OVSA_DBG(DBG_D, "%s exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_json_extract_element(const char* inputBuf, const char* keyName,
                                        void** keyValue) {
    ovsa_status_t ret = OVSA_OK;
    cJSON* parse_json = NULL;
    cJSON* key        = NULL;

    OVSA_DBG(DBG_D, "%s entry\n", __func__);
    if (inputBuf == NULL || keyName == NULL) {
        ret = OVSA_JSON_INVALID_INPUT;
        OVSA_DBG(DBG_E, "Error: Input parameters invalid %d\n", ret);
        goto end;
    }
    parse_json = cJSON_Parse(inputBuf);
    if (parse_json == NULL) {
        ret = OVSA_JSON_PARSE_FAIL;
        OVSA_DBG(DBG_E, "Error: Json parse failed %d\n", ret);
        goto end;
    }
    key = cJSON_GetObjectItemCaseSensitive(parse_json, keyName);
    if (cJSON_IsString(key) && (key->valuestring != NULL)) {
        size_t str_len = 0;
        ret            = ovsa_get_string_length(key->valuestring, &str_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Could not get length of key string %d\n", ret);
            goto end;
        }
        ret = ovsa_safe_malloc(str_len + 1, (char**)keyValue);
        if (ret < OVSA_OK) {
            ret = OVSA_JSON_MEMORY_ALLOC_FAIL;
            OVSA_DBG(DBG_E, "Error: could not allocate memory %d\n", ret);
            goto end;
        }
        memcpy_s(*keyValue, str_len, key->valuestring, str_len);

    } else if (cJSON_IsNumber(key)) {
        memcpy_s(*keyValue, sizeof(key->valueint), (int*)&key->valueint, sizeof(key->valueint));
    }
end:
    cJSON_Delete(parse_json);
    OVSA_DBG(DBG_D, "%s exit\n", __func__);
    return ret;
}

#ifdef OVSA_RUNTIME
ovsa_status_t ovsa_json_extract_customer_license(const char* inputBuf,
                                                 ovsa_customer_license_sig_t* cust_lic_sig) {
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
    char fname[10];
    ovsa_license_serv_url_list_t* head = NULL;
    ovsa_license_serv_url_list_t* cur  = NULL;
    ovsa_license_serv_url_list_t* tail = NULL;
    ovsa_tcb_sig_list_t* tcb_head      = NULL;
    ovsa_tcb_sig_list_t* tcb_cur       = NULL;
    ovsa_tcb_sig_list_t* tcb_tail      = NULL;
    char* tcb_tail_signature           = NULL;

    OVSA_DBG(DBG_D, "%s entry\n", __func__);

    if (inputBuf == NULL || cust_lic_sig == NULL) {
        OVSA_DBG(DBG_E, "Error: Input is null %d\n", ret);
        ret = OVSA_JSON_INVALID_INPUT;
        goto end;
    }

    parse_json = cJSON_Parse(inputBuf);
    if (parse_json == NULL) {
        ret = OVSA_JSON_PARSE_FAIL;
        OVSA_DBG(DBG_E, "Error: could not parse %d\n", ret);
        goto end;
    }

    creation_date = cJSON_GetObjectItemCaseSensitive(parse_json, "creation_date");
    if (cJSON_IsString(creation_date) && (creation_date->valuestring != NULL)) {
        memcpy_s(cust_lic_sig->customer_lic.creation_date,
                 strnlen_s(creation_date->valuestring, MAX_NAME_SIZE), creation_date->valuestring,
                 strnlen_s(creation_date->valuestring, MAX_NAME_SIZE));
        OVSA_DBG(DBG_D, "creation_date %s\n", creation_date->valuestring);
    }

    isv_certificate = cJSON_GetObjectItemCaseSensitive(parse_json, "isv_certificate");
    if (cJSON_IsString(isv_certificate) && (isv_certificate->valuestring != NULL)) {
        size_t str_len = 0;
        ret            = ovsa_get_string_length(isv_certificate->valuestring, &str_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Could not get length of isv_certificate string %d\n", ret);
            goto end;
        }
        /* Memory allocated and this needs to be freed by consumer */
        ret = ovsa_safe_malloc(str_len + 1, &cust_lic_sig->customer_lic.isv_certificate);
        if (ret < OVSA_OK || cust_lic_sig->customer_lic.isv_certificate == NULL) {
            OVSA_DBG(DBG_E, "Error: could not allocate memory %d\n", ret);
            goto end;
        }
        memcpy_s(cust_lic_sig->customer_lic.isv_certificate, str_len, isv_certificate->valuestring,
                 str_len);
        cust_lic_sig->customer_lic.isv_certificate[str_len] = '\0';
        OVSA_DBG(DBG_D, "isv_certificate %s\n", isv_certificate->valuestring);
    }

    model_hash = cJSON_GetObjectItemCaseSensitive(parse_json, "model_hash");
    if (cJSON_IsString(model_hash) && (model_hash->valuestring != NULL)) {
        memcpy_s(cust_lic_sig->customer_lic.model_hash,
                 strnlen_s(model_hash->valuestring, HASH_SIZE), model_hash->valuestring,
                 strnlen_s(model_hash->valuestring, HASH_SIZE));
        OVSA_DBG(DBG_D, "model_hash %s\n", model_hash->valuestring);
    }

    signature = cJSON_GetObjectItemCaseSensitive(parse_json, "signature");
    if (cJSON_IsString(signature) && (signature->valuestring != NULL)) {
        memcpy_s(cust_lic_sig->signature, strnlen_s(signature->valuestring, MAX_SIGNATURE_SIZE),
                 signature->valuestring, strnlen_s(signature->valuestring, MAX_SIGNATURE_SIZE));
        OVSA_DBG(DBG_D, "signature %s\n", cust_lic_sig->signature);
    }

    name = cJSON_GetObjectItemCaseSensitive(parse_json, "license_name");
    if (cJSON_IsString(name) && (name->valuestring != NULL)) {
        memcpy_s(cust_lic_sig->customer_lic.license_name,
                 strnlen_s(name->valuestring, MAX_NAME_SIZE), name->valuestring,
                 strnlen_s(name->valuestring, MAX_NAME_SIZE));
        OVSA_DBG(DBG_D, "name %s\n", name->valuestring);
    }

    version = cJSON_GetObjectItemCaseSensitive(parse_json, "license_version");
    if (cJSON_IsString(version) && (version->valuestring != NULL)) {
        memcpy_s(cust_lic_sig->customer_lic.license_version,
                 strnlen_s(version->valuestring, MAX_VERSION_SIZE), version->valuestring,
                 strnlen_s(version->valuestring, MAX_VERSION_SIZE));
        OVSA_DBG(DBG_D, "version %s\n", version->valuestring);
    }

    license_guid = cJSON_GetObjectItemCaseSensitive(parse_json, "license_guid");
    if (cJSON_IsString(license_guid) && (license_guid->valuestring != NULL)) {
        memcpy_s(cust_lic_sig->customer_lic.license_guid,
                 strnlen_s(license_guid->valuestring, GUID_SIZE), license_guid->valuestring,
                 strnlen_s(license_guid->valuestring, GUID_SIZE));
        OVSA_DBG(DBG_D, "license_guid %s\n", license_guid->valuestring);
    }

    model_guid = cJSON_GetObjectItemCaseSensitive(parse_json, "model_guid");
    if (cJSON_IsString(model_guid) && (model_guid->valuestring != NULL)) {
        memcpy_s(cust_lic_sig->customer_lic.model_guid,
                 strnlen_s(model_guid->valuestring, GUID_SIZE), model_guid->valuestring,
                 strnlen_s(model_guid->valuestring, GUID_SIZE));
        OVSA_DBG(DBG_D, "model_guid %s\n", model_guid->valuestring);
    }

    encryption_key = cJSON_GetObjectItemCaseSensitive(parse_json, "encryption_key");
    if (cJSON_IsString(encryption_key) && (encryption_key->valuestring != NULL)) {
        memcpy_s(cust_lic_sig->customer_lic.encryption_key,
                 strnlen_s(encryption_key->valuestring, MAX_EKEY_SIZE), encryption_key->valuestring,
                 strnlen_s(encryption_key->valuestring, MAX_EKEY_SIZE));
        OVSA_DBG(DBG_D, "encryption_key %s\n", encryption_key->valuestring);
    }

    cJSON* svrurl = cJSON_GetObjectItemCaseSensitive(parse_json, "license_serv_url");
    if (svrurl) {
        cJSON* device = svrurl->child;
        i             = 0;
        while (device) {
            snprintf_s_i(fname, 10, "url_%d", (i++) % 100u);
            cJSON* url = cJSON_GetObjectItemCaseSensitive(svrurl, fname);
            if (head == NULL) {
                /* Memory allocated and this needs to be freed by consumer */
                ret = ovsa_safe_malloc(sizeof(ovsa_license_serv_url_list_t), (char**)&head);
                if (ret < OVSA_OK || head == NULL) {
                    OVSA_DBG(DBG_E, "Error: could not allocate memory %d\n", ret);
                    goto end;
                }
                head->next = NULL;
                tail       = head;
            } else {
                /* Memory allocated and this needs to be freed by consumer */
                ret = ovsa_safe_malloc(sizeof(ovsa_license_serv_url_list_t), (char**)&cur);
                if (ret < OVSA_OK || cur == NULL) {
                    OVSA_DBG(DBG_E, "Error: could not allocate memory %d\n", ret);
                    goto end;
                }
                cur->next  = NULL;
                tail->next = cur;
                tail       = cur;
            }
            if (cJSON_IsString(url) && (url->valuestring != NULL)) {
                memcpy_s(tail->license_serv_url, strnlen_s(url->valuestring, MAX_URL_SIZE),
                         url->valuestring, strnlen_s(url->valuestring, MAX_URL_SIZE));
                OVSA_DBG(DBG_D, "%s\n", fname);
            }
            device = device->next;
        }
    }
    cust_lic_sig->customer_lic.license_url_list = head;

    license_type = cJSON_GetObjectItemCaseSensitive(parse_json, "license_type");
    if (cJSON_IsString(license_type) && (license_type->valuestring != NULL)) {
        cust_lic_sig->customer_lic.license_type =
            ovsa_json_map_license_type(license_type->valuestring);
        OVSA_DBG(DBG_D, "license_type %s\n", license_type->valuestring);
    }

    usage_count = cJSON_GetObjectItemCaseSensitive(parse_json, "usage_count");
    if (cJSON_IsNumber(usage_count)) {
        cust_lic_sig->customer_lic.usage_count = usage_count->valueint;
        OVSA_DBG(DBG_D, "usage_count %d\n", usage_count->valueint);
    }

    time_limit = cJSON_GetObjectItemCaseSensitive(parse_json, "time_limit");
    if (cJSON_IsNumber(time_limit)) {
        cust_lic_sig->customer_lic.time_limit = time_limit->valueint;
        OVSA_DBG(DBG_D, "time_limit %d\n", time_limit->valueint);
    }
    cJSON* tcb_sig = cJSON_GetObjectItemCaseSensitive(parse_json, "tcb_signature");
    if (tcb_sig) {
        cJSON* device = tcb_sig->child;
        i             = 0;
        while (device) {
            snprintf_s_i(fname, 10, "sig_%d", (i++) % 100u);
            cJSON* sig = cJSON_GetObjectItemCaseSensitive(tcb_sig, fname);
            if (tcb_head == NULL) {
                /* Memory allocated and this needs to be freed by consumer */
                ret = ovsa_safe_malloc(sizeof(ovsa_tcb_sig_list_t), (char**)&tcb_head);
                if (ret < OVSA_OK || tcb_head == NULL) {
                    OVSA_DBG(DBG_E, "Error: could not allocate memory %d\n", ret);
                    goto end;
                }
                tcb_head->next = NULL;
                tcb_tail       = tcb_head;
            } else {
                /* Memory allocated and this needs to be freed by consumer */
                ret = ovsa_safe_malloc(sizeof(ovsa_tcb_sig_list_t), (char**)&tcb_cur);
                if (ret < OVSA_OK || tcb_cur == NULL) {
                    OVSA_DBG(DBG_E, "Error: could not allocate memory %d\n", ret);
                    goto end;
                }
                tcb_cur->next  = NULL;
                tcb_tail->next = tcb_cur;
                tcb_tail       = tcb_cur;
            }
            if (cJSON_IsString(sig) && (sig->valuestring != NULL)) {
                size_t str_len = 0;
                ret            = ovsa_get_string_length(sig->valuestring, &str_len);
                if (ret < OVSA_OK) {
                    OVSA_DBG(DBG_E, "Error: Could not get length of signature string %d\n", ret);
                    goto end;
                }
                /* Memory allocated and this needs to be freed by consumer */
                ret                     = ovsa_safe_malloc(str_len + 1, &tcb_tail_signature);
                tcb_tail->tcb_signature = tcb_tail_signature;
                if (ret < OVSA_OK || tcb_tail->tcb_signature == NULL) {
                    OVSA_DBG(DBG_E, "Error: could not allocate memory %d\n", ret);
                    goto end;
                }
                memcpy_s(tcb_tail->tcb_signature, str_len, sig->valuestring, str_len);
                tcb_tail->tcb_signature[str_len] = '\0';
                OVSA_DBG(DBG_D, "%s\n", fname);
            }
            device = device->next;
        }
    }
    cust_lic_sig->customer_lic.tcb_signatures = tcb_head;
end:
    cJSON_Delete(parse_json);
    OVSA_DBG(DBG_D, "%s exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_append_json_payload_len_to_blob(const char* input_buf, char** json_payload) {
    ovsa_status_t ret         = OVSA_OK;
    uint64_t json_payload_len = 0;
    char payload_len[PAYLOAD_LENGTH + 1];

    memset_s(payload_len, sizeof(payload_len), 0);
    ret = ovsa_get_string_length(input_buf, &json_payload_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of input_buf string %d\n", ret);
        return ret;
    }
    snprintf_s_l(payload_len, (PAYLOAD_LENGTH + 1), "%08ld", json_payload_len);
    strcpy_s(*json_payload, RSIZE_MAX_STR, payload_len);
    strcat(*json_payload, input_buf);
    return ret;
}

ovsa_status_t ovsa_json_create_message_blob(ovsa_command_type_t cmdtype, const char* payload,
                                            char** outputBuf, size_t* valuelen) {
    ovsa_status_t ret = OVSA_OK;
    cJSON* message    = NULL;
    size_t len        = 0;
    char command[MAX_COMMAND_TYPE_LENGTH];
    char* str_print = NULL;

    OVSA_DBG(DBG_D, "%s entry\n", __func__);
    if (cmdtype < 0 || payload == NULL) {
        ret = OVSA_JSON_INVALID_INPUT;
        OVSA_DBG(DBG_E, "Error: Input parameters invalid %d\n", ret);
        goto end;
    }
    memset_s(command, sizeof(command), 0);

    if (cmdtype == OVSA_SEND_SIGN_NONCE) {
        memcpy_s(command, strnlen_s("OVSA_SEND_SIGN_NONCE", RSIZE_MAX_STR), "OVSA_SEND_SIGN_NONCE",
                 strnlen_s("OVSA_SEND_SIGN_NONCE", RSIZE_MAX_STR));
    } else if (cmdtype == OVSA_SEND_HW_QUOTE) {
        memcpy_s(command, strnlen_s("OVSA_SEND_HW_QUOTE", RSIZE_MAX_STR), "OVSA_SEND_HW_QUOTE",
                 strnlen_s("OVSA_SEND_HW_QUOTE", RSIZE_MAX_STR));
    } else if (cmdtype == OVSA_SEND_QUOTE_INFO) {
        memcpy_s(command, strnlen_s("OVSA_SEND_QUOTE_INFO", RSIZE_MAX_STR), "OVSA_SEND_QUOTE_INFO",
                 strnlen_s("OVSA_SEND_QUOTE_INFO", RSIZE_MAX_STR));
    } else if (cmdtype == OVSA_SEND_EK_AK_BIND_INFO) {
        memcpy_s(command, strnlen_s("OVSA_SEND_EK_AK_BIND_INFO", RSIZE_MAX_STR),
                 "OVSA_SEND_EK_AK_BIND_INFO",
                 strnlen_s("OVSA_SEND_EK_AK_BIND_INFO", RSIZE_MAX_STR));
    } else if (cmdtype == OVSA_SEND_CUST_LICENSE) {
        memcpy_s(command, strnlen_s("OVSA_SEND_CUST_LICENSE", RSIZE_MAX_STR),
                 "OVSA_SEND_CUST_LICENSE", strnlen_s("OVSA_SEND_CUST_LICENSE", RSIZE_MAX_STR));
    } else {
        OVSA_DBG(DBG_E, "Error: json message command not valid \n");
        goto end;
    }

    /* Create json object */
    message = cJSON_CreateObject();
    if (message == NULL) {
        ret = OVSA_JSON_ERROR_CREATE_OBJECT;
        OVSA_DBG(DBG_E, "Error: Create create_send_nonce_message failed %d\n", ret);
        goto end;
    }

    /* Populate the json */
    if (cJSON_AddStringToObject(message, "command", command) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add command to message info failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(message, "payload", (char*)payload) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add payload to json failed %d\n", ret);
        goto end;
    }

    str_print = cJSON_Print(message);
    if (str_print == NULL) {
        ret = OVSA_JSON_PRINT_FAIL;
        OVSA_DBG(DBG_E, "Error: Print message json to buffer failed %d\n", ret);
        goto end;
    }
    ret = ovsa_get_string_length(str_print, &len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of string %d\n", ret);
        goto end;
    }
    /* For NULL termination */
    len = len + 1;
    ret = ovsa_safe_malloc(len, (char**)outputBuf);
    if (ret < OVSA_OK || *outputBuf == NULL) {
        OVSA_DBG(DBG_E, "Error: could not allocate memory %d\n", ret);
        goto end;
    }
    *valuelen = len;
    memcpy_s(*outputBuf, len, str_print, len);

end:
    cJSON_Delete(message);
    ovsa_safe_free(&str_print);
    OVSA_DBG(DBG_D, "%s exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_json_create_EK_AK_binding_info_blob(ovsa_sw_ek_ak_bind_info_t sw_ek_ak_bind_info,
                                                       char** outputBuf, size_t* valuelen) {
    ovsa_status_t ret = OVSA_OK;
    cJSON* message    = NULL;
    size_t len        = 0;
    char* str_print   = NULL;

    OVSA_DBG(DBG_D, "%s entry\n", __func__);

    /* Create json object */
    message = cJSON_CreateObject();
    if (message == NULL) {
        ret = OVSA_JSON_ERROR_CREATE_OBJECT;
        OVSA_DBG(DBG_E, "Error: Create json message object failed %d\n", ret);
        goto end;
    }
    /* Populate the json */
    if (sw_ek_ak_bind_info.sw_ek_cert == NULL) {
        if (cJSON_AddStringToObject(message, "EK_cert", "") == NULL) {
            ret = OVSA_JSON_ERROR_ADD_ELEMENT;
            OVSA_DBG(DBG_E, "Error: Add EK_cert to message info failed %d\n", ret);
            goto end;
        }
        if (cJSON_AddStringToObject(message, "EKcert_signature", "") == NULL) {
            ret = OVSA_JSON_ERROR_ADD_ELEMENT;
            OVSA_DBG(DBG_E, "Error: Add EKcert_signature to json failed %d\n", ret);
            goto end;
        }
        if (cJSON_AddStringToObject(message, "EK_pub", sw_ek_ak_bind_info.sw_ek_pub_key) == NULL) {
            ret = OVSA_JSON_ERROR_ADD_ELEMENT;
            OVSA_DBG(DBG_E, "Error: Add EK_pub to message info failed %d\n", ret);
            goto end;
        }
        if (cJSON_AddStringToObject(message, "EKpub_signature", sw_ek_ak_bind_info.sw_ek_pub_sig) ==
            NULL) {
            ret = OVSA_JSON_ERROR_ADD_ELEMENT;
            OVSA_DBG(DBG_E, "Error: Add EKpub_signature to json failed %d\n", ret);
            goto end;
        }
    } else {
        if (cJSON_AddStringToObject(message, "EK_cert", sw_ek_ak_bind_info.sw_ek_cert) == NULL) {
            ret = OVSA_JSON_ERROR_ADD_ELEMENT;
            OVSA_DBG(DBG_E, "Error: Add EK_cert to message info failed %d\n", ret);
            goto end;
        }
        if (cJSON_AddStringToObject(message, "EKcert_signature",
                                    sw_ek_ak_bind_info.sw_ek_cert_sig) == NULL) {
            ret = OVSA_JSON_ERROR_ADD_ELEMENT;
            OVSA_DBG(DBG_E, "Error: Add EKcert_signature to json failed %d\n", ret);
            goto end;
        }
        if (cJSON_AddStringToObject(message, "EK_pub", "") == NULL) {
            ret = OVSA_JSON_ERROR_ADD_ELEMENT;
            OVSA_DBG(DBG_E, "Error: Add EK_pub to message info failed %d\n", ret);
            goto end;
        }
        if (cJSON_AddStringToObject(message, "EKpub_signature", "") == NULL) {
            ret = OVSA_JSON_ERROR_ADD_ELEMENT;
            OVSA_DBG(DBG_E, "Error: Add EKpub_signature to json failed %d\n", ret);
            goto end;
        }
    }
    if (cJSON_AddStringToObject(message, "AKpub", sw_ek_ak_bind_info.sw_ak_pub_key) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add AKpub to message info failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(message, "AK_name", sw_ek_ak_bind_info.sw_ak_name) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add AK_name to json failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(message, "certificate", sw_ek_ak_bind_info.platform_cert) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add certificate to json failed %d\n", ret);
        goto end;
    }
    str_print = cJSON_Print(message);
    if (str_print == NULL) {
        ret = OVSA_JSON_PRINT_FAIL;
        OVSA_DBG(DBG_E, "Error: Print message json to buffer failed %d\n", ret);
        goto end;
    }
    ret = ovsa_get_string_length(str_print, &len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of string %d\n", ret);
        goto end;
    }
    /* For NULL termination */
    len = len + 1;
    ret = ovsa_safe_malloc(len, (char**)outputBuf);
    if (ret < OVSA_OK || *outputBuf == NULL) {
        OVSA_DBG(DBG_E, "Error: could not allocate memory %d\n", ret);
        goto end;
    }
    *valuelen = len;
    memcpy_s(*outputBuf, len, str_print, len);

end:
    cJSON_Delete(message);
    ovsa_safe_free(&str_print);
    OVSA_DBG(DBG_D, "%s exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_json_create_quote_info_blob(const char* secret,
                                               const ovsa_quote_info_t sw_quote_info,
                                               const ovsa_quote_info_t hw_quote_info,
                                               char** outputBuf, size_t* valuelen) {
    ovsa_status_t ret = OVSA_OK;
    cJSON* message    = NULL;
    size_t len        = 0;
    char* str_print   = NULL;

    OVSA_DBG(DBG_D, "%s entry\n", __func__);
    if (secret == NULL) {
        ret = OVSA_JSON_INVALID_INPUT;
        OVSA_DBG(DBG_E, "Error: Input parameters invalid %d\n", ret);
        goto end;
    }
    /* Create json object */
    message = cJSON_CreateObject();
    if (message == NULL) {
        ret = OVSA_JSON_ERROR_CREATE_OBJECT;
        OVSA_DBG(DBG_E, "Error: Create json message object failed %d\n", ret);
        goto end;
    }
    /* Populate the json */
    if (cJSON_AddStringToObject(message, "Secret", secret) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add secret to message info failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(message, "SW_Quote_MSG", sw_quote_info.quote_message) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add SW_Quote_MSG to message info failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(message, "SW_Quote_SIG", sw_quote_info.quote_sig) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add SW_Quote_SIG to json failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(message, "SW_Quote_PCR", sw_quote_info.quote_pcr) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add SW_Quote_PCR to json failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(message, "SW_AK_Pub_key", sw_quote_info.ak_pub_key) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add SW_AK_Pub_key to json failed %d\n", ret);
        goto end;
    }
#ifndef DISABLE_TPM2_HWQUOTE
    if (cJSON_AddStringToObject(message, "HW_Quote_MSG", hw_quote_info.quote_message) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add HW_Quote_MSG to message info failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(message, "HW_Quote_SIG", hw_quote_info.quote_sig) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add HW_Quote_SIG to json failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(message, "HW_Quote_PCR", hw_quote_info.quote_pcr) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add HW_Quote_PCR to json failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(message, "HW_AK_Pub_Key", hw_quote_info.ak_pub_key) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add HW_AK_Pub_Key to json failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(message, "HW_EK_Cert", hw_quote_info.ek_cert) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add HW_EK_Cert to json failed %d\n", ret);
        goto end;
    }
#endif
    str_print = cJSON_Print(message);
    if (str_print == NULL) {
        ret = OVSA_JSON_PRINT_FAIL;
        OVSA_DBG(DBG_E, "Error: Print message json to buffer failed %d\n", ret);
        goto end;
    }
    ret = ovsa_get_string_length(str_print, &len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of string %d\n", ret);
        goto end;
    }
    /* For NULL termination */
    len = len + 1;
    ret = ovsa_safe_malloc(len, (char**)outputBuf);
    if (ret < OVSA_OK || *outputBuf == NULL) {
        OVSA_DBG(DBG_E, "Error: could not allocate memory %d\n", ret);
        goto end;
    }
    *valuelen = len;
    memcpy_s(*outputBuf, len, str_print, len);

end:
    cJSON_Delete(message);
    ovsa_safe_free(&str_print);
    OVSA_DBG(DBG_D, "%s exit\n", __func__);
    return ret;
}
#endif
