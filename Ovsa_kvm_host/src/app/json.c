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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "ovsa.h"
#include "safe_mem_lib.h"
#include "safe_str_lib.h"
#include "snprintf_s.h"
#include "utils.h"

ovsa_status_t ovsa_json_create_hw_quote_info(ovsa_hw_quote_info_t* quote_info, char** outputBuf) {
    ovsa_status_t ret = OVSA_OK;
    cJSON* message    = NULL;
    size_t len        = 0;
    char* str_print   = NULL;

    /* create json object */
    message = cJSON_CreateObject();
    if (message == NULL) {
        ret = OVSA_JSON_ERROR_CREATE_OBJECT;
        OVSA_DBG(DBG_E, "Error: Create create_send_nonce_message failed %d\n", ret);
        goto end;
    }
    /* populate the json */
    if (cJSON_AddStringToObject(message, "HW_Quote_MSG", quote_info->hw_quote_message) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add HW_Quote_MSG to message info failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(message, "HW_Quote_SIG", quote_info->hw_quote_sig) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add HW_Quote_SIG to message info failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(message, "HW_Quote_PCR", quote_info->hw_quote_pcr) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add HW_Quote_PCR to message info failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(message, "HW_AK_Pub_Key", quote_info->hw_ak_pub_key) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add HW_AK_Pub_Key to message info failed %d\n", ret);
        goto end;
    }
    if (cJSON_AddStringToObject(message, "HW_EK_Pub_Key", quote_info->hw_ek_pub_key) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "Error: Add HW_EK_Pub_Key to message info failed %d\n", ret);
        goto end;
    }

    if (quote_info->hw_ek_cert == NULL) {
        if (cJSON_AddStringToObject(message, "HW_EK_Cert", "") == NULL) {
            ret = OVSA_JSON_ERROR_ADD_ELEMENT;
            OVSA_DBG(DBG_E, "Error: Add HW_EK_Cert to message info failed %d\n", ret);
            goto end;
        }
    } else {
        if (cJSON_AddStringToObject(message, "HW_EK_Cert", quote_info->hw_ek_cert) == NULL) {
            ret = OVSA_JSON_ERROR_ADD_ELEMENT;
            OVSA_DBG(DBG_E, "Error: Add HW_EK_Cert to message info failed %d\n", ret);
            goto end;
        }
    }
    str_print = cJSON_Print(message);
    if (str_print == NULL) {
        ret = OVSA_JSON_PRINT_FAIL;
        OVSA_DBG(DBG_E, "Error: Print json to buffer failed %d\n", ret);
        goto end;
    }
    ret = ovsa_get_string_length(str_print, &len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of string %d\n", ret);
        goto end;
    }
    len = len + 1;
    ret = ovsa_safe_malloc(len, (char**)outputBuf);
    if (ret < OVSA_OK || *outputBuf == NULL) {
        OVSA_DBG(DBG_E, "Error: could not allocate memory %d\n", ret);
        goto end;
    }
    memcpy_s(*outputBuf, len, str_print, len);
end:
    cJSON_Delete(message);
    ovsa_safe_free(&str_print);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);

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

ovsa_status_t ovsa_json_create_message_blob(ovsa_host_cmd_t cmdtype, const char* payload,
                                            char** outputBuf, size_t* length) {
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

    if (cmdtype == OVSA_SEND_HW_QUOTE) {
        memcpy_s(command, strnlen_s("OVSA_SEND_HW_QUOTE", RSIZE_MAX_STR), "OVSA_SEND_HW_QUOTE",
                 strnlen_s("OVSA_SEND_HW_QUOTE", RSIZE_MAX_STR));
    } else {
        OVSA_DBG(DBG_E, "Error: json message command not valid \n");
        goto end;
    }

    /* create json object */
    message = cJSON_CreateObject();
    if (message == NULL) {
        ret = OVSA_JSON_ERROR_CREATE_OBJECT;
        OVSA_DBG(DBG_E, "Error: Create create_send_nonce_message failed %d\n", ret);
        goto end;
    }

    /* populate the json */
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
    len = len + 1;
    ret = ovsa_safe_malloc(len, (char**)outputBuf);
    if (ret < OVSA_OK || *outputBuf == NULL) {
        OVSA_DBG(DBG_E, "Error: could not allocate memory %d\n", ret);
        goto end;
    }
    *length = len;
    memcpy_s(*outputBuf, len, str_print, len);

end:
    cJSON_Delete(message);
    ovsa_safe_free(&str_print);
    OVSA_DBG(DBG_D, "%s exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_append_json_payload_len_to_blob(char* input_buf, char** json_payload) {
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
