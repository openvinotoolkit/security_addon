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

#include "utils.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "license_service.h"
#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "safe_str_lib.h"

ovsa_status_t ovsa_license_service_safe_add(size_t* var1, size_t var2) {
    ovsa_status_t ret = OVSA_OK;

    if (*var1 >= 0) {
        if (var2 > SIZE_MAX - *var1) {
            /* overflow */
            OVSA_DBG(DBG_E, "OVSA: Error integer overflow detected\n");
            ret = OVSA_INTEGER_OVERFLOW;
            goto out;
        }
    } else {
        if (var2 < INT_MIN - *var1) {
            /* underflow */
            OVSA_DBG(DBG_E, "OVSA: Error integer underflow detected\n");
            ret = OVSA_INTEGER_UNDERFLOW;
            goto out;
        }
    }
    *var1 = *var1 + var2;

out:
    return ret;
}

ovsa_status_t ovsa_license_service_get_string_length(const char* in_buff, size_t* in_buff_len) {
    ovsa_status_t ret = OVSA_OK;
    size_t total_len = 0, buff_len = 0;

    if (in_buff == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error getting string length failed with invalid parameter\n");
        ret = OVSA_INVALID_PARAMETER;
        return ret;
    }

    buff_len = strnlen_s(in_buff, RSIZE_MAX_STR);
    if (buff_len < RSIZE_MAX_STR) {
        *in_buff_len = buff_len;
    } else {
        while (buff_len == RSIZE_MAX_STR) {
            ret = ovsa_license_service_safe_add(&total_len, RSIZE_MAX_STR);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "OVSA: Error ovsa_safe_add failed %d\n", ret);
                return ret;
            }
            buff_len = strnlen_s((in_buff + total_len), RSIZE_MAX_STR);
            if (buff_len < RSIZE_MAX_STR) {
                ret = ovsa_license_service_safe_add(&total_len, buff_len);
                if (ret < OVSA_OK) {
                    OVSA_DBG(DBG_E, "OVSA: Error ovsa_safe_add failed %d\n", ret);
                    return ret;
                }
                break;
            }
        }
        *in_buff_len = total_len;
    }
    return ret;
}
ovsa_status_t ovsa_license_service_safe_malloc(size_t size, char** aloc_buf) {
    ovsa_status_t ret = OVSA_OK;

    *aloc_buf = (char*)malloc(size * sizeof(char));
    if (*aloc_buf == NULL) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error buffer allocation failed with code %d\n", ret);
        goto out;
    }
    memset_s(*aloc_buf, (size) * sizeof(char), 0);
out:
    return ret;
}

void ovsa_license_service_safe_free(char** ptr) {
    if (*ptr != NULL) {
        free(*ptr);
        *ptr = NULL;
    }

    return;
}

void ovsa_license_service_safe_free_url_list(ovsa_license_serv_url_list_t** lhead) {
    ovsa_license_serv_url_list_t* head = NULL;
    ovsa_license_serv_url_list_t* cur  = NULL;
    head                               = *lhead;
    while (head != NULL) {
        cur = head->next;
        ovsa_license_service_safe_free((char**)&head);
        head = cur;
    }
    *lhead = NULL;
}

void ovsa_license_service_safe_free_tcb_list(ovsa_tcb_sig_list_t** listhead) {
    ovsa_tcb_sig_list_t* head = NULL;
    ovsa_tcb_sig_list_t* cur  = NULL;
    head                      = *listhead;
    while (head != NULL) {
        cur = head->next;
        ovsa_license_service_safe_free(&head->tcb_signature);
        ovsa_license_service_safe_free((char**)&head);
        head = cur;
    }
    *listhead = NULL;
}

void ovsa_license_service_mem(const void* data, size_t size) {
    uint8_t* ptr = (uint8_t*)data;
    for (size_t i = 0; i < size; i++) OVSA_DBG(DBG_D, "%02x", ptr[i]);
}

ovsa_status_t ovsa_license_service_string_concat(const char* in_buff, char** out_buff) {
    ovsa_status_t ret = OVSA_OK;
    size_t buff_len   = 0;
    char* cur_buff    = NULL;
    size_t len        = 0;

    if ((in_buff == NULL) || (*out_buff == NULL)) {
        OVSA_DBG(DBG_E, "OVSA: Error do string concat failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }
    cur_buff = *out_buff;
    buff_len = strnlen_s(in_buff, RSIZE_MAX_STR);
    if (buff_len < RSIZE_MAX_STR) {
        strcat_s(*out_buff, RSIZE_MAX_STR, in_buff);
    } else {
        while (buff_len == RSIZE_MAX_STR) {
            len = strnlen_s(cur_buff, RSIZE_MAX_STR);
            cur_buff += len;
            memcpy_s(cur_buff, RSIZE_MAX_STR, in_buff, buff_len);
            in_buff += RSIZE_MAX_STR;
            cur_buff += RSIZE_MAX_STR;
            buff_len = strnlen_s(in_buff, RSIZE_MAX_STR);
            if (buff_len < RSIZE_MAX_STR) {
                strcat_s(cur_buff, RSIZE_MAX_STR, in_buff);
                break;
            }
        }
    }
    return ret;
}
ovsa_status_t ovsa_license_service_append_payload_len_to_blob(const char* input_buf,
                                                              char** json_payload) {
    ovsa_status_t ret         = OVSA_OK;
    uint64_t json_payload_len = 0;
    unsigned char payload_len[PAYLOAD_LENGTH + 1];
    size_t size = 0;
    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    memset_s(payload_len, sizeof(payload_len), 0);
    ret = ovsa_license_service_get_string_length(input_buf, &json_payload_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of input_buf string %d\n", ret);
        return ret;
    }
    snprintf(payload_len, (PAYLOAD_LENGTH + 1), "%08ld", json_payload_len);
    size = strnlen_s(payload_len, RSIZE_MAX_STR) + 1;
    strcpy_s(*json_payload, size, payload_len);
    /*concatenate input_buf and json_payload*/
    ret = ovsa_license_service_string_concat(input_buf, json_payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error string concat failed with error code %d\n", ret);
        return ret;
    }
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_license_service_read_file_content(const char* filename, char** filecontent,
                                                     size_t* filesize) {
    ovsa_status_t ret = OVSA_OK;
    size_t file_size  = 0;
    FILE* fptr        = NULL;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    if (filename == NULL || filesize == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error invalid parameter while reading Quote info\n");
        ret = OVSA_INVALID_PARAMETER;
        goto out;
    }

    fptr = fopen(filename, "rb");
    if (fptr == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error opening file %s failed with code %d\n", filename, ret);
        goto out;
    }

    ret = ovsa_license_service_crypto_get_file_size(fptr, &file_size);
    if (ret < OVSA_OK || file_size == 0) {
        OVSA_DBG(DBG_E, "OVSA: Error getting file size for %s failed\n", filename);
        ret = OVSA_FILEIO_FAIL;
        fclose(fptr);
        goto out;
    }

    ret = ovsa_license_service_safe_malloc((sizeof(char) * file_size), filecontent);
    if ((ret < OVSA_OK) || (*filecontent == NULL)) {
        OVSA_DBG(DBG_E, "OVSA: Error PCR quote buffer allocation failed %d\n", ret);
        fclose(fptr);
        goto out;
    }

    if (!fread(*filecontent, 1, file_size - 1, fptr)) {
        OVSA_DBG(DBG_E, "OVSA: Error reading pcr quote failed %d\n", ret);
        ret = OVSA_FILEIO_FAIL;
        fclose(fptr);
        goto out;
    }
    fclose(fptr);
    *filesize = file_size;
out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_license_service_crypto_get_file_size(FILE* fp, size_t* filesize) {
    size_t fsize      = 0;
    ovsa_status_t ret = OVSA_FILEIO_FAIL;
    *filesize         = 0;

    if (fp == NULL) {
        BIO_printf(g_bio_err, "OVSA: Error getting file size failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    if (!(fseek(fp, 0L, SEEK_END) == 0)) {
        BIO_printf(g_bio_err,
                   "OVSA: Error getting file size failed in setting the fp to "
                   "end of the file\n");
        goto end;
    }

    fsize = ftell(fp);
    if (fsize == 0) {
        BIO_printf(g_bio_err, "OVSA: Error file size is zero\n");
        goto end;
    }

    if (fseek(fp, 0L, SEEK_SET) != 0) {
        BIO_printf(g_bio_err,
                   "OVSA: Error getting file size failed in setting the fp to "
                   "beginning of the file\n");
        goto end;
    }

    *filesize = fsize + NULL_TERMINATOR;
    ret       = OVSA_OK;
end:
    if (!ret) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}
