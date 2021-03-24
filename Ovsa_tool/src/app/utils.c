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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "libovsa.h"
#include "safe_mem_lib.h"
#include "safe_str_lib.h"
/* utils.h to be included at end due to dependencies */
#include "utils.h"

bool ovsa_check_if_file_exists(const char* filename) {
    if (access(filename, F_OK) != -1)
        return true;
    else
        return false;
}

ovsa_status_t ovsa_read_file_content(const char* filename, char** filecontent, size_t* filesize) {
    ovsa_status_t ret = OVSA_OK;
    size_t file_size  = 0;
    FILE* fptr        = NULL;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    if (filename == NULL || filesize == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error invalid input parameter\n");
        ret = OVSA_INVALID_PARAMETER;
        goto out;
    }

    fptr = fopen(filename, "rb");
    if (fptr == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error opening file %s failed with code %d\n", filename, ret);
        goto out;
    }

    file_size = ovsa_crypto_get_file_size(fptr);
    if (file_size == 0) {
        OVSA_DBG(DBG_E, "OVSA: Error getting file size for %s failed\n", filename);
        ret = OVSA_FILEIO_FAIL;
        fclose(fptr);
        goto out;
    }

    ret = ovsa_safe_malloc((sizeof(char) * file_size), filecontent);
    if ((ret < OVSA_OK) || (*filecontent == NULL)) {
        OVSA_DBG(DBG_E, "OVSA: Error memory allocation failed %d\n", ret);
        fclose(fptr);
        goto out;
    }

    if (!fread(*filecontent, 1, file_size - 1, fptr)) {
        OVSA_DBG(DBG_E, "OVSA: Error in reading file content%d\n", ret);
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

bool ovsa_is_guid_valid(unsigned char* guid) {
    unsigned int i;

    /* Check GUID is valid */
    for (i = 0; i < GUID_SIZE; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (guid[i] != '-')
                return false;
        } else if (!isxdigit(guid[i])) {
            return false;
        }
    }
    return true;
}

void ovsa_safe_free(char** ptr) {
    size_t ptr_len = 0;

    if (*ptr != NULL) {
        ovsa_get_string_length(*ptr, &ptr_len);
        memset_s(*ptr, ptr_len, 0);
        free(*ptr);
        *ptr = NULL;
    }

    return;
}

ovsa_status_t ovsa_safe_malloc(size_t size, char** aloc_buf) {
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

ovsa_status_t ovsa_store_license_url_list(char* optarg, ovsa_license_serv_url_list_t** listhead,
                                          ovsa_license_serv_url_list_t** listtail) {
    ovsa_status_t ret                  = OVSA_OK;
    ovsa_license_serv_url_list_t* cur  = NULL;
    ovsa_license_serv_url_list_t* head = NULL;
    ovsa_license_serv_url_list_t* tail = NULL;

    if (optarg != NULL)
        OVSA_DBG(DBG_D, "LicGen: Arg is %s\n", optarg);

    tail = *listtail;

    if (*listhead == NULL) {
        ret = ovsa_safe_malloc(sizeof(ovsa_license_serv_url_list_t), (char**)&head);
        if (ret < OVSA_OK || head == NULL) {
            OVSA_DBG(DBG_E, "OVSA: Error init URL list failed\n");
            goto out;
        }
        head->next = NULL;
        memset_s(head->license_serv_url, MAX_URL_SIZE, 0);
        memcpy_s(head->license_serv_url, MAX_URL_SIZE, optarg, strnlen_s(optarg, MAX_URL_SIZE));
        OVSA_DBG(DBG_D, "LicGen: head->license_serv_url is %s\n", head->license_serv_url);
        *listhead = head;
        *listtail = head;
    } else {
        ret = ovsa_safe_malloc(sizeof(ovsa_license_serv_url_list_t), (char**)&cur);
        if (ret < OVSA_OK || cur == NULL) {
            OVSA_DBG(DBG_E, "OVSA: Error init URL list failed\n");
            goto out;
        }
        cur->next = NULL;
        memset_s(cur->license_serv_url, MAX_URL_SIZE, 0);
        memcpy_s(cur->license_serv_url, MAX_URL_SIZE, optarg, strnlen_s(optarg, MAX_URL_SIZE));
        OVSA_DBG(DBG_D, "LicGen: cur->license_serv_url is %s\n", cur->license_serv_url);
        tail->next = cur;
        tail       = cur;
        *listtail  = tail;
    }

out:
    return ret;
}

ovsa_status_t ovsa_store_input_file_list(const char* optarg, ovsa_input_files_t** listhead,
                                         ovsa_input_files_t** listtail) {
    ovsa_status_t ret        = OVSA_OK;
    ovsa_input_files_t* cur  = NULL;
    ovsa_input_files_t* head = NULL;
    ovsa_input_files_t* tail = NULL;

    if (optarg != NULL)
        OVSA_DBG(DBG_D, "Control Access: Arg is %s\n", optarg);

    tail = *listtail;
    if (*listhead == NULL) {
        ret = ovsa_safe_malloc(sizeof(ovsa_input_files_t), (char**)&head);
        if (ret < OVSA_OK || head == NULL) {
            OVSA_DBG(DBG_E, "OVSA: Error init input files list failed\n");
            goto out;
        }
        head->next = NULL;
        memcpy_s(head->name, MAX_FILE_NAME, optarg, strnlen_s(optarg, MAX_FILE_NAME));
        OVSA_DBG(DBG_D, "Control Access: head->name is %s\n", head->name);
        *listhead = head;
        *listtail = head;
    } else {
        ret = ovsa_safe_malloc(sizeof(ovsa_input_files_t), (char**)&cur);
        if (ret < OVSA_OK || cur == NULL) {
            OVSA_DBG(DBG_E, "OVSA: Error init input files list failed\n");
            goto out;
        }
        cur->next = NULL;
        memcpy_s(cur->name, MAX_FILE_NAME, optarg, strnlen_s(optarg, MAX_FILE_NAME));
        OVSA_DBG(DBG_D, "Control Access: cur->name is %s\n", cur->name);
        tail->next = cur;
        tail       = cur;
        *listtail  = tail;
    }

out:
    return ret;
}

void ovsa_safe_free_enc_list(ovsa_enc_models_t** listhead) {
    ovsa_enc_models_t* head = NULL;
    ovsa_enc_models_t* cur  = NULL;
    head                    = *listhead;
    while (head != NULL) {
        cur = head->next;
        ovsa_safe_free(&head->enc_model);
        ovsa_safe_free((char**)&head);
        head = cur;
    }
    *listhead = NULL;
}

void ovsa_safe_free_input_list(ovsa_input_files_t** listhead) {
    ovsa_input_files_t* head = NULL;
    ovsa_input_files_t* cur  = NULL;
    head                     = *listhead;
    while (head != NULL) {
        cur = head->next;
        free(head);
        head = cur;
    }
    *listhead = NULL;
}

void ovsa_safe_free_url_list(ovsa_license_serv_url_list_t** lhead) {
    ovsa_license_serv_url_list_t* head = NULL;
    ovsa_license_serv_url_list_t* cur  = NULL;
    head                               = *lhead;
    while (head != NULL) {
        cur = head->next;
        ovsa_safe_free((char**)&head);
        head = cur;
    }
    *lhead = NULL;
}

void ovsa_safe_free_tcb_list(ovsa_tcb_sig_list_t** listhead) {
    ovsa_tcb_sig_list_t* head = NULL;
    ovsa_tcb_sig_list_t* cur  = NULL;
    head                      = *listhead;
    while (head != NULL) {
        cur = head->next;
        ovsa_safe_free(&head->tcb_signature);
        ovsa_safe_free((char**)&head);
        head = cur;
    }
    *listhead = NULL;
}
