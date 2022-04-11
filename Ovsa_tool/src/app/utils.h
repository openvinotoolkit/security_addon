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

#ifndef __OVSA_UTILS_H_
#define __OVSA_UTILS_H_

#include <fcntl.h>
#include <stdbool.h>
#include <sys/file.h>
#include <unistd.h>

#include "ovsa_tool.h"

typedef enum { SIGN_VERIFY, HMAC_VERIFY, INVALID_HASH } ovsa_hash_alg_t;

typedef struct ovsa_input_url_list {
    char license_serv_url[MAX_URL_SIZE];
    char cur_cert_file[MAX_NAME_SIZE];
    char fut_cert_file[MAX_NAME_SIZE];
    struct ovsa_input_url_list* next;
} ovsa_input_url_list_t;

extern ovsa_status_t ovsa_get_string_length(const char* in_buff, size_t* in_buff_len);

/** \brief This function checks whether guid is valid.
 *
 * \param[in]  guid   Pointer to guid.
 *
 * \return true or false
 */
bool ovsa_is_guid_valid(unsigned char* guid);

/** \brief This function is used to free the allocated memory.
 *
 * \param[in] ptr  Pointer to be freed.
 */
void ovsa_safe_free(char** ptr);

/** \brief This function is used to free the allocated memory for command line inputs.
 *
 * \param[in] listhead  Pointer to the list to be freed.
 */
void ovsa_safe_free_input_list(ovsa_input_files_t** listhead);

/** \brief This function is used to free the allocated memory for url list.
 *
 * \param[in] listhead  Pointer to the list of urls.
 */
void ovsa_safe_free_url_list(ovsa_license_serv_url_list_t** listhead);

/** \brief This function is used to free the allocated memory for url list.
 *
 * \param[in] listhead  Pointer to the list of urls.
 */
void ovsa_safe_free_input_url_list(ovsa_input_url_list_t** lhead);

/** \brief This function is used to free the allocated memory for model files.
 *
 * \param[in] listhead  Pointer to the list of model files.
 */
void ovsa_safe_free_model_file_list(ovsa_model_files_t** listhead);

/** \brief This function is used to free the allocated memory for tcb files.
 *
 * \param[in] listhead  Pointer to the list of tcbs.
 */
void ovsa_safe_free_tcb_list(ovsa_tcb_sig_list_t** listhead);

/** \brief This function is used for dynamic memory allocation.
 *
 * \param[in] size      Buffer size for allocation.
 * \param[in] aloc_buf  Pointer to be allocated.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_safe_malloc(size_t size, char** aloc_buf);

/** \brief This function is used to store the input files.
 *
 * \param[in] optarg    File names from the command line.
 * \param[in] listhead  Pointer to the head of the list.
 * \param[in] listtail  Pointer to be tail of the list.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_store_input_file_list(const char* optarg, ovsa_input_files_t** listhead,
                                         ovsa_input_files_t** listtail);

/** \brief This function is used to store the license url list.
 *
 * \param[in] optarg    File names from the command line
 * \param[in] listhead  Pointer to the head of the list.
 * \param[in] listtail  Pointer to be tail of the list.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_store_input_url_list(char* optarg, ovsa_input_url_list_t** listhead,
                                        ovsa_input_url_list_t** listtail);

/** \brief This function is used to store the license url list.
 *
 * \param[in] optarg    File names from the command line
 * \param[in] listhead  Pointer to the head of the list.
 * \param[in] listtail  Pointer to be tail of the list.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_store_license_url_list(char* optarg, ovsa_license_serv_url_list_t** listhead,
                                          ovsa_license_serv_url_list_t** listtail);

/*!
 * \brief This function reads the file content.
 *
 * \param [in]  filename     Filename to read.
 * \param [out] filecontent  Pointer to buffer holding file content.
 * \param [out] filesize     Length of file size in bytes.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_read_file_content(const char* filename, char** filecontent, size_t* filesize);

/** \brief This function checks whether file exits.
 *
 * \param[in]  filename   Filename.
 *
 * \return true or false
 */
bool ovsa_check_if_file_exists(const char* filename);

/** \brief This function generates hash for the input file.
 *
 * \param[in]  filename   Filename.
 * \param [out] cert_hash hash value
 * \return true or false
 */
ovsa_status_t ovsa_generate_cert_hash(char* filename, char* cert_hash);
#endif /* __OVSA_UTILS_H_ */
