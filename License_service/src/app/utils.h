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

#ifndef __OVSA_UTILS_H_
#define __OVSA_UTILS_H_

#include "license_service.h"
#define NULL_TERMINATOR 1
static BIO* g_bio_err = NULL;

/** \brief This function calculates the length of the input buffer.
 *
 * \param[in]  in_buff       Buffer pointer for calculating the length.
 * \param[out] in_buff_len   Length of the input buffer.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_license_service_get_string_length(const char* in_buff, size_t* in_buff_len);

/** \brief This function is used for dynamic memory allocation.
 *
 * \param[in] size      Buffer size for allocation.
 * \param[in] aloc_buf  Pointer to be allocated.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_license_service_safe_malloc(size_t size, char** aloc_buf);

/** \brief This function is used to free the allocated memory.
 *
 * \param[in] ptr  Pointer to be freed.
 */
void ovsa_license_service_safe_free(char** ptr);

/** \brief This function is used to free the allocated memory for url list.
 *
 * \param[in] listhead  Pointer to the list of urls.
 */
void ovsa_license_service_safe_free_url_list(ovsa_license_serv_url_list_t** lhead);

/** \brief This function is used to get the hex dump of input data
 *
 * \param[in] data Pointer to input data
 */
void ovsa_license_service_hexdump_mem(const void* data, size_t size);

/** \brief This function is append payload length to received input buffer
 *
 * \param[in] input buf pointer.
 * \param[in] outbuf pointer.
 */
ovsa_status_t ovsa_license_service_append_payload_len_to_blob(const char* input_buf,
                                                              char** json_payload);
/*!
 * \brief This function reads the file content.
 *
 * \param [in]  filename     Filename to read.
 * \param [out] filecontent  Pointer to buffer holding file content.
 * \param [out] filesize     Length of file size in bytes.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_license_service_read_file_content(const char* filename, char** filecontent,
                                                     size_t* filesize);
/*!
 * \brief This function reads the file size.
 *
 *  \param [in] fp        File descriptor to read contents
 * \param [out] filesize  Length of file size in bytes.
 *
 * \return ovsa_status_t: OVSA_OK or OVSA_ERROR
 */
ovsa_status_t ovsa_license_service_crypto_get_file_size(FILE* fp, size_t* filesize);

/** \brief This function is used to free the allocated memory for tcb files.
 *
 * \param[in] listhead  Pointer to the list of tcbs.
 */
void ovsa_license_service_safe_free_tcb_list(ovsa_tcb_sig_list_t** listhead);
/*!
 *  * \brief ovsa_license_service_safe_add
 *
 * \param [in]  size_t Variable1,sum of var1+var2 stored in var1
 * \param [in]  size_t Variable2
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_license_service_safe_add(size_t* var1, size_t var2);
#endif
