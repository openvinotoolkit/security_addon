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

#ifndef __OVSA_UTILS_H
#define __OVSA_UTILS_H

#include "ovsa.h"

/*!
 * \brief ovsa_get_command_type
 *
 * \param [in]  Command Type in String
 * \return  Command Type enum corresponding to the string
 */
ovsa_host_cmd_t ovsa_get_command_type(const char* command);

/*!
 * \brief ovsa_safe_free
 *
 * \param [in]  Pointer to memory for free
 */
void ovsa_safe_free(char** ptr);

/*!
 * \brief ovsa_safe_malloc
 *
 * \param [in]  Size of memory to be allocated
 * \param [out] Pointer to allocated memory
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_safe_malloc(size_t size, char** aloc_buf);

/*!
 * \brief ovsa_socket_read
 *
 * \param [in]  Socket descriptor
 * \param [in]  Number of bytes to read
 * \param [out] Pointer to buffer for read
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_socket_read(int sockfd, char* buf, size_t len);

/*!
 * \brief ovsa_safe_free_hw_quote_info
 *
 * \param [in]  HW Quote info structure for free
 */
void ovsa_safe_free_hw_quote_info(ovsa_hw_quote_info_t** hw_quote_info);

/*!
 * \brief ovsa_socket_write
 *
 * \param [in]  Socket descriptor
 * \param [in]  Number of bytes to read
 * \param [in]  Pointer to buffer for write
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_socket_write(int sockfd, const char* buf, size_t len);

/*!
 * \brief ovsa_get_file_size
 *
 * \param [in]  File pointer
 * \return File size
 */
int ovsa_get_file_size(FILE* fp);

/*!
 * \brief ovsa_get_string_length
 *
 * \param [in]  Pointer to buffer for getting its length
 * \param [out] Length of the string in bytes
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_get_string_length(const char* in_buff, size_t* in_buff_len);

/*!
 * \brief ovsa_convert_bin_to_pem
 *
 * \param [in]  Pointer to buffer for converting from bin to pem
 * \param [in]  Length of input buffer
 * \param [out] Pointer to buffer holding PEM formatter data
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_convert_bin_to_pem(const char* in_buff, size_t in_buff_len, char** out_buff);

/*!
 * \brief ovsa_crypto_convert_base64_to_bin
 *
 * \param [in]  Pointer to buffer for converting from pem to bin
 * \param [in]  Length of input buffer
 * \param [out] Pointer to buffer holding Bin data
 * \param [out] Length of Bin data in bytes
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_crypto_convert_base64_to_bin(const char* in_buff, size_t in_buff_len,
                                                char* out_buff, size_t* out_buff_len);

/*!
 * \brief ovsa_read_file_content
 *
 * \param [in]  Filename to read
 * \param [out] Pointer to buffer holding file content
 * \param [out] Length of file size in bytes
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_read_file_content(const char* filename, char** filecontent, size_t* filesize);

/*!
 * \brief ovsa_read_quote_info
 *
 * \param [out] Content of HW Quote info
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_read_quote_info(ovsa_hw_quote_info_t* hw_quote_info, int sockfd);

/*!
 * \brief ovsa_send_quote_info
 *
 * \param [in]  Socket descriptor
 * \param [in] Content of HW Quote info
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_send_quote_info(int sockfd, const char* quote_info);

/*!
 * \brief ovsa_remove quote_file
 * \param [in]  sockfd
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_remove_quote_files(int sockfd);
#endif
