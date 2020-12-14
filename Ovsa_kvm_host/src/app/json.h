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

#ifndef __OVSA_JSON_H_
#define __OVSA_JSON_H_

#include "ovsa.h"

/*!
 * \brief ovsa_json_create_hw_quote_info
 *
 * \param [in]  Gets HW Quote information
 * \param [out] JSON blob string with HW Quote information
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_json_create_hw_quote_info(ovsa_hw_quote_info_t* quote_info, char** outputBuf);

/*!
 * \brief ovsa_json_extract_element
 *
 * \param [in]  JSON blob
 * \param [in]  Element to be extracted from JSON blob
 * \param [out] Extracted element of JSON blob
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_json_extract_element(const char* inputBuf, const char* keyName, void** keyValue);

/*!
 * \brief ovsa_json_create_message_blob
 *
 * \param [in]  Command Type
 * \param [in]  Payload for which JSON blob to be created
 * \param [out] Output buffer containing JSON blob
 * \param [out] Length of JSON blob
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_json_create_message_blob(ovsa_host_cmd_t cmdtype, const char* payload,
                                            char** outputBuf, size_t* length);

/*!
 * \brief ovsa_json_append_json_payload_len_to_blob
 *
 * \param [in]  Input buf containing JSON blob
 * \param [out] Output buffer containing Payload length prefixed with payload
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_append_json_payload_len_to_blob(char* input_buf, char** json_payload);
#endif
