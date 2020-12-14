/*
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
 *
 */

#ifndef _OVSA_JSON_H_
#define _OVSA_JSON_H_

#include "license_service.h"

/*!
 * \brief ovsa_server_json_map_license_type
 *
 * \param [in]   lictype string value of licence type
 * \return [out] enum of licence type
 */
ovsa_license_type_t ovsa_server_json_map_license_type(const char* lictype);

/*!
 * \brief ovsa_server_json_extract_customer_license
 *
 * \param [in]  inputBuf Buffer having json file contents
 * \param [out] cust_lic_sig structure* containing customer license information
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_server_json_extract_customer_license(const char* inputBuf,
                                                        ovsa_customer_license_sig_t* cust_lic_sig);

/*!
 * \brief ovsa_server_json_extract_element
 *
 * \param [in]  inputBuf Buffer having json file contents
 * \param [in]  keyName  keyname to be read
 * \param [out] keyValue keyvale read
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_server_json_extract_element(const char* inputBuf, const char* keyName,
                                               void** keyValue);
/*!
 * \brief ovsa_server_json_create_message_blob
 *
 * \param [in]  command type information to update inside blob
 * \param [in]  payloed information to update inside blob
 * \param [out] outputBuf Buffer updated with input parms
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_server_json_create_message_blob(ovsa_command_type_t cmdtype, const char* payload,
                                                   char** outputBuf, size_t* valuelen);

/*!
 * \brief ovsa_server_json_extract_tcb_signature
 *
 * \param [in]  inputBuf Buffer having json file contents
 * \param [out] tsig  structure* containing TCB information
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_server_json_extract_tcb_signature(const char* inputBuf, ovsa_tcb_sig_t* tsig);
/*!
 * \brief ovsa_json_create_quote_cred_data_blob
 *
 * \param [in]  cred_out information to update inside blob
 * \param [in]  quote_nonce information to update inside blob
 * \param [out] outputBuf Buffer updated with input parms
 * \param [out] valuelen length of the output buffer
 * \return ovsa_status_t
 */

ovsa_status_t ovsa_json_create_quote_cred_data_blob(const char* cred_out, const char* quote_nonce,
                                                    char** outputBuf, size_t* valuelen);

#endif
