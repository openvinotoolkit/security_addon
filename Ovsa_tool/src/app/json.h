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

#ifndef __OVSA_LIBJSON_H_
#define __OVSA_LIBJSON_H_

#ifdef OVSA_RUNTIME
#include "runtime.h"
#endif

/* API's */

/*!
 * \brief ovsa_json_map_license_type
 *
 * \param [in]   lictype string value of licence type
 * \return [out] enum of licence type
 */
ovsa_license_type_t ovsa_json_map_license_type(const char* lictype);

/* create_json_blob APIs */
/*!
 * \brief ovsa_json_create_license_config
 *
 * \param [in]  lic_conf_sig structure* containing keystore information
 * \param [in]  size_t size containing size of the ouput buffer
 * \param [out] outputBuf Buffer updated with json file contents
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_json_create_license_config(const ovsa_license_config_sig_t* lic_conf_sig,
                                              size_t size, char* outputBuf);

/*!
 * \brief ovsa_json_create_controlled_access_model
 *
 * \param [in]  control_access_model_sig structure* containing controlled access model information
 * \param [in]  size_t size containing size of the ouput buffer
 * \param [out] outputBuf Buffer updated with json file contents
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_json_create_controlled_access_model(
    const ovsa_controlled_access_model_sig_t* control_access_model_sig, size_t size,
    char* outputBuf);
/*!
 * \brief ovsa_json_create_TCB_signature
 *
 * \param [in]  tsig structure* containing TCB information
 * \param [in]  size_t size containing size of the ouput buffer
 * \param [out] outputBuf Buffer updated with json file contents
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_json_create_tcb_signature(const ovsa_tcb_sig_t* tsig, size_t size,
                                             char* outputBuf);
/*!
 * \brief ovsa_json_create_customer_license
 *
 * \param [in]  cust_lic_sig structure* containing customer license information
 * \param [in]  size_t size containing size of the ouput buffer
 * \param [out] outputBuf Buffer updated with json file contents
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_json_create_customer_license(const ovsa_customer_license_sig_t* cust_lic_sig,
                                                size_t size, char* outputBuf);

/*!
 * \brief ovsa_json_create_master_license
 *
 * \param [in]  master_lic_sig structure* containing master license information
 * \param [in]  size_t size containing size of the ouput buffer
 * \param [out] outputBuf Buffer updated with json file contents
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_json_create_master_license(const ovsa_master_license_sig_t* master_lic_sig,
                                              size_t size, char* outputBuf);

/*!
 * \brief ovsa_json_extract_license_config
 *
 * \param [in]  inputBuf Buffer having json file contents
 * \param [out] lic_conf_sig structure* containing license config information
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_json_extract_license_config(const char* inputBuf,
                                               ovsa_license_config_sig_t* lic_conf_sig);

/*!
 * \brief ovsa_json_extract_controlled_access_model
 *
 * \param [in]  inputBuf Buffer having json file contents
 * \param [out] control_access_model_sig structure* containing controlled access model information
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_json_extract_controlled_access_model(
    const char* inputBuf, ovsa_controlled_access_model_sig_t* control_access_model_sig);
/*!
 * \brief ovsa_json_extract_tcb_signature
 *
 * \param [in]  inputBuf Buffer having json file contents
 * \param [out] tsig  structure* containing TCB information
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_json_extract_tcb_signature(const char* inputBuf, ovsa_tcb_sig_t* tsig);
/*!
 * \brief ovsa_json_extract_master_license
 *
 * \param [in]  inputBuf Buffer having json file contents
 * \param [out] master_lic_sig structure* containing master license information
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_json_extract_master_license(const char* inputBuf,
                                               ovsa_master_license_sig_t* master_lic_sig);

/*!
 * \brief ovsa_json_extract_customer_license
 *
 * \param [in]  inputBuf Buffer having json file contents
 * \param [out] cust_lic_sig structure* containing customer license information
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_json_extract_customer_license(const char* inputBuf,
                                                 ovsa_customer_license_sig_t* cust_lic_sig);

/*!
 * \brief ovsa_json_extract_element
 *
 * \param [in]  inputBuf Buffer having json file contents
 * \param [in]  keyName Name of key to read
 * \param [out] keyValue Updated with json file contents
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_json_extract_element(const char* inputBuf, const char* keyName, char** keyValue);

#ifdef OVSA_RUNTIME
#ifndef ENABLE_SGX_GRAMINE
/*!
 * \brief ovsa_json_create_EK_AK_binding_info_blob
 *
 * \param [in]  ek_ak_bind_info
 * \param [out] outputBuf buffer content
 * \param [out] valuelen output size
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_json_create_EK_AK_binding_info_blob(ovsa_ek_ak_bind_info_t ek_ak_bind_info,
                                                       char** outputBuf, size_t* valuelen);
#endif

/*!
 * \brief ovsa_json_create_message_blob
 *
 * \param [in]  Command Type
 * \param [in]  Payload for which JSON blob to be created
 * \param [out] Output buffer containing JSON blob
 * \param [out] Length of JSON blob
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_json_create_message_blob(ovsa_command_type_t cmdtype, const char* payload,
                                            char** outputBuf, size_t* length);

#ifndef ENABLE_SGX_GRAMINE
/*!
 * \brief ovsa_json_create_quote_info
 *
 * \param [in]  Gets HW Quote information
 * \param [in]  Gets SW Quote information
 * \param [out] JSON blob string with HW and SW Quote information
 * \param [out] JSON blob size
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_json_create_quote_info_blob(const char* secret,
                                               const ovsa_quote_info_t sw_quote_info,
                                               const ovsa_quote_info_t hw_quote_info,
                                               char** outputBuf, size_t* valuelen);
#endif
/*!
 * \brief ovsa_json_append_json_payload_len_to_blob
 *
 * \param [in]  Input buf containing JSON blob
 * \param [out] Output buffer containing Payload length prefixed with payload
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_append_json_payload_len_to_blob(const char* input_buf, char** json_payload);
#endif
#endif /* __OVSA_LIBJSON_H_ */
