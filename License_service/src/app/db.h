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
#ifndef __OVSA_LIBDB_H_
#define __OVSA_LIBDB_H_

#include "license_service.h"

#define SQL_BUFFER_LENGTH 1024
#define OVSA_DB_PATH      "/opt/ovsa/DB/ovsa.db"

/* API's */
/*!
 * \brief ovsa_db_get_customer_primary_certificate
 *
 * \param [in]  db_name buffer pointing to the database name
 * \param [in]  license_guid buffer pointing to the license guid
 * \param [in]  model_guid buffer pointing to the model guid
 * \param [out]  customer_certificate buffer pointing to retrieve the customer
 * primary certificate \return ovsa_status_t
 */

ovsa_status_t ovsa_db_get_customer_primary_certificate(const char* db_name,
                                                       const char* license_guid,
                                                       const char* model_guid,
                                                       char** customer_certificate);

/*!
 * \brief ovsa_db_get_customer_secondary_certificate
 *
 * \param [in]  db_name buffer pointing to the database name
 * \param [in]  license_guid buffer pointing to the license guid
 * \param [in]  model_guid buffer pointing to the model guid
 * \param [out]  customer_certificate buffer pointing to retrieve the customer
 * secondary certificate \return ovsa_status_t
 */

ovsa_status_t ovsa_db_get_customer_secondary_certificate(const char* db_name,
                                                         const char* license_guid,
                                                         const char* model_guid,
                                                         char** customer_certificate);

/*!
 * \brief ovsa_db_get_customer_license_blob
 *
 * \param [in]  db_name buffer pointing to the database name
 * \param [in]  license_guid buffer pointing to the license guid
 * \param [in]  model_guid buffer pointing to the model guid
 * \param [out]  customer_license_blob buffer pointing to retrieve the customer
 * license blob \return ovsa_status_t
 */

ovsa_status_t ovsa_db_get_customer_license_blob(const char* db_name, const char* license_guid,
                                                const char* model_guid,
                                                char** customer_license_blob);
/*!
 * \brief ovsa_db_validate_license_usage
 *
 * \param [in]  db_name buffer pointing to the database name
 * \param [in]  license_guid buffer pointing to the license guid
 * \param [in]  model_guid buffer pointing to the model guid
 * \return ovsa_status_t
 */

ovsa_status_t ovsa_db_validate_license_usage(const char* db_name, const char* license_guid,
                                             const char* model_guid);

#endif
