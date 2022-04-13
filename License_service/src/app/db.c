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

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "safe_str_lib.h"
#include "utils.h"
/* db.h to be included at end due to dependencies */
#include "db.h"

ovsa_status_t ovsa_db_get_customer_primary_certificate(const char* db_name,
                                                       const char* license_guid,
                                                       const char* model_guid,
                                                       char** customer_certificate) {
    int ret       = 0;
    int db_status = 0;
    size_t sqllen = 0, licguid_len = 0, modelguid_len = 0;
    char sql[SQL_BUFFER_LENGTH];

    sqlite3* db        = NULL;
    sqlite3_stmt* stmt = NULL;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    memset_s(sql, sizeof(sql), 0);
    /* open the database */
    db_status = sqlite3_open(db_name, &db);
    if (db_status) {
        OVSA_DBG(DBG_E, "OVSA: Error OVSA DB open failed%s \n", sqlite3_errmsg(db));
        ret = OVSA_DB_INIT_FAIL;
        goto end;
    } else {
        OVSA_DBG(DBG_I, "OVSA: OVSA DB open successful\n");
    }

    sprintf(sql,
            "select customer_license_id, customer_primary_certificate from "
            "customer_license_info where "
            "license_guid = @license_guid and model_guid = @model_guid;");
    OVSA_DBG(DBG_D, "OVSA: SQL: %s\n", sql);

    ret = ovsa_license_service_get_string_length(sql, &sqllen);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of sql %d\n", ret);
        goto end;
    }

    db_status = sqlite3_prepare_v2(db, sql, sqllen, &stmt, 0);
    if (db_status == SQLITE_OK) {
        int idx = sqlite3_bind_parameter_index(stmt, "@license_guid");
        ret     = ovsa_license_service_get_string_length(license_guid, &licguid_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error could not get length of license_guid %d\n", ret);
            goto end;
        }
        sqlite3_bind_text(stmt, idx, license_guid, licguid_len, SQLITE_STATIC);

        idx = sqlite3_bind_parameter_index(stmt, "@model_guid");
        ret = ovsa_license_service_get_string_length(model_guid, &modelguid_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error could not get length of modelguid_len %d\n", ret);
            goto end;
        }
        sqlite3_bind_text(stmt, idx, model_guid, modelguid_len, SQLITE_STATIC);
    } else {
        OVSA_DBG(DBG_E, "OVSA: Error failed to execute statement: %s\n", sqlite3_errmsg(db));
        ret = OVSA_DB_QUERY_FAIL;
        goto end;
    }

    db_status = sqlite3_step(stmt);
    if (db_status == SQLITE_ROW) {
        /* success */
        size_t certlen = 0;
        ret = ovsa_license_service_get_string_length(sqlite3_column_text(stmt, 1), &certlen);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error could not get length of certificate %d\n", ret);
            goto end;
        }
        if ((!certlen) || (certlen > MAX_CERT_SIZE)) {
            OVSA_DBG(DBG_E, "OVSA: Error certificate length is invalid \n");
            ret = OVSA_INVALID_PARAMETER;
            goto end;
        }
        ret = ovsa_license_service_safe_malloc(sizeof(char) * (certlen + 1), customer_certificate);
        if (ret < OVSA_OK) {
            sqlite3_finalize(stmt);
            OVSA_DBG(DBG_E,
                     "OVSA: Error allocating memory for certificate buffer failed with code %d\n",
                     ret);
            ret = OVSA_MEMORY_ALLOC_FAIL;
            goto end;
        }
        sprintf(*customer_certificate, "%s", sqlite3_column_text(stmt, 1));
        ret = sqlite3_column_int(stmt, 0);

        OVSA_DBG(DBG_D, "OVSA: ROWID %s: \n", sqlite3_column_text(stmt, 0));
        OVSA_DBG(DBG_D, "OVSA: PRIMARY CERT %s\n", sqlite3_column_text(stmt, 1));
        OVSA_DBG(DBG_I, "OVSA: Customer primary certificate extracted from DB successfully\n");
    } else {
        OVSA_DBG(DBG_E, "OVSA: Error failed to execute statement: %s\n", sqlite3_errmsg(db));
        ret = OVSA_DB_UPDATE_FAIL;
        goto end;
    }
    sqlite3_finalize(stmt);

end:
    if (db)
        sqlite3_close(db);

    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_db_get_customer_secondary_certificate(const char* db_name,
                                                         const char* license_guid,
                                                         const char* model_guid,
                                                         char** customer_certificate) {
    ovsa_status_t ret = OVSA_OK;
    int db_status     = 0;
    size_t sqllen = 0, licguid_len = 0, modelguid_len = 0;
    char sql[SQL_BUFFER_LENGTH];

    sqlite3* db        = NULL;
    sqlite3_stmt* stmt = NULL;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    memset_s(sql, sizeof(sql), 0);
    /* open the database */
    db_status = sqlite3_open(db_name, &db);
    if (db_status) {
        OVSA_DBG(DBG_E, "OVSA: Error OVSA DB open failed%s \n", sqlite3_errmsg(db));
        ret = OVSA_DB_INIT_FAIL;
        goto end;
    } else {
        OVSA_DBG(DBG_I, "OVSA: OVSA DB open successful\n");
    }

    sprintf(sql,
            "select customer_license_id, customer_secondary_certificate from "
            "customer_license_info where "
            "license_guid = @license_guid and model_guid = @model_guid;");
    OVSA_DBG(DBG_D, "OVSA: SQL: %s\n", sql);

    ret = ovsa_license_service_get_string_length(sql, &sqllen);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of sql %d\n", ret);
        goto end;
    }

    db_status = sqlite3_prepare_v2(db, sql, sqllen, &stmt, 0);
    if (db_status == SQLITE_OK) {
        int idx = sqlite3_bind_parameter_index(stmt, "@license_guid");
        ret     = ovsa_license_service_get_string_length(license_guid, &licguid_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error could not get length of license_guid %d\n", ret);
            goto end;
        }
        sqlite3_bind_text(stmt, idx, license_guid, licguid_len, SQLITE_STATIC);

        idx = sqlite3_bind_parameter_index(stmt, "@model_guid");
        ret = ovsa_license_service_get_string_length(model_guid, &modelguid_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error could not get length of modelguid_len %d\n", ret);
            goto end;
        }
        sqlite3_bind_text(stmt, idx, model_guid, modelguid_len, SQLITE_STATIC);
    } else {
        OVSA_DBG(DBG_E, "OVSA: Error failed to execute statement: %s\n", sqlite3_errmsg(db));
        ret = OVSA_DB_QUERY_FAIL;
        goto end;
    }

    db_status = sqlite3_step(stmt);
    if (db_status == SQLITE_ROW) {
        /* success */
        size_t certlen = 0;
        ret = ovsa_license_service_get_string_length(sqlite3_column_text(stmt, 1), &certlen);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error could not get length of certificate %d\n", ret);
            goto end;
        }
        if ((!certlen) || (certlen > MAX_CERT_SIZE)) {
            OVSA_DBG(DBG_E, "OVSA: Error certificate length is invalid \n");
            ret = OVSA_INVALID_PARAMETER;
            goto end;
        }
        ret = ovsa_license_service_safe_malloc(sizeof(char) * (certlen + 1), customer_certificate);
        if (ret < OVSA_OK) {
            sqlite3_finalize(stmt);
            OVSA_DBG(DBG_E,
                     "OVSA: Error allocating memory for certificate buffer failed with code %d\n",
                     ret);
            ret = OVSA_MEMORY_ALLOC_FAIL;
            goto end;
        }
        sprintf(*customer_certificate, "%s", sqlite3_column_text(stmt, 1));
        ret = sqlite3_column_int(stmt, 0);

        OVSA_DBG(DBG_D, "OVSA: ROWID %s: \n", sqlite3_column_text(stmt, 0));
        OVSA_DBG(DBG_D, "OVSA: SECONDARY CERT %s\n", sqlite3_column_text(stmt, 1));
        OVSA_DBG(DBG_I, "OVSA: Customer secondary certificate extracted from DB successfully\n");
    } else {
        OVSA_DBG(DBG_E, "OVSA: Error failed to execute statement: %s\n", sqlite3_errmsg(db));
        ret = OVSA_DB_UPDATE_FAIL;
        goto end;
    }
    sqlite3_finalize(stmt);

end:
    if (db)
        sqlite3_close(db);

    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_db_get_customer_license_blob(const char* db_name, const char* license_guid,
                                                const char* model_guid,
                                                char** customer_license_blob) {
    int ret       = 0;
    int db_status = 0;
    size_t sqllen = 0, licguid_len = 0, modelguid_len = 0;
    char sql[SQL_BUFFER_LENGTH];

    sqlite3* db        = NULL;
    sqlite3_stmt* stmt = NULL;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    memset_s(sql, sizeof(sql), 0);
    /* open the database */
    db_status = sqlite3_open(db_name, &db);
    if (db_status) {
        OVSA_DBG(DBG_E, "OVSA: Error OVSA DB open failed%s \n", sqlite3_errmsg(db));
        ret = OVSA_DB_INIT_FAIL;
        goto end;
    } else {
        OVSA_DBG(DBG_I, "OVSA: OVSA DB open successful\n");
    }

    sprintf(sql,
            "select customer_license_id, customer_license_blob from "
            "customer_license_info where "
            "license_guid = @license_guid and model_guid = @model_guid;");
    OVSA_DBG(DBG_D, "OVSA: SQL: %s\n", sql);

    ret = ovsa_license_service_get_string_length(sql, &sqllen);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of sql %d\n", ret);
        goto end;
    }

    db_status = sqlite3_prepare_v2(db, sql, sqllen, &stmt, 0);
    if (db_status == SQLITE_OK) {
        int idx = sqlite3_bind_parameter_index(stmt, "@license_guid");
        ret     = ovsa_license_service_get_string_length(license_guid, &licguid_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error could not get length of license_guid %d\n", ret);
            goto end;
        }
        sqlite3_bind_text(stmt, idx, license_guid, licguid_len, SQLITE_STATIC);

        idx = sqlite3_bind_parameter_index(stmt, "@model_guid");
        ret = ovsa_license_service_get_string_length(model_guid, &modelguid_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error could not get length of modelguid_len %d\n", ret);
            goto end;
        }
        sqlite3_bind_text(stmt, idx, model_guid, modelguid_len, SQLITE_STATIC);
    } else {
        OVSA_DBG(DBG_E, "OVSA: Error failed to execute statement: %s\n", sqlite3_errmsg(db));
        ret = OVSA_DB_QUERY_FAIL;
        goto end;
    }

    db_status = sqlite3_step(stmt);
    if (db_status == SQLITE_ROW) {
        /* success */
        size_t bloblen = 0;
        ret = ovsa_license_service_get_string_length(sqlite3_column_text(stmt, 1), &bloblen);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error could not get length of customer license blob %d\n", ret);
            goto end;
        }
        if ((!bloblen) || (bloblen > SIZE_MAX)) {
            OVSA_DBG(DBG_E, "OVSA: Error customer license blob length is invalid \n");
            ret = OVSA_INVALID_PARAMETER;
            goto end;
        }
        ret = ovsa_license_service_safe_malloc(sizeof(char) * (bloblen + 1), customer_license_blob);
        if (ret < OVSA_OK) {
            sqlite3_finalize(stmt);
            OVSA_DBG(DBG_E,
                     "OVSA: Error allocating memory for customer license blob buffer failed with "
                     "code %d\n",
                     ret);
            ret = OVSA_MEMORY_ALLOC_FAIL;
            goto end;
        }
        sprintf(*customer_license_blob, "%s", sqlite3_column_text(stmt, 1));
        ret = sqlite3_column_int(stmt, 0);

        OVSA_DBG(DBG_D, "OVSA: ROWID %s: \n", sqlite3_column_text(stmt, 0));
        OVSA_DBG(DBG_D, "OVSA: Customer License Blob %s\n", sqlite3_column_text(stmt, 1));
        OVSA_DBG(DBG_I, "OVSA: Customer License Blob extracted from DB successfully\n");
    } else {
        OVSA_DBG(DBG_E, "OVSA: Error failed to execute statement: %s\n", sqlite3_errmsg(db));
        ret = OVSA_DB_UPDATE_FAIL;
        goto end;
    }
    sqlite3_finalize(stmt);

end:
    if (db)
        sqlite3_close(db);

    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_db_validate_license_usage(const char* db_name, const char* license_guid,
                                             const char* model_guid) {
    int ret       = 0;
    int db_status = 0;
    size_t sqllen = 0, licguid_len = 0, modelguid_len = 0;
    char sql[SQL_BUFFER_LENGTH];

    sqlite3* db        = NULL;
    sqlite3_stmt* stmt = NULL;

    int license_type = 0;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    memset_s(sql, sizeof(sql), 0);
    /* open the database */
    db_status = sqlite3_open(db_name, &db);
    if (db_status) {
        OVSA_DBG(DBG_E, "OVSA: Error OVSA DB open failed in validating license %s \n",
                 sqlite3_errmsg(db));
        ret = OVSA_DB_INIT_FAIL;
        goto end;
    } else {
        OVSA_DBG(DBG_I, "OVSA: OVSA DB open successful\n");
    }

    sprintf(sql,
            "select customer_license_id, license_type, usage_count, time_limit "
            "from customer_license_info where license_guid = @license_guid and "
            "model_guid = "
            "@model_guid;");
    OVSA_DBG(DBG_D, "OVSA: SQL: %s\n", sql);

    ret = ovsa_license_service_get_string_length(sql, &sqllen);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of sql %d\n", ret);
        goto end;
    }
    db_status = sqlite3_prepare_v2(db, sql, sqllen, &stmt, 0);
    if (db_status == SQLITE_OK) {
        int idx = sqlite3_bind_parameter_index(stmt, "@license_guid");
        ret     = ovsa_license_service_get_string_length(license_guid, &licguid_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error could not get length of license_guid %d\n", ret);
            goto end;
        }
        sqlite3_bind_text(stmt, idx, license_guid, licguid_len, SQLITE_STATIC);

        idx = sqlite3_bind_parameter_index(stmt, "@model_guid");
        ret = ovsa_license_service_get_string_length(model_guid, &modelguid_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error could not get length of modelguid_len %d\n", ret);
            goto end;
        }
        sqlite3_bind_text(stmt, idx, model_guid, modelguid_len, SQLITE_STATIC);
    } else {
        OVSA_DBG(DBG_E, "OVSA: Error failed to execute statement: %s\n", sqlite3_errmsg(db));
        ret = OVSA_DB_QUERY_FAIL;
        goto end;
    }

    db_status = sqlite3_step(stmt);
    if (db_status == SQLITE_ROW) {
        /* success */
        OVSA_DBG(DBG_I, "OVSA:%s: ", sqlite3_column_text(stmt, 0));

        OVSA_DBG(DBG_I, "OVSA:license type - %d ", atoi(sqlite3_column_text(stmt, 1)));
        OVSA_DBG(DBG_I, "OVSA:usage count - %s ", sqlite3_column_text(stmt, 2));
        OVSA_DBG(DBG_I, "OVSA:time limit - %s\n", sqlite3_column_text(stmt, 3));

        license_type           = sqlite3_column_int(stmt, 1);
        int usage_count        = sqlite3_column_int(stmt, 2);
        const char* time_limit = sqlite3_column_text(stmt, 3);

        if (license_type == 0) {
            ret = OVSA_OK;
        } else if (license_type == 1) {
            if (usage_count > 0) {
                ret = OVSA_OK;
            } else {
                sqlite3_finalize(stmt);
                stmt = NULL;

                ret = OVSA_DB_USAGELIMIT_FAIL;
                OVSA_DBG(DBG_E, "OVSA: Error usage exceeded, license validation failed\n");
                goto end;
            }
        } else if (license_type == 2) {
            time_t t;
            time(&t);

            struct tm* ltm;
            ltm = gmtime(&t);

            if (ltm == NULL) {
                OVSA_DBG(DBG_E, "OVSA: Error gmt Init time value failed");
                ret = OVSA_FAIL;
                goto end;
            }
            OVSA_DBG(DBG_I, "OVSA:from ltm structure - %d-%02d-%02d %02d:%02d:%02d\n",
                     ltm->tm_year + 1900, ltm->tm_mon + 1, ltm->tm_mday, ltm->tm_hour, ltm->tm_min,
                     ltm->tm_sec);

            struct tm* tm;
            tm = gmtime(&t);
            if (tm == NULL) {
                OVSA_DBG(DBG_E, "OVSA: Error gmt Init time value failed");
                ret = OVSA_FAIL;
                goto end;
            }

            strptime(time_limit, "%Y-%m-%d %H:%M:%S", tm);
            OVSA_DBG(DBG_I, "OVSA:from tm structure - %d-%02d-%02d %02d:%02d:%02d\n",
                     tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min,
                     tm->tm_sec);

            time_t tlimit = mktime(tm);
            time_t tnow   = time(0);
            double diff   = difftime(tlimit, tnow); /* If positive, then tm1 > tm2 */
            OVSA_DBG(DBG_I, "OVSA:%f diff\n", diff);
            if (diff > 0) {
                ret = OVSA_OK;
            } else {
                sqlite3_finalize(stmt);
                stmt = NULL;

                ret = OVSA_DB_TIMELIMT_FAIL;
                OVSA_DBG(DBG_E, "OVSA: Error time exceeded, license validation failed\n");
                goto end;
            }
        }
    } else {
        OVSA_DBG(DBG_E, "OVSA: Error failed to execute statement: %s\n", sqlite3_errmsg(db));
        ret = OVSA_DB_UPDATE_FAIL;
        goto end;
    }

    if (stmt != NULL) {
        sqlite3_finalize(stmt);
        stmt = NULL;
    }

    if (license_type == 1 && ret == OVSA_OK) {
        sprintf(sql,
                "update customer_license_info set usage_count = usage_count - 1 "
                "where license_guid = @license_guid and model_guid = @model_guid;");
        OVSA_DBG(DBG_D, "OVSA: SQL: %s\n", sql);
        ret = ovsa_license_service_get_string_length(sql, &sqllen);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error could not get length of sql %d\n", ret);
            goto end;
        }
        db_status = sqlite3_prepare_v2(db, sql, sqllen, &stmt, 0);
        if (db_status == SQLITE_OK) {
            int idx = sqlite3_bind_parameter_index(stmt, "@license_guid");
            ret     = ovsa_license_service_get_string_length(license_guid, &licguid_len);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "OVSA: Error could not get length of license_guid %d\n", ret);
                goto end;
            }
            sqlite3_bind_text(stmt, idx, license_guid, licguid_len, SQLITE_STATIC);

            idx = sqlite3_bind_parameter_index(stmt, "@model_guid");
            ret = ovsa_license_service_get_string_length(model_guid, &modelguid_len);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "OVSA: Error could not get length of modelguid_len %d\n", ret);
                goto end;
            }
            sqlite3_bind_text(stmt, idx, model_guid, modelguid_len, SQLITE_STATIC);
        } else {
            OVSA_DBG(DBG_E, "OVSA: Error failed to execute statement: %s\n", sqlite3_errmsg(db));
            ret = OVSA_DB_QUERY_FAIL;
            goto end;
        }

        db_status = sqlite3_step(stmt);
        if (db_status != SQLITE_DONE) {
            OVSA_DBG(DBG_E, "OVSA: Error failed to execute statement: %s\n", sqlite3_errmsg(db));
            ret = OVSA_DB_UPDATE_FAIL;
            goto end;
        } else {
            OVSA_DBG(DBG_D, "OVSA: Usage count incremented successfully\n");
        }

        if (stmt != NULL) {
            sqlite3_finalize(stmt);
            stmt = NULL;
        }
    }

end:

    if (stmt != NULL)
        sqlite3_finalize(stmt);

    if (db)
        sqlite3_close(db);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}
