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

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* db.h to be included at end due to dependencies */
#include "db.h"

ovsa_status_t ovsa_db_create_customer_license(char* db_name, char* license_guid, char* model_guid,
                                              char* isv_certificate, char* customer_certificate,
                                              int license_type, int limit_count) {
    ovsa_status_t ret = 0;
    int db_status;
    char* err_message;
    char sql[1024];
    char* sqlsql;

    sqlite3* db;
    sqlite3_stmt* stmt;
    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /* open the database */
    db_status = sqlite3_open(db_name, &db);
    if (db_status) {
        OVSA_DBG(DBG_E, "OVSA: OVSA DB open failed%s \n", sqlite3_errmsg(db));
        ret = OVSA_DB_INIT_FAIL;
        goto end;
    } else {
        OVSA_DBG(DBG_D, "OVSA: OVSA DB open successful\n");
    }

    sprintf(sql,
            "insert into customer_license_info ("
            "license_guid, model_guid, isv_certificate, customer_certificate, "
            "license_type, limit_count, usage_count, time_limit, created_date, "
            "updated_date) "
            "values (@license_guid, @model_guid, @isv_certificate, "
            "@customer_certificate, @license_type, @limit_count, @usage_count, "
            "@time_limit, "
            "datetime('now', 'localtime'), datetime('now', 'localtime'))");
    OVSA_DBG(DBG_D, "OVSA: SQL: %s\n", sql);

    OVSA_DBG(DBG_D, "OVSA: Before Prepare\n");
    db_status = sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, 0);
    OVSA_DBG(DBG_D, "OVSA: After Prepare %d\n", db_status);

    if (db_status == SQLITE_OK) {
        int idx = sqlite3_bind_parameter_index(stmt, "@license_guid");
        sqlite3_bind_text(stmt, idx, license_guid, strlen(license_guid), SQLITE_STATIC);

        idx = sqlite3_bind_parameter_index(stmt, "@model_guid");
        sqlite3_bind_text(stmt, idx, model_guid, strlen(model_guid), SQLITE_STATIC);

        idx = sqlite3_bind_parameter_index(stmt, "@isv_certificate");
        sqlite3_bind_text(stmt, idx, isv_certificate, strlen(isv_certificate), SQLITE_STATIC);

        idx = sqlite3_bind_parameter_index(stmt, "@customer_certificate");
        sqlite3_bind_text(stmt, idx, customer_certificate, strlen(customer_certificate),
                          SQLITE_STATIC);

        idx = sqlite3_bind_parameter_index(stmt, "@license_type");
        sqlite3_bind_int(stmt, idx, license_type);

        idx = sqlite3_bind_parameter_index(stmt, "@limit_count");
        sqlite3_bind_int(stmt, idx, limit_count);

        if (license_type == 0) {
            idx = sqlite3_bind_parameter_index(stmt, "@usage_count");
            sqlite3_bind_null(stmt, idx);

            idx = sqlite3_bind_parameter_index(stmt, "@time_limit");
            sqlite3_bind_null(stmt, idx);
        } else if (license_type == 1) {
            idx = sqlite3_bind_parameter_index(stmt, "@usage_count");
            sqlite3_bind_int(stmt, idx, limit_count);

            idx = sqlite3_bind_parameter_index(stmt, "@time_limit");
            sqlite3_bind_null(stmt, idx);
        } else if (license_type == 2) {
            idx = sqlite3_bind_parameter_index(stmt, "@usage_count");
            sqlite3_bind_null(stmt, idx);

            char dt[20];
            time_t t;
            time(&t);

            struct tm* tm;
            tm = gmtime(&t);
            if (tm == NULL) {
                OVSA_DBG(DBG_E, "OVSA: gmt Init time value failed");
                ret = OVSA_FAIL;
                goto end;
            }
            tm->tm_mday += limit_count;
            mktime(tm);

            snprintf(dt, sizeof(dt), "%04d-%02d-%02d %02d:%02d:%02d", tm->tm_year + 1900,
                     tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
            OVSA_DBG(DBG_D, "OVSA: NOW: %s\n", dt);

            idx = sqlite3_bind_parameter_index(stmt, "@time_limit");
            sqlite3_bind_text(stmt, idx, dt, strlen(dt), SQLITE_STATIC);
        }
    } else {
        OVSA_DBG(DBG_E, "OVSA: Failed to execute statement: %s\n", sqlite3_errmsg(db));
        ret = OVSA_DB_UPDATE_FAIL;
        goto end;
    }

    db_status = sqlite3_step(stmt);
    if (db_status != SQLITE_DONE) {
        OVSA_DBG(DBG_E, "OVSA: Failed to execute statement: %s\n", sqlite3_errmsg(db));
        ret = OVSA_DB_UPDATE_FAIL;
        goto end;
    } else {
        sqlite3_finalize(stmt);
        OVSA_DBG(DBG_D, "OVSA:Data inserted successfully\n");
    }

end:
    if (db)
        sqlite3_close(db);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_db_get_customer_certificate(const char* db_name, const char* license_guid,
                                               const char* model_guid,
                                               char** customer_certificate) {
    int ret = 0;
    int db_status;
    char* err_message;
    char sql[1024];

    sqlite3* db;
    sqlite3_stmt* stmt;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /* open the database */
    db_status = sqlite3_open(db_name, &db);
    if (db_status) {
        OVSA_DBG(DBG_E, "OVSA: OVSA DB open failed%s \n", sqlite3_errmsg(db));
        ret = OVSA_DB_INIT_FAIL;
        goto end;
    } else {
        OVSA_DBG(DBG_D, "OVSA: OVSA DB open successful\n");
    }

    sprintf(sql,
            "select customer_license_id, customer_certificate from "
            "customer_license_info where "
            "license_guid = @license_guid and model_guid = @model_guid;");
    OVSA_DBG(DBG_D, "OVSA: SQL: %s\n", sql);

    db_status = sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, 0);
    if (db_status == SQLITE_OK) {
        int idx = sqlite3_bind_parameter_index(stmt, "@license_guid");
        sqlite3_bind_text(stmt, idx, license_guid, strlen(license_guid), SQLITE_STATIC);

        idx = sqlite3_bind_parameter_index(stmt, "@model_guid");
        sqlite3_bind_text(stmt, idx, model_guid, strlen(model_guid), SQLITE_STATIC);
    } else {
        OVSA_DBG(DBG_E, "OVSA: Failed to execute statement: %s\n", sqlite3_errmsg(db));
        ret = OVSA_DB_QUERY_FAIL;
        goto end;
    }

    db_status = sqlite3_step(stmt);
    if (db_status == SQLITE_ROW) {
        /* success */
        int certlen           = strlen(sqlite3_column_text(stmt, 1));
        *customer_certificate = (char*)malloc((certlen + 1) * sizeof(char));
        if (*customer_certificate == NULL) {
            sqlite3_finalize(stmt);
            OVSA_DBG(DBG_E, "OVSA: Failed in allocating memory for certificate buffer\n");
            ret = OVSA_MEMORY_ALLOC_FAIL;
            goto end;
        }
        sprintf(*customer_certificate, "%s", sqlite3_column_text(stmt, 1));
        ret = sqlite3_column_int(stmt, 0);

        OVSA_DBG(DBG_D, "OVSA: Failed to execute statement: %s\n", sqlite3_errmsg(db));

        OVSA_DBG(DBG_D, "OVSA: ROWID %s: \n", sqlite3_column_text(stmt, 0));
        OVSA_DBG(DBG_D, "OVSA: CERT %s\n", sqlite3_column_text(stmt, 1));
        OVSA_DBG(DBG_I, "OVSA: Cusotmer certificate extracted from DB successfully\n");
    } else {
        OVSA_DBG(DBG_E, "OVSA: Failed to execute statement: %s\n", sqlite3_errmsg(db));
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
    int ret = 0;
    int db_status;
    char* err_message;
    char sql[1024];

    sqlite3* db;
    sqlite3_stmt* stmt = NULL;

    int license_type = 0;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /* open the database */
    db_status = sqlite3_open(db_name, &db);
    if (db_status) {
        OVSA_DBG(DBG_E, "OVSA: OVSA DB open failed%s \n", sqlite3_errmsg(db));
        ret = OVSA_DB_INIT_FAIL;
        goto end;
    } else {
        OVSA_DBG(DBG_D, "OVSA: OVSA DB open successful\n");
    }

    sprintf(sql,
            "select customer_license_id, license_type, usage_count, time_limit "
            "from customer_license_info where license_guid = @license_guid and "
            "model_guid = "
            "@model_guid;");
    OVSA_DBG(DBG_D, "OVSA: SQL: %s\n", sql);

    db_status = sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, 0);
    if (db_status == SQLITE_OK) {
        int idx = sqlite3_bind_parameter_index(stmt, "@license_guid");
        sqlite3_bind_text(stmt, idx, license_guid, strlen(license_guid), SQLITE_STATIC);

        idx = sqlite3_bind_parameter_index(stmt, "@model_guid");
        sqlite3_bind_text(stmt, idx, model_guid, strlen(model_guid), SQLITE_STATIC);
    } else {
        OVSA_DBG(DBG_E, "OVSA: Failed to execute statement: %s\n", sqlite3_errmsg(db));
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
                OVSA_DBG(DBG_E, "OVSA: Usage exceeded, license validation failed\n");
                goto end;
            }
        } else if (license_type == 2) {
            time_t t;
            time(&t);

            struct tm* ltm;
            ltm = gmtime(&t);

            if (ltm == NULL) {
                OVSA_DBG(DBG_E, "OVSA: gmt Init time value failed");
                ret = OVSA_FAIL;
                goto end;
            }
            OVSA_DBG(DBG_I, "OVSA:from ltm structure - %d-%02d-%02d %02d:%02d:%02d\n",
                     ltm->tm_year + 1900, ltm->tm_mon + 1, ltm->tm_mday, ltm->tm_hour, ltm->tm_min,
                     ltm->tm_sec);

            struct tm* tm;
            tm = gmtime(&t);
            if (tm == NULL) {
                OVSA_DBG(DBG_E, "OVSA: gmt Init time value failed");
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
                OVSA_DBG(DBG_E, "OVSA: Time exceeded, license validation failed\n");
                goto end;
            }
        }
    } else {
        OVSA_DBG(DBG_E, "OVSA: Failed to execute statement: %s\n", sqlite3_errmsg(db));
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

        db_status = sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, 0);
        if (db_status == SQLITE_OK) {
            int idx = sqlite3_bind_parameter_index(stmt, "@license_guid");
            sqlite3_bind_text(stmt, idx, license_guid, strlen(license_guid), SQLITE_STATIC);

            idx = sqlite3_bind_parameter_index(stmt, "@model_guid");
            sqlite3_bind_text(stmt, idx, model_guid, strlen(model_guid), SQLITE_STATIC);
        } else {
            OVSA_DBG(DBG_E, "OVSA: Failed to execute statement: %s\n", sqlite3_errmsg(db));
            ret = OVSA_DB_QUERY_FAIL;
            goto end;
        }

        db_status = sqlite3_step(stmt);
        if (db_status != SQLITE_DONE) {
            OVSA_DBG(DBG_E, "OVSA: Failed to execute statement: %s\n", sqlite3_errmsg(db));
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
