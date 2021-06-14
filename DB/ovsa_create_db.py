#!/usr/bin/env python3 
#
# Copyright (c) 2020-2021 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import sys, json
import sqlite3
from sqlite3 import Error
import datetime

def create_connection(db_file):

    """ create a database connection to the SQLite database
        specified by db_file
    :param db_file: database file
    :return: Connection object or None
    """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Error as e:
        print(e)

    return conn

def main():
    # validate command line arguments
    if len(sys.argv) != 2:
        print('Invalid arguments. ovsa_create_db.py <db file>')
        return

    database = sys.argv[1]

    try:
        open(database)
        print("DB already exists!")
    except IOError as e:
        if (e.args[0] == 2): # DB does not exists
            print("Creating DB!")
            sqlite3.connect(database)
        else:
            print("Error: " + str(e))
            exit()

    conn = create_connection(database)

    # create table customer_license_info
    sql_customer_license = """create table if not exists customer_license_info (
        customer_license_id integer primary key autoincrement,
        license_guid text,
        model_guid text,
        isv_certificate text,
        customer_certificate text,
	customer_license_blob text,
        license_type integer,
        limit_count integer,
        usage_count numeric,
        time_limit numeric,
        created_date numeric,
        updated_date numeric) """
    print("Creating customer_license_info table...")
    conn.execute(sql_customer_license)

    # create table tcb_info
    sql_tcb_info = """create table if not exists tcb_info (
        tcb_info_id integer primary key autoincrement,
        tcb_name text,
        version text,
        mrsigner_id text,
        mrenclave_id text,
        product_id text,
        svn text,
        hw_quote text,
        sw_quote text,
        hw_pubkey text,
        sw_pubkey text)"""
    print("Creating tcb_info table...")
    conn.execute(sql_tcb_info)

    #cur = conn.cursor()
    #cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name; ")
    #rows = cur.fetchall()
    #for row in rows:
    #    print(row)

    conn.close



if __name__ == "__main__":
    main()
