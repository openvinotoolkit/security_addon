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
from datetime import timedelta

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

def create_customer_license_info(conn, customer_license_info):
    """
    Create a new task
    :param conn:
    :param task:
    :return:
    """

    sql = ''' DELETE FROM customer_license_info WHERE license_guid=? AND model_guid=? '''
    cur = conn.cursor()
    cur.execute(sql, (customer_license_info[0], customer_license_info[1]))
    conn.commit()

    sql = ''' INSERT INTO customer_license_info (license_guid, model_guid, isv_certificate, customer_certificate,
              license_type, limit_count, usage_count, time_limit, created_date, updated_date)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) '''

    cur = conn.cursor()
    cur.execute(sql, customer_license_info)
    conn.commit()

    return cur.lastrowid


def main():
    # validate command line arguments
    if len(sys.argv) != 4:
        print('Invalid arguments. UpdateCl.py <db file> <customer license file> <customer certificate file>')
        return

    try:
        database = sys.argv[1]
        customer_license_file_path = sys.argv[2]
        customer_cert_file_path = sys.argv[3]

        # read customer license file
        print('Opening Customer License File - ' + customer_license_file_path)
        with open(customer_license_file_path) as customer_license_file:
            license_json_dict = json.load(customer_license_file)

        license_guid = license_json_dict["license_guid"]
        model_guid = license_json_dict["model_guid"]
        isv_certificate = license_json_dict["isv_certificate"]
        license_type = license_json_dict["license_type"]
        limit_count = license_json_dict["usage_count"] + license_json_dict["time_limit"]
        license_type_no = 0;
        usage_count = 0;
        time_limit = 0;

        if license_type == "Sale":
            license_type_no = 0
            usage_count = 0
            time_limit = 0
        elif license_type == "InstanceLimit":
            license_type_no = 1
            usage_count = limit_count
            time_limit = 0
        elif license_type == "TimeLimit":
            license_type_no = 2
            usage_count = 0
            time_limit = datetime.datetime.now() + timedelta(days=limit_count)

        # read customer certificate file
        print('Opening Customer Certificate File - ' + customer_cert_file_path)
        with open(customer_cert_file_path, "r") as customer_certificate_file:
            customer_certificate = customer_certificate_file.read()

        # create a database connection
        print('Opening DB - ' + database)
        conn = create_connection(database)
        customer_license_info = (license_guid, model_guid, isv_certificate, customer_certificate,
                                 license_type_no, limit_count, usage_count, time_limit,
                                 datetime.datetime.now(), datetime.datetime.now())
        create_customer_license_info(conn, customer_license_info)

        print("Customer license info updated successfully")

    except Exception as e:
        print('Customer license info updated failed')
        print(e)

if __name__ == "__main__":
    main()
