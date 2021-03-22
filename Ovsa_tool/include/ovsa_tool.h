/*****************************************************************************
 * Copyright 2020-2021 Intel Corporation
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

#ifndef __OVSA_TOOL_H_
#define __OVSA_TOOL_H_

#define MAX_OVSA_CMDS 4

/* Needs to be updated based on the json blob key names */
#define LICENSE_CONFIG_BLOB_TEXT_SIZE          147
#define LICENSE_URL_BLOB_TEXT_SIZE             15
#define CONTROLLED_ACCESS_MODEL_BLOB_TEXT_SIZE 110
#define MODEL_FILE_BLOB_TEXT_SIZE              15
#define MASTER_LICENSE_BLOB_TEXT_SIZE          131
#define CUSTOMER_LICENSE_BLOB_TEXT_SIZE        300
#define TCB_NAME_BLOB_TEXT_SIZE                15
#define MAX_FILE_NAME_LEN                      20
#define TPM2_BLOB_TEXT_SIZE                    130
#define TPM2_QUOTE_SIZE                        3072
#define TPM2_PUBKEY_SIZE                       512

/* Struct to handle specified input commands */
typedef struct ovsa_handle_cmd {
    char* command;
    ovsa_status_t (*funcptr)(int argc, char* argv[]);
} ovsa_handle_cmd_t;

/* Enum values for keygen command */
typedef enum {
    STOREKEY = 0,
    STORECERT,
    GETCERT,
    SIGN,
    VERIFY,
    HELP,
    INVALID_CMD
} ovsa_keygen_cmd_t;

/* Enum values for licence type */
typedef enum { SALE = 0, INSTANCELIMIT, TIMELIMIT, MAXLICENSETYPE } ovsa_license_type_t;

/* To Store list of License Server URL for License Config Struct */
typedef struct ovsa_license_serv_url_list {
    char license_serv_url[MAX_URL_SIZE];
    struct ovsa_license_serv_url_list* next;
} ovsa_license_serv_url_list_t;

/* License Config Struct */
typedef struct ovsa_license_config {
    char license_name[MAX_NAME_SIZE];
    char license_version[MAX_VERSION_SIZE];
    int usage_count;
    int time_limit;
    ovsa_license_type_t license_type;
    ovsa_license_serv_url_list_t* license_url_list;
    char* isv_certificate;
} ovsa_license_config_t;

/*
 * License Config Struct with Signature
 * Signature is kept separately to accommodate if we need to sign contents of license_config_t
 * structure In our current design, signing is done for JSON Blob of license_config_t and hence
 * signature shall be added to license_config_t structure itself. This is same for other structures
 * as well.
 */
typedef struct ovsa_license_config_sig {
    char signature[MAX_SIGNATURE_SIZE];
    ovsa_license_config_t lic_config;
} ovsa_license_config_sig_t;

/* Master License Struct */
typedef struct ovsa_master_license {
    char creation_date[MAX_NAME_SIZE];
    char model_hash[HASH_SIZE];
    char encryption_key[MAX_EKEY_SIZE];
    GUID license_guid;
    GUID model_guid;
    char* isv_certificate;
} ovsa_master_license_t;

typedef struct ovsa_master_license_sig {
    char signature[MAX_SIGNATURE_SIZE];
    ovsa_master_license_t master_lic;
} ovsa_master_license_sig_t;

/*
 * TCB Signature list in Customer License
 * This is going to contain the TCB Signature JSON blob
 */
typedef struct ovsa_tcb_sig_list {
    char* tcb_signature;
    struct ovsa_tcb_sig_list* next;
} ovsa_tcb_sig_list_t;

/* Customer License Struct */
typedef struct ovsa_customer_license {
    char license_name[MAX_NAME_SIZE];
    char license_version[MAX_VERSION_SIZE];
    char creation_date[MAX_NAME_SIZE];
    char model_hash[HASH_SIZE];
    char encryption_key[MAX_EKEY_SIZE];
    ovsa_license_type_t license_type;
    int usage_count;
    int time_limit;
    GUID license_guid;
    GUID model_guid;
    char* isv_certificate;
    ovsa_license_serv_url_list_t* license_url_list;
    ovsa_tcb_sig_list_t* tcb_signatures;
} ovsa_customer_license_t;

/* License Info Struct with Signature */
typedef struct ovsa_customer_license_sig {
    char signature[MAX_SIGNATURE_SIZE];
    ovsa_customer_license_t customer_lic;
} ovsa_customer_license_sig_t;

/* TCB Signature Struct */
typedef struct ovsa_tcb_info {
    char tcb_name[MAX_NAME_SIZE];
    char tcb_version[MAX_VERSION_SIZE];
    char hw_quote[TPM2_QUOTE_SIZE];
    char sw_quote[TPM2_QUOTE_SIZE];
    char hw_pub_key[TPM2_PUBKEY_SIZE];
    char sw_pub_key[TPM2_PUBKEY_SIZE];
    char* isv_certificate;
} ovsa_tcb_info_t;

/* TCB Signature Struct with Signature */
typedef struct ovsa_tcb_sig {
    char signature[MAX_SIGNATURE_SIZE];
    ovsa_tcb_info_t tcbinfo;
} ovsa_tcb_sig_t;

/*
 * Controlled Access Model Struct
 * First file would be BIN file followed by XML file and other files
 * This structure would contain encrypted data of these files
 */
typedef struct ovsa_enc_models {
    char file_name[MAX_NAME_SIZE];
    char* enc_model;
    struct ovsa_enc_models* next;
} ovsa_enc_models_t;

/* Controlled Access Model Struct */
typedef struct ovsa_controlled_access_model {
    char model_name[MAX_NAME_SIZE];
    char description[MAX_NAME_SIZE];
    char version[MAX_VERSION_SIZE];
    char* isv_certificate;
    GUID model_guid;
    ovsa_enc_models_t* enc_model;
} ovsa_controlled_access_model_t;

/* Controlled Access Model Struct with Signature */
typedef struct ovsa_controlled_access_model_sig {
    char signature[MAX_SIGNATURE_SIZE];
    ovsa_controlled_access_model_t controlled_access_model;
} ovsa_controlled_access_model_sig_t;

/* To Store list of Model files, TCB Signature file specified as input */
typedef struct ovsa_input_files {
    char name[MAX_FILE_NAME];
    struct ovsa_input_files* next;
} ovsa_input_files_t;

/* keygen APIs */
/*!
 * \brief initiates key generation commands
 *
 * \param [in]  command line params
 * \param [out] keygeneration status
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_keygen_main(int argc, char* argv[]);

/* licgen APIs */
/*!
 * \brief initiates license config generation
 *
 * \param [in] count of command line params
 * \param [in] command line params
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_licgen_main(int argc, char* argv[]);

/* controlaccess APIs */
/*!
 * \brief initiates contolled access model amd master license config generaton
 *
 * \param [in] count of command line params
 * \param [in] command line params
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_controlaccess_main(int argc, char* argv[]);

/* sale APIs */
/*!
 * \brief initiates customer license config generation
 *
 * \param [in] count of command line params
 * \param [in] command line params
 * \return ovsa_status_t
 */
ovsa_status_t ovsa_sale_main(int argc, char* argv[]);

#endif /* __OVSA_TOOL_H_ */
