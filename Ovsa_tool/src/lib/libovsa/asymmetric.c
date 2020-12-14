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

#include "asymmetric.h"

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string.h>

#include "libovsa.h"
#include "symmetric.h"

static ovsa_status_t ovsa_crypto_generate_asymmetric_keys(ovsa_key_alg_t alg_type,
                                                          char* private_key, char* public_key) {
    int nid = 0, asn1_flag = OPENSSL_EC_NAMED_CURVE, prv_param = 0, pub_param = 0;
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
    ovsa_status_t ret            = OVSA_OK;
    BUF_MEM* privatekey_ptr      = NULL;
    BUF_MEM* publickey_ptr       = NULL;
    BIO* privatekey_mem          = NULL;
    BIO* publickey_mem           = NULL;
    EC_GROUP* group              = NULL;
    EC_KEY* eckey                = NULL;

    if ((ECDSA != alg_type) || (private_key == NULL) || (public_key == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric keys failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    privatekey_mem = BIO_new(BIO_s_mem());
    if (privatekey_mem == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric keys failed in getting new BIO for "
                   "private key\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    publickey_mem = BIO_new(BIO_s_mem());
    if (publickey_mem == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error generating asymmetric keys failed in getting new BIO for public key\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    nid   = NID_secp384r1;
    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric keys failed in creating curve\n");
        ret = OVSA_CRYPTO_ECKEY_ERROR;
        goto end;
    }

    EC_GROUP_set_asn1_flag(group, asn1_flag);
    EC_GROUP_set_point_conversion_form(group, form);

    prv_param = PEM_write_bio_ECPKParameters(privatekey_mem, group);
    pub_param = PEM_write_bio_ECPKParameters(publickey_mem, group);
    if (!prv_param || !pub_param) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric keys failed in writing elliptic curve "
                   "parameters\n");
        ret = OVSA_CRYPTO_PEM_ENCODE_ERROR;
        goto end;
    }

    /* Create new EC key */
    eckey = EC_KEY_new();
    if (eckey == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric keys failed in creating EC key\n");
        ret = OVSA_CRYPTO_ECKEY_ERROR;
        goto end;
    }

    /* Set key's group (curve) */
    if (EC_KEY_set_group(eckey, group) == 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric keys failed to set EC_GROUP object while "
                   "generating key\n");
        ret = OVSA_CRYPTO_ECKEY_ERROR;
        goto end;
    }

    /* Generate EC key pair */
    if (!EC_KEY_generate_key(eckey)) {
        BIO_printf(g_bio_err, "LibOVSA: Error generating asymmetric keys failed to generate key\n");
        ret = OVSA_CRYPTO_ECKEY_ERROR;
        goto end;
    }

    if (!PEM_write_bio_ECPrivateKey(privatekey_mem, eckey, NULL, NULL, 0, NULL, NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric keys failed to write the private key data "
                   "in PEM format\n");
        ret = OVSA_CRYPTO_PEM_ENCODE_ERROR;
        goto end;
    }

    if (!PEM_write_bio_EC_PUBKEY(publickey_mem, eckey)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric keys failed to write the public key data "
                   "in PEM format\n");
        ret = OVSA_CRYPTO_PEM_ENCODE_ERROR;
        goto end;
    }

    BIO_get_mem_ptr(privatekey_mem, &privatekey_ptr);
    if (privatekey_ptr == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric keys failed to extract the private key\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    BIO_get_mem_ptr(publickey_mem, &publickey_ptr);
    if (publickey_ptr == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric keys failed to extract the public key\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (memcpy_s(private_key, MAX_KEY_SIZE, privatekey_ptr->data, privatekey_ptr->length) != EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric keys failed in getting private key\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

    if (memcpy_s(public_key, MAX_KEY_SIZE, publickey_ptr->data, publickey_ptr->length) != EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric keys failed in getting public key\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

end:
    EC_KEY_free(eckey);
    EC_GROUP_free(group);
    BIO_free_all(privatekey_mem);
    BIO_free_all(publickey_mem);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_add_asymmetric_keystore_array(const ovsa_isv_keystore_t* isv_keystore,
                                                        int* asym_key_slot) {
    ovsa_status_t ret        = OVSA_OK;
    size_t keystore_cert_len = 0;
    int asymmetric_index     = 0;
    char* empty_string       = "";
    int isv_name_indicator   = -1;
    int public_key_indicator = -1, private_key_indicator = -1;
    int key_guid_indicator = -1, cert_indicator = -1;

    if (isv_keystore == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error adding to asymmetric keystore array failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    /* Find the empty asymmetric index */
    for (asymmetric_index = 0; asymmetric_index < MAX_KEY_SLOT; asymmetric_index++) {
        if (strcmp_s(g_key_store[asymmetric_index].isv_name, MAX_NAME_SIZE, empty_string,
                     &isv_name_indicator) != EOK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error adding to asymmetric keystore array failed in comparing the "
                       "keystore name\n");
            return OVSA_CRYPTO_GENERIC_ERROR;
        }

        if (strcmp_s(g_key_store[asymmetric_index].public_key, MAX_KEY_SIZE, empty_string,
                     &public_key_indicator) != EOK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error adding to asymmetric keystore array failed in comparing the "
                       "public key\n");
            return OVSA_CRYPTO_GENERIC_ERROR;
        }

        if (strcmp_s(g_key_store[asymmetric_index].private_key, MAX_KEY_SIZE, empty_string,
                     &private_key_indicator) != EOK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error adding to asymmetric keystore array failed in comparing the "
                       "private key\n");
            return OVSA_CRYPTO_GENERIC_ERROR;
        }

        if (strcmp_s(g_key_store[asymmetric_index].key_guid, sizeof(GUID), empty_string,
                     &key_guid_indicator) != EOK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error adding to asymmetric keystore array failed in comparing the "
                       "guid\n");
            return OVSA_CRYPTO_GENERIC_ERROR;
        }

        if (g_key_store[asymmetric_index].isv_certificate != NULL) {
            ret = ovsa_get_string_length(g_key_store[asymmetric_index].isv_certificate,
                                         &keystore_cert_len);
            if (ret < OVSA_OK) {
                BIO_printf(
                    g_bio_err,
                    "LibOVSA: Error adding to asymmetric keystore array failed in getting the "
                    "keystore certificate length\n");
                return ret;
            }

            if (keystore_cert_len == 0) {
                cert_indicator = 0;
            }
        } else {
            cert_indicator = 0;
        }

        if ((isv_name_indicator == 0) && (public_key_indicator == 0) &&
            (private_key_indicator == 0) && (key_guid_indicator == 0) && (cert_indicator == 0)) {
            if (memcpy_s(&g_key_store[asymmetric_index], sizeof(ovsa_isv_keystore_t), isv_keystore,
                         sizeof(ovsa_isv_keystore_t)) != EOK) {
                BIO_printf(
                    g_bio_err,
                    "LibOVSA: Error adding to asymmetric keystore array failed in getting the "
                    "keystore data\n");
                return OVSA_MEMIO_ERROR;
            }

            *asym_key_slot = asymmetric_index;
            break;
        } else {
            continue;
        }
    }

    if (asymmetric_index == MAX_KEY_SLOT) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error adding to asymmetric keystore array failed since not able to "
                   "store the asymmetric key\n");
        return OVSA_CRYPTO_GENERIC_ERROR;
    }

    return ret;
}

ovsa_status_t ovsa_crypto_add_cert_keystore_array(int asym_key_slot, const char* cert) {
    ovsa_status_t ret = OVSA_OK;
    size_t cert_len   = 0;

    if ((asym_key_slot < MIN_KEY_SLOT) || (asym_key_slot >= MAX_KEY_SLOT) || (cert == NULL)) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error adding certificate to keystore array failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    ret = ovsa_get_string_length(cert, &cert_len);
    if ((ret < OVSA_OK) || (cert_len == EOK)) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error adding certificate to keystore array failed in getting the size of "
            "the certificate\n");
        return ret;
    }

    if (g_key_store[asym_key_slot].isv_certificate != NULL) {
        ovsa_crypto_openssl_free(&g_key_store[asym_key_slot].isv_certificate);
    }

    g_key_store[asym_key_slot].isv_certificate =
        (char*)ovsa_crypto_app_malloc(cert_len + NULL_TERMINATOR, "certificate");
    if (g_key_store[asym_key_slot].isv_certificate == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error adding certificate to keystore array failed in allocating memory "
            "for certificate\n");
        return OVSA_MEMORY_ALLOC_FAIL;
    }

    if (memcpy_s(g_key_store[asym_key_slot].isv_certificate, cert_len, cert, cert_len) != EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error adding certificate to keystore array failed in getting the "
                   "certificate\n");
        return OVSA_MEMIO_ERROR;
    }

    return ret;
}

ovsa_status_t ovsa_crypto_generate_asymmetric_key_pair(ovsa_key_alg_t alg_type, const char* subject,
                                                       const char* isv_name,
                                                       const char* keystore_name,
                                                       const char* csr_file_name,
                                                       int* asym_key_slot) {
    size_t keystore_buff_len = 0, isv_name_len = 0;
    ovsa_status_t ret     = OVSA_OK;
    char* keystore_buff   = NULL;
    int keystore_name_len = 0;
    BIO* keystore_bio     = NULL;
    ovsa_isv_keystore_t keystore[MAX_KEYPAIR];
    int sym_key_slot = -1;
    char magic_salt_buff[MAX_MAGIC_SALT_LENGTH];

    if ((ECDSA != alg_type) || (subject == NULL) || (isv_name == NULL) || (keystore_name == NULL) ||
        (csr_file_name == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric key pair failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    memset_s(&keystore, sizeof(ovsa_isv_keystore_t) * MAX_KEYPAIR, 0);

    ret = ovsa_crypto_generate_asymmetric_keys(alg_type, keystore[0].private_key,
                                               keystore[0].public_key);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric key pair failed in generating the primary "
                   "keys\n");
        goto end;
    }

    ret = ovsa_crypto_generate_asymmetric_keys(alg_type, keystore[1].private_key,
                                               keystore[1].public_key);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric key pair failed in generating the "
                   "secondary keys\n");
        goto end;
    }

    keystore_name_len = strnlen_s(keystore_name, MAX_NAME_SIZE);
    if (keystore_name_len == EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric key pair failed in getting the size of "
                   "the keystore name\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    ret = ovsa_crypto_generate_guid(keystore[0].key_guid);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric key pair failed in generating the guid\n");
        goto end;
    }

    isv_name_len = strnlen_s(isv_name, MAX_NAME_SIZE);
    if (isv_name_len == EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric key pair failed in getting the size of "
                   "the keystore name\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    if (memcpy_s(keystore[0].isv_name, MAX_NAME_SIZE, isv_name, isv_name_len) != EOK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error generating asymmetric key pair failed in getting keystore name\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

    keystore[0].isv_certificate = "";
    keystore_buff               = (char*)ovsa_crypto_app_malloc(
        (sizeof(ovsa_isv_keystore_t) * MAX_KEYPAIR) + KEYSTORE_BLOB_TEXT_SIZE, "keystore buffer");
    if (keystore_buff == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric key pair failed in allocating memory for "
                   "keystore buffer\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    ret = ovsa_json_create_isv_keystore(keystore, keystore_buff);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error generating asymmetric key pair failed in creating the keystore\n");
        goto end;
    }

    ret = ovsa_get_string_length(keystore_buff, &keystore_buff_len);
    if ((ret < OVSA_OK) || (keystore_buff_len == EOK)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric key pair failed in getting the size of "
                   "the keystore buffer\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    memset_s(magic_salt_buff, sizeof(magic_salt_buff), 0);
    ret = ovsa_crypto_derive_unsealing_key(magic_salt_buff, &sym_key_slot);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error generating asymmetric key pair failed in deriving unsealing key\n");
        goto end;
    }

    ret = ovsa_crypto_encrypt_keystore(sym_key_slot, keystore_name, keystore_buff,
                                       keystore_buff_len, magic_salt_buff);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric key pair failed in encrypting keystore\n");
        goto end;
    }

    ret = ovsa_crypto_generate_csr(keystore[0].private_key, subject, csr_file_name);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error generating asymmetric key pair failed in generating the csr file\n");
        goto end;
    }

    if (pthread_mutex_lock(&g_asymmetric_index_lock) != 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric key pair failed in acquiring the "
                   "mutex with error code = %s\n",
                   strerror(errno));
        ret = OVSA_MUTEX_LOCK_FAIL;
        goto end;
    }

    ret = ovsa_crypto_add_asymmetric_keystore_array(&keystore[0], asym_key_slot);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric key pair failed in adding to asymmetric "
                   "keystore array\n");
        goto exit;
    }

    ret = ovsa_crypto_add_asymmetric_keystore_array(&keystore[1], asym_key_slot);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric key pair failed in adding to asymmetric "
                   "keystore array\n");
        goto exit;
    }

    /* Return primary keyslot */
    *asym_key_slot = *asym_key_slot - 1;

exit:
    if (pthread_mutex_unlock(&g_asymmetric_index_lock) != 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating asymmetric key pair failed in releasing the "
                   "mutex with error code = %s\n",
                   strerror(errno));
        ret = OVSA_MUTEX_UNLOCK_FAIL;
        goto end;
    }

end:
    OPENSSL_cleanse(magic_salt_buff, sizeof(magic_salt_buff));
    memset_s(&keystore, sizeof(ovsa_isv_keystore_t) * MAX_KEYPAIR, 0);
    BIO_free_all(keystore_bio);
    ovsa_crypto_openssl_free(&keystore_buff);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

static ovsa_status_t ovsa_crypto_extract_keystore(const char* keystore_name,
                                                  ovsa_isv_keystore_t keystore[]) {
    ovsa_status_t ret         = OVSA_OK;
    size_t keystore_file_size = 0;
    char* keystore_data       = NULL;
    FILE* keystore_fp         = NULL;
    size_t cert_len           = 0;
    char* decrypted_buff      = NULL;
    size_t decrypted_buff_len = 0;
    int sym_key_slot          = -1;
    char magic_salt_buff[MAX_MAGIC_SALT_LENGTH];

    if (keystore_name == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error loading asymmetric key failed with invalid file path\n");
        return OVSA_INVALID_FILE_PATH;
    }

    /* Read keystore from on disk file */
    keystore_fp = fopen(keystore_name, "r");
    if (keystore_fp == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error loading asymmetric key failed in opening the keystore file\n");
        return OVSA_FILEOPEN_FAIL;
    }

    keystore_file_size = ovsa_crypto_get_file_size(keystore_fp);
    if (keystore_file_size == 0) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error loading asymmetric key failed in reading the keystore file size\n");
        ret = OVSA_FILEIO_FAIL;
        goto end;
    }

    keystore_data = (char*)ovsa_crypto_app_malloc(keystore_file_size, "keystore data");
    if (keystore_data == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error loading asymmetric key failed in allocating memory for keystore "
                   "data\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    if (!fread(keystore_data, 1, keystore_file_size, keystore_fp)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error loading asymmetric key failed in reading the keystore file\n");
        ret = OVSA_FILEIO_FAIL;
        goto end;
    }

    keystore_data[keystore_file_size - 1] = '\0';
    memset_s(magic_salt_buff, sizeof(magic_salt_buff), 0);

    ret = ovsa_crypto_derive_unsealing_key(magic_salt_buff, &sym_key_slot);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error loading asymmetric key pair failed in deriving unsealing key\n");
        goto end;
    }

    ret = ovsa_crypto_decrypt_keystore(sym_key_slot, keystore_data, keystore_file_size,
                                       magic_salt_buff, &decrypted_buff, &decrypted_buff_len);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error loading asymmetric key failed in decrypting the keystore\n");
        goto end;
    }

    ovsa_crypto_openssl_free(&keystore_data);
    keystore_data = (char*)ovsa_crypto_app_malloc(decrypted_buff_len + NULL_TERMINATOR,
                                                  "decrypted keystore data");
    if (keystore_data == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error loading asymmetric key failed in allocating memory for decrypted "
            "keystore data\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    if (memcpy_s(keystore_data, decrypted_buff_len, decrypted_buff, decrypted_buff_len) != EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error loading asymmetric key failed in getting the decrypted keystore "
                   "data\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

    ret = ovsa_json_getitem_size("certificate", keystore_data, &cert_len);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error loading asymmetric key failed in getting the certificate size\n");
        goto end;
    }

    if (cert_len != 0) {
        keystore[0].isv_certificate =
            (char*)ovsa_crypto_app_malloc(cert_len + NULL_TERMINATOR, "certificate");
        if (keystore[0].isv_certificate == NULL) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error loading asymmetric key failed in allocating memory for "
                       "certificate\n");
            ret = OVSA_MEMORY_ALLOC_FAIL;
            goto end;
        }
    }

    ret = ovsa_json_extract_keystore_info(keystore_data, keystore);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error loading asymmetric key failed in extracting the keystore info "
                   "from json blob\n");
        goto end;
    }

end:
    OPENSSL_cleanse(magic_salt_buff, sizeof(magic_salt_buff));
    ovsa_crypto_openssl_free(&decrypted_buff);
    if (keystore_fp != NULL) {
        fclose(keystore_fp);
    }
    ovsa_crypto_openssl_free(&keystore_data);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_load_asymmetric_key(const char* keystore_name, int* asym_key_slot) {
    ovsa_status_t ret = OVSA_OK;
    ovsa_isv_keystore_t keystore[MAX_KEYPAIR];

    if (keystore_name == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error loading asymmetric key failed with invalid file path\n");
        return OVSA_INVALID_FILE_PATH;
    }

    memset_s(&keystore, sizeof(ovsa_isv_keystore_t) * MAX_KEYPAIR, 0);

    ret = ovsa_crypto_extract_keystore(keystore_name, keystore);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error loading asymmetric key failed in extracting the keystore\n");
        goto end;
    }

    if (pthread_mutex_lock(&g_asymmetric_index_lock) != 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error loading asymmetric key failed in acquiring the "
                   "mutex with error code = %s\n",
                   strerror(errno));
        ret = OVSA_MUTEX_LOCK_FAIL;
        goto end;
    }

    ret = ovsa_crypto_add_asymmetric_keystore_array(&keystore[0], asym_key_slot);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error loading asymmetric key failed in adding to asymmetric keystore "
                   "array\n");
        goto exit;
    }

    ret = ovsa_crypto_add_asymmetric_keystore_array(&keystore[1], asym_key_slot);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error loading asymmetric key failed in adding to asymmetric keystore "
                   "array\n");
        goto exit;
    }

    /* Return primary keyslot */
    *asym_key_slot = *asym_key_slot - 1;

exit:
    if (pthread_mutex_unlock(&g_asymmetric_index_lock) != 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error loading asymmetric key failed in releasing the "
                   "mutex with error code = %s\n",
                   strerror(errno));
        ret = OVSA_MUTEX_UNLOCK_FAIL;
        goto end;
    }
end:
    memset_s(&keystore, sizeof(ovsa_isv_keystore_t) * MAX_KEYPAIR, 0);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_get_asymmetric_key_slot(const char* keystore_name, int* asym_key_slot) {
    ovsa_status_t ret = OVSA_OK;
    size_t cert_len = 0, keystore_cert_len = 0;
    int asymmetric_index = 0, isv_name_indicator = -1;
    int public_key_indicator = -1, private_key_indicator = -1;
    int key_guid_indicator = -1, cert_indicator = -1;
    ovsa_isv_keystore_t keystore[MAX_KEYPAIR];

    if (keystore_name == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error getting asymmetric key slot failed with invalid file path\n");
        return OVSA_INVALID_FILE_PATH;
    }

    memset_s(&keystore, sizeof(ovsa_isv_keystore_t) * MAX_KEYPAIR, 0);

    ret = ovsa_crypto_extract_keystore(keystore_name, keystore);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error getting asymmetric key slot failed in extracting the keystore\n");
        goto end;
    }

    if (keystore[0].isv_certificate != NULL) {
        ret = ovsa_get_string_length(keystore[0].isv_certificate, &cert_len);
        if (ret < OVSA_OK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error getting asymmetric key slot failed in getting the "
                       "certificate length\n");
            goto end;
        }
    }

    for (asymmetric_index = 0; asymmetric_index < MAX_KEY_SLOT; asymmetric_index++) {
        if (strcmp_s(g_key_store[asymmetric_index].isv_name, MAX_NAME_SIZE, keystore[0].isv_name,
                     &isv_name_indicator) != EOK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error getting asymmetric key slot failed in comparing the "
                       "keystore name\n");
            ret = OVSA_CRYPTO_GENERIC_ERROR;
            goto end;
        }

        if (strcmp_s(g_key_store[asymmetric_index].public_key, MAX_KEY_SIZE, keystore[0].public_key,
                     &public_key_indicator) != EOK) {
            BIO_printf(
                g_bio_err,
                "LibOVSA: Error getting asymmetric key slot failed in comparing the public key\n");
            ret = OVSA_CRYPTO_GENERIC_ERROR;
            goto end;
        }

        if (strcmp_s(g_key_store[asymmetric_index].private_key, MAX_KEY_SIZE,
                     keystore[0].private_key, &private_key_indicator) != EOK) {
            BIO_printf(
                g_bio_err,
                "LibOVSA: Error getting asymmetric key slot failed in comparing the private key\n");
            ret = OVSA_CRYPTO_GENERIC_ERROR;
            goto end;
        }

        if (strcmp_s(g_key_store[asymmetric_index].key_guid, sizeof(GUID), keystore[0].key_guid,
                     &key_guid_indicator) != EOK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error getting asymmetric key slot failed in comparing the guid\n");
            ret = OVSA_CRYPTO_GENERIC_ERROR;
            goto end;
        }

        if (g_key_store[asymmetric_index].isv_certificate != NULL) {
            ret = ovsa_get_string_length(g_key_store[asymmetric_index].isv_certificate,
                                         &keystore_cert_len);
            if (ret < OVSA_OK) {
                BIO_printf(g_bio_err,
                           "LibOVSA: Error getting asymmetric key slot failed in getting the "
                           "keystore certificate length\n");
                goto end;
            }
        }

        if ((cert_len != 0) && (keystore_cert_len != 0)) {
            if ((g_key_store[asymmetric_index].isv_certificate != NULL) &&
                (keystore[0].isv_certificate != NULL)) {
                ret = ovsa_compare_strings(g_key_store[asymmetric_index].isv_certificate,
                                           keystore[0].isv_certificate, &cert_indicator);
                if (ret < OVSA_OK) {
                    BIO_printf(g_bio_err,
                               "LibOVSA: Error getting asymmetric key slot failed in comparing the "
                               "certificate\n");
                    ret = OVSA_CRYPTO_GENERIC_ERROR;
                    goto end;
                }
            } else {
                cert_indicator = -1;
            }
        } else {
            cert_indicator = 0;
        }

        /* If matching keyslot found, return the keyslot */
        if ((isv_name_indicator == 0) && (public_key_indicator == 0) &&
            (private_key_indicator == 0) && (key_guid_indicator == 0) && (cert_indicator == 0)) {
            *asym_key_slot = asymmetric_index;
            break;
        }
    }

    if (asymmetric_index >= MAX_KEY_SLOT) {
        BIO_printf(g_bio_err, "LibOVSA: Error matching keyslot could not be found\n");
        *asym_key_slot = -1;
        ret            = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

end:
    memset_s(&keystore, sizeof(ovsa_isv_keystore_t) * MAX_KEYPAIR, 0);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_store_certificate_keystore(int asym_key_slot, bool peer_cert,
                                                     const char* cert, bool lifetime_validity_check,
                                                     const char* keystore_name) {
    size_t cert_len = 0, keystore_size = 0;
    ovsa_status_t ret        = OVSA_OK;
    size_t keystore_buff_len = 0;
    char* keystore_buff      = NULL;
    BIO* keystore_bio        = NULL;
    int sym_key_slot         = -1;
    char magic_salt_buff[MAX_MAGIC_SALT_LENGTH];

    if ((asym_key_slot < MIN_KEY_SLOT) || (asym_key_slot >= MAX_KEY_SLOT) || (cert == NULL) ||
        (keystore_name == NULL)) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error storing certificate to keystore failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    ret = ovsa_crypto_verify_certificate(asym_key_slot, peer_cert, cert, lifetime_validity_check);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error storing certificate to keystore failed in verifying the certificate\n");
        goto end;
    }

    ret = ovsa_get_string_length(cert, &cert_len);
    if ((ret < OVSA_OK) || (cert_len == EOK)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error storing certificate to keystore failed in getting the size of "
                   "the certificate\n");
        ret = OVSA_INVALID_FILE_PATH;
        goto end;
    }

    if (pthread_mutex_lock(&g_asymmetric_index_lock) != 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error storing certificate to keystore failed in acquiring the "
                   "mutex with error code = %s\n",
                   strerror(errno));
        ret = OVSA_MUTEX_LOCK_FAIL;
        goto end;
    }

    ret = ovsa_crypto_add_cert_keystore_array(asym_key_slot, cert);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error storing certificate to keystore failed in adding certificate to "
                   "keystore array\n");
        goto exit;
    }

    if (pthread_mutex_unlock(&g_asymmetric_index_lock) != 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error storing certificate to keystore failed in releasing the "
                   "mutex with error code = %s\n",
                   strerror(errno));
        ret = OVSA_MUTEX_UNLOCK_FAIL;
        goto end;
    }

    keystore_size = cert_len + sizeof(ovsa_isv_keystore_t) + KEYSTORE_BLOB_TEXT_SIZE;
    keystore_buff = (char*)ovsa_crypto_app_malloc(keystore_size * MAX_KEYPAIR, "keystore buffer");
    if (keystore_buff == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error storing certificate to keystore failed in allocating memory for "
                   "keysore buffer\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    ret = ovsa_json_create_isv_keystore(&g_key_store[asym_key_slot], keystore_buff);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error storing certificate to keystore failed in creating the keystore\n");
        goto end;
    }

    ret = ovsa_get_string_length(keystore_buff, &keystore_buff_len);
    if ((ret < OVSA_OK) || (keystore_buff_len == EOK)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error storing certificate to keystore failed in getting the size of "
                   "the keystore buffer\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    memset_s(magic_salt_buff, sizeof(magic_salt_buff), 0);
    ret = ovsa_crypto_derive_unsealing_key(magic_salt_buff, &sym_key_slot);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error storing certificate to keystore failed in deriving unsealing key\n");
        goto end;
    }

    ret = ovsa_crypto_encrypt_keystore(sym_key_slot, keystore_name, keystore_buff,
                                       keystore_buff_len, magic_salt_buff);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error storing certificate to keystore failed in encrypting keystore\n");
        goto end;
    }
    goto end;

exit:
    if (pthread_mutex_unlock(&g_asymmetric_index_lock) != 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error storing certificate to keystore failed in releasing the "
                   "mutex with error code = %s\n",
                   strerror(errno));
        ret = OVSA_MUTEX_UNLOCK_FAIL;
        goto end;
    }

end:
    OPENSSL_cleanse(magic_salt_buff, sizeof(magic_salt_buff));
    ovsa_crypto_openssl_free(&keystore_buff);
    BIO_free_all(keystore_bio);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_get_certificate(int asym_key_slot, char** cert) {
    ovsa_status_t ret    = OVSA_OK;
    size_t cert_buff_len = 0;
    char* cert_buff      = NULL;

    if ((asym_key_slot < MIN_KEY_SLOT) || (asym_key_slot >= MAX_KEY_SLOT)) {
        BIO_printf(g_bio_err, "LibOVSA: Error getting certificate failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    if (g_key_store[asym_key_slot].isv_certificate == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error getting certificate failed since certificate is not stored in "
                   "keystore\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    cert_buff = g_key_store[asym_key_slot].isv_certificate;
    ret       = ovsa_get_string_length(g_key_store[asym_key_slot].isv_certificate, &cert_buff_len);
    if ((ret < OVSA_OK) || (cert_buff_len == EOK)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error getting certificate failed in getting the size of the "
                   "certificate buffer\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    /* App needs to free the certificate memory */
    *cert = (char*)ovsa_crypto_app_malloc(cert_buff_len + NULL_TERMINATOR, "cert buffer");
    if (*cert == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error getting certificate failed in allocating memory for certificate "
                   "buffer\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    if (memcpy_s(*cert, cert_buff_len, cert_buff, cert_buff_len) != EOK) {
        BIO_printf(g_bio_err, "LibOVSA: Error getting certificate failed to get the certificate\n");
        ovsa_crypto_openssl_free(cert);
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

end:
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_store_certificate_file(int asym_key_slot, bool peer_cert,
                                                 bool lifetime_validity_check,
                                                 const char* cert_file_name) {
    ovsa_status_t ret    = OVSA_OK;
    size_t cert_buff_len = 0;
    char* cert_buff      = NULL;
    BIO* cert_bio        = NULL;

    if ((asym_key_slot < MIN_KEY_SLOT) || (asym_key_slot >= MAX_KEY_SLOT) ||
        (cert_file_name == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error storing certificate to file failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    if (g_key_store[asym_key_slot].isv_certificate == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error storing certificate to file failed since certificate is not "
                   "stored in keystore\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    cert_buff = g_key_store[asym_key_slot].isv_certificate;
    ret       = ovsa_get_string_length(g_key_store[asym_key_slot].isv_certificate, &cert_buff_len);
    if ((ret < OVSA_OK) || (cert_buff_len == EOK)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error storing certificate to file failed in getting the size of the "
                   "certificate buffer\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    ret = ovsa_crypto_verify_certificate(asym_key_slot, peer_cert, cert_buff,
                                         lifetime_validity_check);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error storing certificate to file failed in verifying the certificate\n");
        goto end;
    }

    cert_bio = BIO_new_file(cert_file_name, "wx");
    if (cert_bio == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error storing certificate to file failed in creating the certificate file\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    /* Write certificate file on to disk */
    if (!BIO_write(cert_bio, cert_buff, cert_buff_len)) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error storing certificate to file failed in writing the certificate file\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

end:
    BIO_free_all(cert_bio);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_sign_file(int asym_key_slot, const char* file_to_sign,
                                    const char* signed_file) {
    int siglen = 0, sign = 0;
    ovsa_status_t ret       = OVSA_OK;
    unsigned char* sign_buf = NULL;
    FILE* file_to_sign_fp   = NULL;
    const EVP_MD* md        = NULL;
    EVP_PKEY* sigkey        = NULL;
    BIO* input_file         = NULL;
    BIO* write_bio          = NULL;
    BIO* read_file          = NULL;
    BIO* signature          = NULL;
    BIO* bmd                = NULL;
    BIO* b64                = NULL;
    size_t private_key_len = 0, sign_file_size = 0;
    char private_key[MAX_KEY_SIZE];

    if ((asym_key_slot < MIN_KEY_SLOT) || (asym_key_slot >= MAX_KEY_SLOT) ||
        (file_to_sign == NULL) || (signed_file == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error signing the file failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    private_key_len = strnlen_s(g_key_store[asym_key_slot].private_key, MAX_KEY_SIZE);
    if (private_key_len == EOK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error signing the file failed in getting the size of the private key\n");
        return OVSA_CRYPTO_GENERIC_ERROR;
    }

    memset_s(private_key, MAX_KEY_SIZE, 0);

    if (memcpy_s(private_key, MAX_KEY_SIZE, g_key_store[asym_key_slot].private_key,
                 private_key_len) != EOK) {
        BIO_printf(g_bio_err, "LibOVSA: Error signing the file failed to get the private key\n");
        return OVSA_MEMIO_ERROR;
    }

    read_file = BIO_new(BIO_s_file());
    if (read_file == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error signing the file failed in getting new BIO for the input file\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    bmd = BIO_new(BIO_f_md());
    if (bmd == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing the file failed in getting the message digest\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing the file failed in getting the b64 encode method\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    input_file = BIO_push(bmd, read_file);
    /* Read file_to_sign from on disk file to check if its a valid file */
    file_to_sign_fp = fopen(file_to_sign, "r");
    if (file_to_sign_fp == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error signing the file failed in opening the input file\n");
        ret = OVSA_FILEOPEN_FAIL;
        goto end;
    }

    sign_file_size = ovsa_crypto_get_file_size(file_to_sign_fp);
    if (sign_file_size == 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing the file failed in reading the input file size\n");
        ret = OVSA_FILEIO_FAIL;
        goto end;
    }

    if (!(BIO_read_filename(read_file, file_to_sign))) {
        BIO_printf(g_bio_err, "LibOVSA: Error signing the file failed in reading the input file\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    sigkey = ovsa_crypto_load_key(private_key, "private key");
    if (sigkey != NULL) {
        EVP_MD_CTX* mctx   = NULL;
        EVP_PKEY_CTX* pctx = NULL;
        md                 = EVP_sha512();
        if (!BIO_get_md_ctx(bmd, &mctx)) {
            BIO_printf(
                g_bio_err,
                "LibOVSA: Error signing the file failed in getting the context for digest\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }

        sign = EVP_DigestSignInit(mctx, &pctx, md, NULL, sigkey);
        if (!sign) {
            BIO_printf(
                g_bio_err,
                "LibOVSA: Error signing the file failed in setting up the signing context\n");
            ret = OVSA_CRYPTO_EVP_ERROR;
            goto end;
        }
    } else {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error signing the file failed in loading the private key into memory\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }

    sign_buf =
        (unsigned char*)ovsa_crypto_app_malloc(EVP_ENCODE_LENGTH(BUFSIZE), "evp sign buffer");
    if (sign_buf == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error signing the file failed in allocating memory for evp sign buffer\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    signature = BIO_new_file(signed_file, "wx");
    if (signature == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing the file failed in creating the signature file\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    write_bio = signature;
    write_bio = BIO_push(b64, signature);
    ret = ovsa_crypto_do_sign_verify_hash(sign_buf, input_file, sigkey, NULL, siglen, file_to_sign,
                                          write_bio);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing the file failed in generating the signature\n");
        goto end;
    }

    (void)BIO_reset(bmd);
end:
    if (file_to_sign_fp != NULL) {
        fclose(file_to_sign_fp);
    }
    OPENSSL_cleanse(private_key, MAX_KEY_SIZE);
    ovsa_crypto_openssl_free((char**)&sign_buf);
    EVP_PKEY_free(sigkey);
    BIO_free(b64);
    BIO_free_all(signature);
    BIO_free(bmd);
    BIO_free_all(read_file);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_sign_mem(int asym_key_slot, const char* in_buff, size_t in_buff_len,
                                   char* out_buff) {
    ovsa_status_t ret            = OVSA_OK;
    unsigned char* sign_mem_buff = NULL;
    size_t private_key_len       = 0;
    BUF_MEM* signed_ptr          = NULL;
    const EVP_MD* md             = NULL;
    EVP_PKEY* sigkey             = NULL;
    BIO* input_bio               = NULL;
    BIO* write_bio               = NULL;
    BIO* read_bio                = NULL;
    BIO* out_bio                 = NULL;
    BIO* bmd                     = NULL;
    BIO* b64                     = NULL;
    int siglen = 0, sign = 0;
    char private_key[MAX_KEY_SIZE];

    if ((asym_key_slot < MIN_KEY_SLOT) || (asym_key_slot >= MAX_KEY_SLOT) || (in_buff == NULL) ||
        (in_buff_len == 0) || (out_buff == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing the memory buffer failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    private_key_len = strnlen_s(g_key_store[asym_key_slot].private_key, MAX_KEY_SIZE);
    if (private_key_len == EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing the memory buffer failed in getting the size for "
                   "private key\n");
        return OVSA_CRYPTO_GENERIC_ERROR;
    }

    memset_s(private_key, MAX_KEY_SIZE, 0);

    if (memcpy_s(private_key, MAX_KEY_SIZE, g_key_store[asym_key_slot].private_key,
                 private_key_len) != EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing the memory buffer failed in getting the private key\n");
        return OVSA_MEMIO_ERROR;
    }

    read_bio = BIO_new(BIO_s_mem());
    if (read_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing the memory buffer failed in getting new BIO for the "
                   "input buffer\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    bmd = BIO_new(BIO_f_md());
    if (bmd == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error signing the memory buffer failed in getting the message digest\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error signing the memory buffer failed in getting the b64 encode method\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    input_bio = BIO_push(bmd, read_bio);
    if (BIO_puts(read_bio, in_buff) <= 0) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error signing the memory buffer failed in writing to input buffer BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    sigkey = ovsa_crypto_load_key(private_key, "private key");
    if (sigkey != NULL) {
        EVP_MD_CTX* mctx   = NULL;
        EVP_PKEY_CTX* pctx = NULL;
        md                 = EVP_sha512();
        if (!BIO_get_md_ctx(bmd, &mctx)) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error signing the memory buffer failed in getting the context for "
                       "digest\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }

        sign = EVP_DigestSignInit(mctx, &pctx, md, NULL, sigkey);
        if (!sign) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error signing the memory buffer failed in setting up the signing "
                       "context\n");
            ret = OVSA_CRYPTO_EVP_ERROR;
            goto end;
        }
    } else {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing the memory buffer failed in loading the private key "
                   "into memory\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    sign_mem_buff =
        (unsigned char*)ovsa_crypto_app_malloc(EVP_ENCODE_LENGTH(BUFSIZE), "evp sign_mem buffer");
    if (sign_mem_buff == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing the memory buffer failed in allocating memory for evp "
                   "sign buffer\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    out_bio = BIO_new(BIO_s_mem());
    if (out_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing the memory buffer failed in getting new BIO for the "
                   "output buffer\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    write_bio = out_bio;
    write_bio = BIO_push(b64, out_bio);
    ret = ovsa_crypto_do_sign_verify_hash(sign_mem_buff, input_bio, sigkey, NULL, siglen, in_buff,
                                          write_bio);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing the memory buffer failed in generating the signature\n");
        goto end;
    }

    BIO_get_mem_ptr(write_bio, &signed_ptr);
    if (signed_ptr == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing the memory buffer failed to extract the signature\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (memcpy_s(out_buff, MAX_SIGNATURE_SIZE, signed_ptr->data, signed_ptr->length) != EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing the memory buffer failed in getting the signature\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

    (void)BIO_reset(bmd);
end:
    OPENSSL_cleanse(private_key, MAX_KEY_SIZE);
    EVP_PKEY_free(sigkey);
    ovsa_crypto_openssl_free((char**)&sign_mem_buff);
    BIO_free(b64);
    BIO_free_all(out_bio);
    BIO_free(bmd);
    BIO_free_all(read_bio);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_verify_file(int asym_key_slot, const char* file_to_verify,
                                      const char* signature) {
    ovsa_status_t ret          = OVSA_OK;
    unsigned char* verify_buff = NULL;
    unsigned char* sigbuff     = NULL;
    const EVP_MD* md           = NULL;
    BIO* input_file            = NULL;
    BIO* read_file             = NULL;
    BIO* write_bio             = NULL;
    EVP_PKEY* pkey             = NULL;
    BIO* sigbio                = NULL;
    char* cert                 = NULL;
    BIO* bmd                   = NULL;
    BIO* b64                   = NULL;
    int siglen = 0, verify = 0;
    char public_key[MAX_KEY_SIZE];

    if ((asym_key_slot < MIN_KEY_SLOT) || (asym_key_slot >= MAX_KEY_SLOT) ||
        (file_to_verify == NULL) || (signature == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error verifying the file failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    ret = ovsa_crypto_get_certificate(asym_key_slot, &cert);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying the file failed in getting the certificate\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    memset_s(public_key, MAX_KEY_SIZE, 0);

    ret = ovsa_crypto_extract_pubkey_certificate(cert, public_key);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying the file failed in extracting the public key\n");
        goto end;
    }

    read_file = BIO_new(BIO_s_file());
    if (read_file == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error verifying the file failed in getting new BIO for the input file\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    bmd = BIO_new(BIO_f_md());
    if (bmd == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying the file failed in getting the message digest\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying the file failed in getting the b64 encode method\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    input_file = BIO_push(bmd, read_file);
    if (!(BIO_read_filename(read_file, file_to_verify))) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying the file failed in reading the input file\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    pkey = ovsa_crypto_load_key(public_key, "public key");
    if (pkey != NULL) {
        EVP_MD_CTX* mctx   = NULL;
        EVP_PKEY_CTX* pctx = NULL;
        md                 = EVP_sha512();
        if (!BIO_get_md_ctx(bmd, &mctx)) {
            BIO_printf(
                g_bio_err,
                "LibOVSA: Error verifying the file failed in getting the context for digest\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }

        verify = EVP_DigestVerifyInit(mctx, &pctx, md, NULL, pkey);
        if (!verify) {
            BIO_printf(
                g_bio_err,
                "LibOVSA: Error verifying the file failed in setting up the verifying context\n");
            ret = OVSA_CRYPTO_EVP_ERROR;
            goto end;
        }

        write_bio = BIO_new(BIO_s_mem());
        if (write_bio == NULL) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error verifying the file failed in getting new BIO for the "
                       "signature file\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }

        sigbio = write_bio;
        if (BIO_puts(sigbio, signature) <= 0) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error verifying the file failed in writing to signature BIO\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }

        sigbio  = BIO_push(b64, sigbio);
        siglen  = EVP_PKEY_size(pkey);
        sigbuff = (unsigned char*)ovsa_crypto_app_malloc(siglen, "signature buffer");
        if (sigbuff == NULL) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error verifying the file failed in allocating memory for evp "
                       "signature buffer\n");
            ret = OVSA_MEMORY_ALLOC_FAIL;
            goto end;
        }

        siglen = BIO_read(sigbio, sigbuff, siglen);
        if (siglen <= 0) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error verifying the file failed in reading the signature file\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }
    } else {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error verifying the file failed in loading the public key into memory\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    verify_buff =
        (unsigned char*)ovsa_crypto_app_malloc(EVP_ENCODE_LENGTH(BUFSIZE), "evp verify buffer");
    if (verify_buff == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying the file failed in allocating memory for evp verify "
                   "buffer\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    ret = ovsa_crypto_do_sign_verify_hash(verify_buff, input_file, pkey, sigbuff, siglen,
                                          file_to_verify, NULL);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying the file failed in verifying the signature\n");
        goto end;
    }

    (void)BIO_reset(bmd);
end:
    OPENSSL_cleanse(public_key, MAX_KEY_SIZE);
    ovsa_crypto_openssl_free((char**)&sigbuff);
    ovsa_crypto_openssl_free(&cert);
    EVP_PKEY_free(pkey);
    ovsa_crypto_openssl_free((char**)&verify_buff);
    BIO_free(b64);
    BIO_free_all(write_bio);
    BIO_free(bmd);
    BIO_free_all(read_file);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_verify_mem(int asym_key_slot, const char* in_buff, size_t in_buff_len,
                                     const char* signature) {
    ovsa_status_t ret              = OVSA_OK;
    unsigned char* verify_mem_buff = NULL;
    unsigned char* sigbuff         = NULL;
    const EVP_MD* md               = NULL;
    BIO* input_bio                 = NULL;
    BIO* write_bio                 = NULL;
    EVP_PKEY* pkey                 = NULL;
    BIO* read_bio                  = NULL;
    BIO* sigbio                    = NULL;
    char* cert                     = NULL;
    BIO* bmd                       = NULL;
    BIO* b64                       = NULL;
    int siglen = 0, verify = 0;
    char public_key[MAX_KEY_SIZE];

    if ((asym_key_slot < MIN_KEY_SLOT) || (asym_key_slot >= MAX_KEY_SLOT) || (in_buff == NULL) ||
        (in_buff_len == 0) || (signature == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying the memory buffer failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    ret = ovsa_crypto_get_certificate(asym_key_slot, &cert);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error verifying the memory buffer failed in getting the certificate\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    memset_s(public_key, MAX_KEY_SIZE, 0);

    ret = ovsa_crypto_extract_pubkey_certificate(cert, public_key);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error verifying the memory buffer failed in extracting the public key\n");
        goto end;
    }

    read_bio = BIO_new(BIO_s_mem());
    if (read_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying the memory buffer failed in getting new BIO for the "
                   "input buffer\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    bmd = BIO_new(BIO_f_md());
    if (bmd == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error verifying the memory buffer failed in getting the message digest\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error verifying the memory buffer failed in getting the b64 encode method\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    input_bio = BIO_push(bmd, read_bio);
    if (BIO_puts(read_bio, in_buff) <= 0) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error verifying the memory buffer failed in writing to input buffer BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    pkey = ovsa_crypto_load_key(public_key, "public key");
    if (pkey != NULL) {
        EVP_MD_CTX* mctx   = NULL;
        EVP_PKEY_CTX* pctx = NULL;
        md                 = EVP_sha512();
        if (!BIO_get_md_ctx(bmd, &mctx)) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error verifying the memory buffer failed in getting the context "
                       "for digest\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }
        verify = EVP_DigestVerifyInit(mctx, &pctx, md, NULL, pkey);
        if (!verify) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error verifying the memory buffer failed in setting up the "
                       "verifying context\n");
            ret = OVSA_CRYPTO_EVP_ERROR;
            goto end;
        }

        write_bio = BIO_new(BIO_s_mem());
        if (write_bio == NULL) {
            BIO_printf(
                g_bio_err,
                "LibOVSA: Error verifying the memory buffer failed in getting new BIO for the "
                "signature buffer\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }

        sigbio = write_bio;
        if (BIO_puts(sigbio, signature) <= 0) {
            BIO_printf(
                g_bio_err,
                "LibOVSA: Error verifying the memory buffer failed in writing to signature BIO\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }

        sigbio  = BIO_push(b64, sigbio);
        siglen  = EVP_PKEY_size(pkey);
        sigbuff = (unsigned char*)ovsa_crypto_app_malloc(siglen, "signature buffer");
        if (sigbuff == NULL) {
            BIO_printf(
                g_bio_err,
                "LibOVSA: Error verifying the memory buffer failed in allocating memory for evp "
                "signature buffer\n");
            ret = OVSA_MEMORY_ALLOC_FAIL;
            goto end;
        }

        siglen = BIO_read(sigbio, sigbuff, siglen);
        if (siglen <= 0) {
            BIO_printf(
                g_bio_err,
                "LibOVSA: Error verifying the memory buffer failed in reading to signature BIO\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }
    } else {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying the memory buffer failed in loading the public key "
                   "into memory\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    verify_mem_buff =
        (unsigned char*)ovsa_crypto_app_malloc(EVP_ENCODE_LENGTH(BUFSIZE), "evp verify_mem buffer");
    if (verify_mem_buff == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying the memory buffer failed in allocating memory for evp "
                   "verify buffer\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    ret = ovsa_crypto_do_sign_verify_hash(verify_mem_buff, input_bio, pkey, sigbuff, siglen,
                                          in_buff, NULL);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error verifying the memory buffer failed in verifying the signature\n");
        goto end;
    }

    (void)BIO_reset(bmd);
end:
    OPENSSL_cleanse(public_key, MAX_KEY_SIZE);
    EVP_PKEY_free(pkey);
    ovsa_crypto_openssl_free((char**)&sigbuff);
    ovsa_crypto_openssl_free(&cert);
    ovsa_crypto_openssl_free((char**)&verify_mem_buff);
    BIO_free(b64);
    BIO_free_all(write_bio);
    BIO_free(bmd);
    BIO_free_all(read_bio);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_compute_hmac(int keyiv_hmac_slot, const char* in_buff, size_t in_buff_len,
                                       char* out_buff) {
    ovsa_status_t ret        = OVSA_OK;
    unsigned char* hmac_buff = NULL;
    EVP_MD_CTX* ctx          = NULL;
    BUF_MEM* hmac_ptr        = NULL;
    const EVP_MD* md         = EVP_sha512();
    const EVP_CIPHER* cipher = NULL;
    EVP_PKEY* pkey           = NULL;
    BIO* write_bio           = NULL;
    BIO* out_bio             = NULL;
    BIO* keyiv_hmac_bio      = NULL;
    BIO* keyiv_hmac_read_bio = NULL;
    BIO* b64                 = NULL;
    BIO* keyiv_hmac_b64      = NULL;
    size_t keyiv_hmac_len = 0, siglen = 0;
    size_t hmac_key_len = 0, hmaclen = 0;
    size_t buff_len = 0;
    int sign        = 0;
    unsigned char keyiv_hmac[MAX_KEYIV_HMAC_LENGTH];
    unsigned char hmac[MAX_HMAC_LENGTH];

    if ((keyiv_hmac_slot < MIN_KEY_SLOT) || (keyiv_hmac_slot >= MAX_KEY_SLOT) ||
        (in_buff == NULL) || (in_buff_len == 0) || (out_buff == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error computing hmac failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    cipher       = EVP_aes_256_ctr();
    hmac_key_len = EVP_CIPHER_key_length(cipher);

    keyiv_hmac_read_bio = BIO_new(BIO_s_mem());
    if (keyiv_hmac_read_bio == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error computing hmac failed in getting new BIO for the keyiv_hmac buffer\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    keyiv_hmac_bio = keyiv_hmac_read_bio;
    if (BIO_puts(keyiv_hmac_read_bio, g_sym_key[keyiv_hmac_slot]) <= 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error computing hmac failed in writing to keyiv_hmac BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if ((keyiv_hmac_b64 = BIO_new(BIO_f_base64())) == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error computing hmac failed in getting the b64 encode method for "
                   "keyiv_hmac\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    keyiv_hmac_bio = BIO_push(keyiv_hmac_b64, keyiv_hmac_bio);
    keyiv_hmac_len = strnlen_s(g_sym_key[keyiv_hmac_slot], MAX_KEYIV_HMAC_LENGTH);
    if (keyiv_hmac_len == EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error computing hmac failed in getting the size for keyiv_hmac\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    memset_s(keyiv_hmac, MAX_KEYIV_HMAC_LENGTH, 0);
    memset_s(hmac, MAX_HMAC_LENGTH, 0);

    keyiv_hmac_len = BIO_read(keyiv_hmac_bio, keyiv_hmac, keyiv_hmac_len);
    if (keyiv_hmac_len <= 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error computing hmac failed in reading to keyiv_hmac BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (memcpy_s(hmac, MAX_HMAC_LENGTH,
                 keyiv_hmac + EVP_CIPHER_key_length(cipher) + EVP_CIPHER_iv_length(cipher),
                 hmac_key_len) != EOK) {
        BIO_printf(g_bio_err, "LibOVSA: Error verifying hmac failed in getting the hmac key\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

    pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, hmac, hmac_key_len);
    if (pkey == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error computing hmac failed in loading the hmac key into memory\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error computing hmac failed in getting the b64 encode method\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error computing hmac failed in creating the context for digest\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    sign = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
    if (sign != 1) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error computing hmac failed in setting up the signing context\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }

    ret = ovsa_get_string_length(in_buff, &buff_len);
    if ((ret < OVSA_OK) || (buff_len == EOK)) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error computing hmac failed in getting the size of the input buffer\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    sign = EVP_DigestSignUpdate(ctx, in_buff, buff_len);
    if (sign != 1) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error computing hmac failed in hashing the data into context\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }

    sign = EVP_DigestSignFinal(ctx, NULL, &siglen);
    if (sign != 1) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error computing hmac failed in getting the size of the hmac buffer\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }

    out_bio = BIO_new(BIO_s_mem());
    if (out_bio == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error computing hmac failed in getting new BIO for the output buffer\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    write_bio = out_bio;
    write_bio = BIO_push(b64, out_bio);

    hmac_buff = (unsigned char*)ovsa_crypto_app_malloc(siglen + NULL_TERMINATOR, "hmac buffer");
    if (hmac_buff == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error computing hmac failed in allocating memory for hmac buffer\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    hmaclen = siglen;
    sign    = EVP_DigestSignFinal(ctx, hmac_buff, &hmaclen);
    if (sign != 1) {
        BIO_printf(g_bio_err, "LibOVSA: Error computing hmac failed in signing the data\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }

    if (!BIO_write(write_bio, hmac_buff, siglen)) {
        BIO_printf(g_bio_err, "LibOVSA: Error computing hmac failed in writing the hmac\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (!BIO_flush(write_bio)) {
        BIO_printf(g_bio_err, "LibOVSA: Error computing hmac failed in flushing the hmac\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    BIO_get_mem_ptr(write_bio, &hmac_ptr);
    if (hmac_ptr == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error computing hmac failed to extract the hmac\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (memcpy_s(out_buff, MAX_MAC_SIZE, hmac_ptr->data, hmac_ptr->length) != EOK) {
        BIO_printf(g_bio_err, "LibOVSA: Error computing hmac failed in getting the hmac\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

    BIO_printf(g_bio_err, "LibOVSA: Computed HMAC successfully\n");

end:
    OPENSSL_cleanse(keyiv_hmac, MAX_KEYIV_HMAC_LENGTH);
    OPENSSL_cleanse(hmac, MAX_HMAC_LENGTH);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(b64);
    BIO_free_all(out_bio);
    BIO_free(keyiv_hmac_b64);
    BIO_free_all(keyiv_hmac_read_bio);
    ovsa_crypto_openssl_free((char**)&hmac_buff);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

static ovsa_status_t ovsa_crypto_verify_hmac(int keyiv_hmac_slot, const char* in_buff,
                                             size_t in_buff_len, const char* signature) {
    ovsa_status_t ret        = OVSA_OK;
    EVP_MD_CTX* ctx          = NULL;
    const EVP_MD* md         = EVP_sha512();
    EVP_PKEY* pkey           = NULL;
    BIO* out_bio             = NULL;
    BIO* sigbio              = NULL;
    BIO* keyiv_hmac_read_bio = NULL;
    BIO* keyiv_hmac_bio      = NULL;
    BIO* b64                 = NULL;
    BIO* keyiv_hmac_b64      = NULL;
    unsigned char* sigbuff   = NULL;
    const EVP_CIPHER* cipher = NULL;
    unsigned char verify_buff[EVP_MAX_MD_SIZE];
    size_t hmac_key_len = 0, siglen = 0;
    size_t keyiv_hmac_len = 0, buff_len = 0;
    size_t hmaclen = 0;
    int sign       = 0;
    unsigned char keyiv_hmac[MAX_KEYIV_HMAC_LENGTH];
    unsigned char hmac[MAX_HMAC_LENGTH];

    if ((keyiv_hmac_slot < MIN_KEY_SLOT) || (keyiv_hmac_slot >= MAX_KEY_SLOT) ||
        (in_buff == NULL) || (in_buff_len == 0) || (signature == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error verifying hmac failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    cipher       = EVP_aes_256_ctr();
    hmac_key_len = EVP_CIPHER_key_length(cipher);

    keyiv_hmac_read_bio = BIO_new(BIO_s_mem());
    if (keyiv_hmac_read_bio == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error verifying hmac failed in getting new BIO for the keyiv_hmac buffer\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    keyiv_hmac_bio = keyiv_hmac_read_bio;
    if (BIO_puts(keyiv_hmac_read_bio, g_sym_key[keyiv_hmac_slot]) <= 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying hmac failed in writing to keyiv_hmac BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if ((keyiv_hmac_b64 = BIO_new(BIO_f_base64())) == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying hmac failed in getting the b64 encode method for "
                   "keyiv_hmac\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    keyiv_hmac_bio = BIO_push(keyiv_hmac_b64, keyiv_hmac_bio);
    keyiv_hmac_len = strnlen_s(g_sym_key[keyiv_hmac_slot], MAX_KEYIV_HMAC_LENGTH);
    if (keyiv_hmac_len == EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying hmac failed in getting the size for keyiv_hmac\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    memset_s(keyiv_hmac, MAX_KEYIV_HMAC_LENGTH, 0);
    memset_s(hmac, MAX_HMAC_LENGTH, 0);

    keyiv_hmac_len = BIO_read(keyiv_hmac_bio, keyiv_hmac, keyiv_hmac_len);
    if (keyiv_hmac_len <= 0) {
        BIO_printf(g_bio_err, "LibOVSA: Error verifying hmac failed in reading the keyiv_hmac\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (memcpy_s(hmac, MAX_HMAC_LENGTH,
                 keyiv_hmac + EVP_CIPHER_key_length(cipher) + EVP_CIPHER_iv_length(cipher),
                 hmac_key_len) != EOK) {
        BIO_printf(g_bio_err, "LibOVSA: Error verifying hmac failed in getting the hmac key\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

    pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, hmac, hmac_key_len);
    if (pkey == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying hmac failed in loading the hmac key into memory\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying hmac failed in creating the context for digest\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    sign = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
    if (sign != 1) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying hmac failed in setting up the signing context\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }

    ret = ovsa_get_string_length(in_buff, &buff_len);
    if ((ret < OVSA_OK) || (buff_len == EOK)) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error verifying hmac failed in getting the size of the input buffer\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    sign = EVP_DigestSignUpdate(ctx, in_buff, buff_len);
    if (sign != 1) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying hmac failed in hashing the data into context\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }

    out_bio = BIO_new(BIO_s_mem());
    if (out_bio == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error verifying hmac failed in getting new BIO for the output buffer\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    sigbio = out_bio;
    if (BIO_puts(sigbio, signature) <= 0) {
        BIO_printf(g_bio_err, "LibOVSA: Error verifying hmac failed in writing to signature BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying hmac failed in getting the b64 encode method\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    sigbio = BIO_push(b64, sigbio);
    siglen = strnlen_s(signature, MAX_MAC_SIZE);
    if (siglen == EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying hmac failed in getting the size for signature\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    sigbuff = (unsigned char*)ovsa_crypto_app_malloc(siglen, "signature buffer");
    if (sigbuff == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error verifying hmac failed in allocating memory for signature buffer\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    siglen = BIO_read(sigbio, sigbuff, siglen);
    if (siglen <= 0) {
        BIO_printf(g_bio_err, "LibOVSA: Error verifying hmac failed in reading to signature BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    memset_s(verify_buff, EVP_MAX_MD_SIZE, 0);
    hmaclen = sizeof(verify_buff);

    sign = EVP_DigestSignFinal(ctx, verify_buff, &hmaclen);
    if (sign != 1) {
        BIO_printf(g_bio_err, "LibOVSA: Error verifying hmac failed in signing the data\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }

    if ((siglen == hmaclen) && (CRYPTO_memcmp(sigbuff, verify_buff, hmaclen) == 0)) {
        BIO_printf(g_bio_err, "LibOVSA: HMAC Verified OK\n");
    } else {
        BIO_printf(g_bio_err, "LibOVSA: HMAC Verification Failure\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }

end:
    OPENSSL_cleanse(keyiv_hmac, MAX_KEYIV_HMAC_LENGTH);
    OPENSSL_cleanse(hmac, MAX_HMAC_LENGTH);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(b64);
    BIO_free(keyiv_hmac_b64);
    BIO_free_all(out_bio);
    BIO_free_all(keyiv_hmac_read_bio);
    ovsa_crypto_openssl_free((char**)&sigbuff);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_sign_json_blob(int asym_key_slot, const char* in_buff, size_t in_buff_len,
                                         char* out_buff) {
    ovsa_status_t ret = OVSA_OK;
    char sig_buff[MAX_SIGNATURE_SIZE];

    if ((asym_key_slot < MIN_KEY_SLOT) || (asym_key_slot >= MAX_KEY_SLOT) || (in_buff == NULL) ||
        (in_buff_len == 0) || (out_buff == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing the JSON blob failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    memset_s(sig_buff, MAX_SIGNATURE_SIZE, 0);

    ret = ovsa_crypto_sign_mem(asym_key_slot, in_buff, in_buff_len, sig_buff);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing the JSON blob failed in signing the memory buffer\n");
        goto end;
    }

    ret = ovsa_json_apend_signature(in_buff, sig_buff, out_buff);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing the JSON blob failed in appending the signature\n");
        goto end;
    }

end:
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_verify_json_blob(int asym_key_slot, const char* in_buff,
                                           size_t in_buff_len, char* out_buff) {
    ovsa_status_t ret = OVSA_OK;
    char sig_buff[MAX_SIGNATURE_SIZE];

    if ((asym_key_slot < MIN_KEY_SLOT) || (asym_key_slot >= MAX_KEY_SLOT) || (in_buff == NULL) ||
        (in_buff_len == 0) || (out_buff == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying the JSON blob failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    memset_s(sig_buff, MAX_SIGNATURE_SIZE, 0);

    ret = ovsa_json_extract_and_strip_signature(in_buff, sig_buff, out_buff);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying the JSON blob failed in stripping the signature\n");
        goto end;
    }

    ret = ovsa_crypto_verify_mem(asym_key_slot, out_buff, in_buff_len, sig_buff);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error verifying the JSON blob failed in verifying the memory buffer\n");
        goto end;
    }

end:
    if (ret < OVSA_OK) {
        out_buff = NULL;
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_hmac_json_blob(int keyiv_hmac_slot, const char* in_buff,
                                         size_t in_buff_len, char* out_buff) {
    ovsa_status_t ret = OVSA_OK;
    char hmac_buff[MAX_MAC_SIZE];

    if ((keyiv_hmac_slot < MIN_KEY_SLOT) || (keyiv_hmac_slot >= MAX_KEY_SLOT) ||
        (in_buff == NULL) || (in_buff_len == 0) || (out_buff == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error hmac JSON blob failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    memset_s(hmac_buff, MAX_MAC_SIZE, 0);

    ret = ovsa_crypto_compute_hmac(keyiv_hmac_slot, in_buff, in_buff_len, hmac_buff);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error hmac JSON blob failed in computing hmac the memory buffer\n");
        goto end;
    }

    ret = ovsa_json_apend_signature(in_buff, hmac_buff, out_buff);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err, "LibOVSA: Error hmac JSON blob failed in appending the signature\n");
        goto end;
    }

end:
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_verify_hmac_json_blob(int keyiv_hmac_slot, const char* in_buff,
                                                size_t in_buff_len, char* out_buff) {
    ovsa_status_t ret = OVSA_OK;
    char hmac_buff[MAX_MAC_SIZE];

    if ((keyiv_hmac_slot < MIN_KEY_SLOT) || (keyiv_hmac_slot >= MAX_KEY_SLOT) ||
        (in_buff == NULL) || (in_buff_len == 0) || (out_buff == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying the hmac JSON blob failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    memset_s(hmac_buff, MAX_MAC_SIZE, 0);

    ret = ovsa_json_extract_and_strip_signature(in_buff, hmac_buff, out_buff);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error verifying the hmac JSON blob failed in stripping the signature\n");
        goto end;
    }

    ret = ovsa_crypto_verify_hmac(keyiv_hmac_slot, out_buff, in_buff_len, hmac_buff);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying the hmac JSON blob failed in verifying the hmac for "
                   "the memory buffer\n");
        goto end;
    }

end:
    if (ret < OVSA_OK) {
        out_buff = NULL;
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_wrap_key(int asym_key_slot, int sym_key_slot, char** out_buff,
                                   size_t* out_buff_len, int* keyiv_hmac_slot) {
    ovsa_status_t ret   = OVSA_OK;
    size_t sym_key_len  = 0;
    int shared_key_slot = -1;

    if ((asym_key_slot < MIN_KEY_SLOT) || (asym_key_slot >= MAX_KEY_SLOT) ||
        (sym_key_slot < MIN_KEY_SLOT) || (sym_key_slot >= MAX_KEY_SLOT)) {
        BIO_printf(g_bio_err, "LibOVSA: Error wrapping the key failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    /* Compute shared key using ISV's primary private key and secondary public key */
    ret = ovsa_crypto_create_ecdh_key(asym_key_slot, asym_key_slot + 1, &shared_key_slot);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error wrapping the key failed in generating the shared key\n");
        return ret;
    }

    sym_key_len = strnlen_s(g_sym_key[sym_key_slot], MAX_EKEY_SIZE);
    if (sym_key_len == EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error wrapping the key failed in getting the size of symmetric key\n");
        return OVSA_CRYPTO_GENERIC_ERROR;
    }

    ret = ovsa_crypto_encrypt_mem(shared_key_slot, g_sym_key[sym_key_slot], sym_key_len, NULL,
                                  out_buff, out_buff_len, keyiv_hmac_slot);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error wrapping the key failed in encrypting the memory buffer\n");
        return ret;
    }

    /* Clear shared key from key slot */
    ovsa_crypto_clear_symmetric_key_slot(shared_key_slot);
    return ret;
}

ovsa_status_t ovsa_crypto_rewrap_key(int asym_key_slot, int peer_key_slot, const char* in_buff,
                                     size_t in_buff_len, char** out_buff, size_t* out_buff_len,
                                     int* keyiv_hmac_slot) {
    ovsa_status_t ret       = OVSA_OK;
    int shared_key_slot     = -1;
    int rewrapped_key_slot  = -1;
    char* decrypt_buff      = NULL;
    size_t decrypt_buff_len = 0;

    if ((asym_key_slot < MIN_KEY_SLOT) || (asym_key_slot >= MAX_KEY_SLOT) ||
        (peer_key_slot < MIN_KEY_SLOT) || (peer_key_slot >= MAX_KEY_SLOT) || (in_buff == NULL) ||
        (in_buff_len == 0)) {
        BIO_printf(g_bio_err, "LibOVSA: Error rewrapping the key failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    /* Compute shared key using ISV's secondary private key and primary public key */
    ret = ovsa_crypto_create_ecdh_key(asym_key_slot + 1, asym_key_slot, &shared_key_slot);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error rewrapping the key failed in generating the shared key\n");
        goto end;
    }

    ret = ovsa_crypto_decrypt_mem(shared_key_slot, in_buff, in_buff_len, &decrypt_buff,
                                  &decrypt_buff_len, keyiv_hmac_slot);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error rewrapping the key failed in decrypting the memory buffer\n");
        goto end;
    }

    /* Clear key/IV/HMAC from key slot */
    ovsa_crypto_clear_symmetric_key_slot(*keyiv_hmac_slot);
    /* Compute shared key using ISV's primary private key and customer public key */
    ret = ovsa_crypto_create_ecdh_key(asym_key_slot, peer_key_slot, &rewrapped_key_slot);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error rewrapping the key failed in generating the shared key\n");
        goto end;
    }

    ret = ovsa_crypto_encrypt_mem(rewrapped_key_slot, decrypt_buff, decrypt_buff_len, NULL,
                                  out_buff, out_buff_len, keyiv_hmac_slot);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error rewrapping the key failed in encrypting the memory buffer\n");
        goto end;
    }

end:
    /* Clear shared key from key slot */
    ovsa_crypto_clear_symmetric_key_slot(shared_key_slot);
    /* Clear rewrapped key from key slot */
    ovsa_crypto_clear_symmetric_key_slot(rewrapped_key_slot);
    ovsa_crypto_openssl_free(&decrypt_buff);
    return ret;
}

ovsa_status_t ovsa_crypto_unwrap_key(int asym_key_slot, int peer_key_slot, const char* in_buff,
                                     size_t in_buff_len, int* sym_key_slot, int* keyiv_hmac_slot) {
    ovsa_status_t ret   = OVSA_OK;
    int shared_key_slot = -1;
    char* unwrapped_key = NULL;
    size_t out_buff_len = 0;

    if ((asym_key_slot < MIN_KEY_SLOT) || (asym_key_slot >= MAX_KEY_SLOT) ||
        (peer_key_slot < MIN_KEY_SLOT) || (peer_key_slot >= MAX_KEY_SLOT) || (in_buff == NULL) ||
        (in_buff_len == 0)) {
        BIO_printf(g_bio_err, "LibOVSA: Error unwrapping the key failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    /* Compute shared key using customer's private key and ISV's public key */
    ret = ovsa_crypto_create_ecdh_key(asym_key_slot, peer_key_slot, &shared_key_slot);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error unwrapping the key failed in generating the shared key\n");
        return ret;
    }

    ret = ovsa_crypto_decrypt_mem(shared_key_slot, in_buff, in_buff_len, &unwrapped_key,
                                  &out_buff_len, keyiv_hmac_slot);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error unwrapping the key failed in decrypting the memory buffer\n");
        goto end;
    }

    ret = ovsa_crypto_add_symmetric_keystore_array(unwrapped_key, sym_key_slot);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error unwrapping the key failed in adding to symmetric keystore array\n");
        goto end;
    }

end:
    /* Clear shared key from key slot */
    ovsa_crypto_clear_symmetric_key_slot(shared_key_slot);
    ovsa_crypto_openssl_free(&unwrapped_key);
    return ret;
}
