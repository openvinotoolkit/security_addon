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

#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/certs.h"
#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "runtime.h"
#include "utils.h"

#ifndef DISABLE_RA_TLS
#include "ra_tls.h"
#endif

/* json.h to be included at end due to dependencies */
#include "json.h"

extern ovsa_status_t ovsa_start_model_loader(
    const int asym_key_slot, const int peer_slot, ovsa_customer_license_sig_t* customer_lic_sig,
    ovsa_controlled_access_model_sig_t* controlled_access_model_sig,
    ovsa_model_file_list_t* decrypted_files);

static mbedtls_ctr_drbg_context g_ctr_drbg;
static mbedtls_entropy_context g_entropy;
static mbedtls_ssl_config g_conf;
static mbedtls_net_context g_verifier_fd;
static mbedtls_ssl_context g_ssl;
#ifndef DISABLE_RA_TLS
static mbedtls_pk_context g_my_ratls_key;
static mbedtls_x509_crt g_my_ratls_cert;
#endif
static ovsa_status_t ovsa_license_service_close(void* ssl);
ovsa_status_t ovsa_license_service_write(void* ssl, const char* buf, size_t len);
static ovsa_status_t ovsa_license_service_read(void* ssl, uint8_t* buf, size_t len);
static ovsa_status_t ovsa_license_service_start(const char* in_servers,
                                                const char* in_ca_chain_path, void** out_ssl,
                                                ovsa_customer_license_sig_t customer_lic_sig);

static const char* g_cipher_suitename[CIPHER_SUITE_SIZE] = {
    "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"};
static int g_cipher_suite[CIPHER_SUITE_SIZE];
static mbedtls_ecp_group_id g_curve_list[CURVE_LIST_SIZE];

static ovsa_status_t ovsa_send_update_cust_lic_ACK(void** _ssl_session) {
    ovsa_status_t ret    = OVSA_OK;
    void* ssl_session    = NULL;
    char* json_buf       = NULL;
    char dummy_payload[] = "";
    char* json_payload   = NULL;
    size_t buf_len       = 0;
    size_t length        = 0;
    size_t payload_len   = 0;

    ssl_session = *_ssl_session;

    OVSA_DBG(DBG_I, "OVSA:Entering %s\n", __func__);

    /* create json message blob */
    ret = ovsa_json_create_message_blob(OVSA_SEND_UPDATE_CUST_LICENSE_ACK, dummy_payload, &json_buf,
                                        &length);
    if (ret < OVSA_OK) {
        OVSA_DBG(
            DBG_E,
            "OVSA: Error create update customer lickense ACK message failed with error code %d\n",
            ret);
        goto out;
    }
    /* Append payload length to json blob */
    payload_len = length + PAYLOAD_LENGTH + 1;
    ret         = ovsa_safe_malloc(sizeof(char) * payload_len, (char**)&json_payload);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error create json blob memory init failed\n");
        goto out;
    }
    ret = ovsa_append_json_payload_len_to_blob(json_buf, (char**)&json_payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error json blob creation failed with %d\n", ret);
        goto out;
    }
    ret = ovsa_get_string_length((char*)json_payload, &buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of json_payload string %d\n", ret);
        goto out;
    }
    /* Send UPDATE_CUST_LICENSE_ACK to Server */
    ret = ovsa_license_service_write(ssl_session, (char*)json_payload, buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error ovsa_license_service_write() returned %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA:Send UPDATE_CUST_LICENSE_ACK to server\n%s", json_payload);
out:
    ovsa_safe_free(&json_buf);
    ovsa_safe_free(&json_payload);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_validate_peer_cert_hash(ovsa_customer_license_sig_t customer_lic_sig,
                                                  char* peer_cert_hash) {
    ovsa_status_t ret           = OVSA_OK;
    char* cur_cert_hash         = NULL;
    char* fut_cert_hash         = NULL;
    int cur_cert_hash_indicator = -1;
    int fut_cert_hash_indicator = -1;
    OVSA_DBG(DBG_I, "OVSA:Entering %s\n", __func__);

    cur_cert_hash = customer_lic_sig.customer_lic.license_url_list->cur_cert_hash;
    fut_cert_hash = customer_lic_sig.customer_lic.license_url_list->fut_cert_hash;

    /*validate peer_cert_hash*/
    strcmp_s(peer_cert_hash, HASH_SIZE, cur_cert_hash, &cur_cert_hash_indicator);
    strcmp_s(peer_cert_hash, HASH_SIZE, fut_cert_hash, &fut_cert_hash_indicator);

    if ((cur_cert_hash_indicator == 0) || (fut_cert_hash_indicator == 0)) {
        OVSA_DBG(DBG_I, "\nOVSA: Peer certificate HASH verified OK.\n");
        goto out;
    } else {
        ret = OVSA_PEER_CERT_HASH_VALIDATION_FAILED;
        OVSA_DBG(DBG_E, "OVSA: Error Peer certificate HASH Validation failed %d\n", ret);
    }

out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}
ovsa_command_type_t ovsa_get_command_type(const char* command) {
    ovsa_command_type_t cmd = OVSA_INVALID_CMD;

    if (!strcmp(command, "OVSA_SEND_NONCE"))
        cmd = OVSA_SEND_NONCE;
#ifndef ENABLE_SGX_GRAMINE
    else if (!strcmp(command, "OVSA_SEND_HW_QUOTE"))
        cmd = OVSA_SEND_HW_QUOTE;
    else if (!strcmp(command, "OVSA_SEND_EK_AK_BIND"))
        cmd = OVSA_SEND_EK_AK_BIND;
    else if (!strcmp(command, "OVSA_SEND_QUOTE_NONCE"))
        cmd = OVSA_SEND_QUOTE_NONCE;
#endif
    else if (!strcmp(command, "OVSA_SEND_UPDATE_CUST_LICENSE"))
        cmd = OVSA_SEND_UPDATE_CUST_LICENSE;
    else if (!strcmp(command, "OVSA_SEND_LICENSE_CHECK_RESP"))
        cmd = OVSA_SEND_LICENSE_CHECK_RESP;
    else
        cmd = OVSA_INVALID_CMD;

    return cmd;
}

static void ovsa_mbedtls_debug_cb(void* ctx, int level, const char* file, int line,
                                  const char* str) {
    const char *p = NULL, *basename = NULL;
    (void)ctx;

    /* Extract basename from file */
    for (p = basename = file; *p != '\0'; p++) {
        if (*p == '/' || *p == '\\') {
            basename = p + 1;
        }
    }
    mbedtls_printf("%s:%04d: |%d| %s", basename, line, level, str);
}

ovsa_status_t ovsa_license_service_write(void* ssl, const char* buf, size_t len) {
    ovsa_status_t ret         = OVSA_OK;
    mbedtls_ssl_context* _ssl = (mbedtls_ssl_context*)ssl;

    if (_ssl == NULL || buf == NULL || len > INT_MAX) {
        OVSA_DBG(DBG_E, "OVSA: Error invalid Input parameter \n");
        ret = OVSA_INVALID_PARAMETER;
        return ret;
    }

    size_t written = 0;
    while (written < len) {
        ret = mbedtls_ssl_write(_ssl, (unsigned char*)buf + written, len - written);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (ret < OVSA_OK) {
            /* use well-known error code for a typical case when remote party closes connection */
            return ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ? -ECONNRESET : ret;
        }
        written += (size_t)ret;
    }
    assert(written == len);
    return (int)written;
}

static ovsa_status_t ovsa_license_service_read(void* ssl, uint8_t* buf, size_t len) {
    ovsa_status_t ret         = OVSA_OK;
    mbedtls_ssl_context* _ssl = (mbedtls_ssl_context*)ssl;

    if (_ssl == NULL || buf == NULL || len > INT_MAX) {
        OVSA_DBG(DBG_E, "OVSA: Error invalid Input parameter \n");
        ret = OVSA_INVALID_PARAMETER;
        return ret;
    }
    size_t read = 0;
    while (read < len) {
        ret = mbedtls_ssl_read(_ssl, buf + read, len - read);
        if (!ret) {
            OVSA_DBG(DBG_E, "OVSA: Error mbedtls_ssl_read failed with error code %d \n", ret);
            return -ECONNRESET;
        }
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (ret < OVSA_OK) {
            /* use well-known error code for a typical case when remote party closes connection */
            return ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ? -ECONNRESET : ret;
        }
        read += (size_t)ret;
    }

    assert(read == len);
    return (int)read;
}

static ovsa_status_t ovsa_license_service_close(void* ssl) {
    mbedtls_ssl_context* _ssl = (mbedtls_ssl_context*)ssl;
    ovsa_status_t ret         = OVSA_OK;
    if (!_ssl)
        return ret;

    ret = -1;
    while (ret < OVSA_OK) {
        ret = mbedtls_ssl_close_notify(_ssl);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (ret < OVSA_OK) {
            mbedtls_ssl_free(&g_ssl);
            mbedtls_ssl_config_free(&g_conf);
            /* use well-known error code for a typical case when remote party closes connection */
            return ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ? -ECONNRESET : ret;
        }
    }
    mbedtls_ssl_free(&g_ssl);
    mbedtls_ssl_config_free(&g_conf);
    return ret;
}

static ovsa_status_t ovsa_license_service_start(const char* in_servers,
                                                const char* in_ca_chain_path, void** out_ssl,
                                                ovsa_customer_license_sig_t customer_lic_sig) {
    ovsa_status_t ret    = OVSA_OK;
    char* servers        = NULL;
    char* connected_addr = NULL;
    char* connected_port = NULL;
    char* issuer_dup     = NULL;
    char peer_cert_hash[HASH_SIZE];
    mbedtls_x509_crt* g_server_cert = NULL;
    BIO* issuer_cert_bio            = NULL;
    BIO* issuer_cert_mem            = NULL;
    BUF_MEM* issuer_cert_ptr        = NULL;
    X509* d2i_xcert                 = NULL;
    int peer_cert_slot              = -1;
    int index                       = 0;

    OVSA_DBG(DBG_I, "OVSA:Entering %s\n", __func__);

    mbedtls_ctr_drbg_init(&g_ctr_drbg);
    mbedtls_entropy_init(&g_entropy);
#ifndef DISABLE_RA_TLS

    mbedtls_pk_init(&g_my_ratls_key);
    mbedtls_x509_crt_init(&g_my_ratls_cert);
#endif
    mbedtls_net_init(&g_verifier_fd);
    mbedtls_ssl_config_init(&g_conf);
    mbedtls_ssl_init(&g_ssl);

    if (out_ssl == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error invalid input to start license service\n");
        ret = OVSA_INVALID_PARAMETER;
        goto out;
    }

    OVSA_DBG(DBG_D, "OVSA:calling mbedtls_ctr_drbg_seed\n");
    const char pers[] = "ovsa-license-check";
    ret = mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func, &g_entropy, (const uint8_t*)pers,
                                sizeof(pers));
    if (ret < 0) {
        OVSA_DBG(DBG_E, "OVSA: Error mbedtls_ctr_drbg_seed failed with error code %d \n", ret);
        goto out;
    }

    servers = strdup(in_servers);
    if (!servers) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto out;
    }

    OVSA_DBG(DBG_D, "OVSA:Getting address, port\n");
    char* saveptr1 = NULL;
    char* saveptr2 = NULL;
    char* str1     = NULL;
    for (str1 = servers; /* no condition */; str1 = NULL) {
        ret         = -ECONNREFUSED;
        char* token = strtok_r(str1, ",; ", &saveptr1);
        if (!token)
            break;

        connected_addr = strtok_r(token, ":", &saveptr2);
        if (!connected_addr)
            continue;

        connected_port = strtok_r(NULL, ":", &saveptr2);
        if (!connected_port)
            continue;

        OVSA_DBG(DBG_D, "OVSA:calling mbedtls_net_connect\n");
        ret = mbedtls_net_connect(&g_verifier_fd, connected_addr, connected_port,
                                  MBEDTLS_NET_PROTO_TCP);
        if (!ret)
            break;
    }

    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error mbedtls_net_connect returned error with code %d\n", ret);
        goto out;
    }

    OVSA_DBG(DBG_D, "OVSA:calling mbedtls_ssl_config_defaults\n");
    ret = mbedtls_ssl_config_defaults(&g_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error mbedtls_ssl_config_defaults returned error with code %d\n",
                 ret);
        goto out;
    }

    /* Add supported Cipher Suites */
    memset_s(g_cipher_suite, CIPHER_SUITE_SIZE, 0);
    memset_s(g_curve_list, CURVE_LIST_SIZE, 0);

    for (index = 0; index < CIPHER_SUITE_SIZE; index++) {
        g_cipher_suite[index] = mbedtls_ssl_get_ciphersuite_id(g_cipher_suitename[index]);
    }

    g_curve_list[0] = MBEDTLS_ECP_DP_SECP521R1;
    g_curve_list[1] = MBEDTLS_ECP_DP_NONE;

    mbedtls_ssl_conf_curves(&g_conf, g_curve_list);
    mbedtls_ssl_conf_ciphersuites(&g_conf, g_cipher_suite);
    /* setting the peer certificate verification as optional since the peer certificate
     * will be verified using OVSA library api which does the OCSP check as well. */
    mbedtls_ssl_conf_authmode(&g_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_rng(&g_conf, mbedtls_ctr_drbg_random, &g_ctr_drbg);
#ifndef DISABLE_RA_TLS
    OVSA_DBG(DBG_D, "OVSA:calling ratls_create_key_and_crt\n");
    ret = ra_tls_create_key_and_crt(&g_my_ratls_key, &g_my_ratls_cert);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:ratls_create_key_and_crt failed with error code %d \n", ret);
        goto out;
    }
    ret = mbedtls_ssl_conf_own_cert(&g_conf, &g_my_ratls_cert, &g_my_ratls_key);
    if (ret < OVSA_OK) {
        goto out;
    }
#endif
    /* mbedtls debug */
    mbedtls_ssl_conf_dbg(&g_conf, ovsa_mbedtls_debug_cb, NULL);
    mbedtls_debug_set_threshold(MBEDTLS_DEBUG_LEVEL);

    ret = mbedtls_ssl_setup(&g_ssl, &g_conf);
    if (ret < OVSA_OK) {
        goto out;
    }

    ret = mbedtls_ssl_set_hostname(&g_ssl, connected_addr);
    if (ret < OVSA_OK) {
        goto out;
    }

    OVSA_DBG(DBG_D, "OVSA:calling mbedtls_ssl_set_bio\n");
    mbedtls_ssl_conf_read_timeout(&g_conf, READ_TIMEOUT_MS);
    mbedtls_ssl_set_bio(&g_ssl, &g_verifier_fd, mbedtls_net_send, mbedtls_net_recv,
                        mbedtls_net_recv_timeout);

    ret = -1;
    while (ret < OVSA_OK) {
        ret = mbedtls_ssl_handshake(&g_ssl);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error mbedtls_ssl_handshake failed with error %d\n", ret);
            goto out;
        }
    }

    /* Extract the peer certificate from ssl context and perform the certificate validation */
    g_server_cert = (mbedtls_x509_crt*)mbedtls_ssl_get_peer_cert(&g_ssl);
    if (g_server_cert == NULL) {
        ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        OVSA_DBG(DBG_E, "OVSA: Error mbedtls_ssl_get_peer_cert failed with error %d\n", ret);
        goto out;
    }

    issuer_cert_mem = BIO_new_mem_buf(g_server_cert->raw.p, g_server_cert->raw.len);
    if (issuer_cert_mem == NULL) {
        ret = OVSA_CRYPTO_BIO_ERROR;
        OVSA_DBG(DBG_E, "OVSA: Error BIO_new_mem_buf failed with error %d\n", ret);
        goto out;
    }

    /* Convert the issuer certificate from DER to PEM */
    d2i_xcert = d2i_X509_bio(issuer_cert_mem, NULL);
    if (d2i_xcert == NULL) {
        ret = OVSA_CRYPTO_BIO_ERROR;
        OVSA_DBG(DBG_E, "OVSA: Error d2i_X509_bio failed with error %d\n", ret);
        goto out;
    }

    issuer_cert_bio = BIO_new(BIO_s_mem());
    if (issuer_cert_bio == NULL) {
        ret = OVSA_CRYPTO_BIO_ERROR;
        OVSA_DBG(DBG_E, "OVSA: Error BIO_new failed with error %d\n", ret);
        goto out;
    }

    if (!PEM_write_bio_X509(issuer_cert_bio, d2i_xcert)) {
        ret = OVSA_CRYPTO_PEM_ENCODE_ERROR;
        OVSA_DBG(DBG_E, "OVSA: Error PEM_write_bio_X509 failed with error %d\n", ret);
        goto out;
    }

    BIO_get_mem_ptr(issuer_cert_bio, &issuer_cert_ptr);
    if (issuer_cert_ptr == NULL) {
        ret = OVSA_CRYPTO_BIO_ERROR;
        OVSA_DBG(DBG_E, "OVSA: Error BIO_get_mem_ptr failed with error %d\n", ret);
        goto out;
    }

    ret = ovsa_safe_malloc(issuer_cert_ptr->length + NULL_TERMINATOR, &issuer_dup);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error issuer cert memory failed with code %d\n", ret);
        goto out;
    }

    /* Copy the issuer certificate to local buffer */
    if (memcpy_s(issuer_dup, issuer_cert_ptr->length, issuer_cert_ptr->data,
                 issuer_cert_ptr->length) != EOK) {
        ret = OVSA_MEMIO_ERROR;
        OVSA_DBG(DBG_E, "OVSA: Error getting the issuer cert failed with error %d\n", ret);
        goto out;
    }
    /*compute hash of peer certificate*/
    memset_s(peer_cert_hash, HASH_SIZE, 0);
    ret = ovsa_crypto_compute_hash(issuer_dup, HASH_ALG_SHA384, (unsigned char*)peer_cert_hash,
                                   true /* FORMAT_BASE64 */);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error certificate HASH generation failed with code %d\n", ret);
        goto out;
    }
    /* Validate peer certificate hash */
    ret = ovsa_validate_peer_cert_hash(customer_lic_sig, peer_cert_hash);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error validate peer certificate hash failed with code %d\n", ret);
        goto out;
    }
    /* Verify the peer certificate */
    ret = ovsa_crypto_extract_pubkey_verify_cert(
        /* PEER CERT */ true, issuer_dup, /* lifetime_validity_check */ true, &peer_cert_slot);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error verifying server certificate failed with code %d\n", ret);
        goto out;
    }
    *out_ssl = &g_ssl;

out:
    mbedtls_x509_crt_free(g_server_cert);
    BIO_free_all(issuer_cert_bio);
    BIO_free_all(issuer_cert_mem);
    X509_free(d2i_xcert);
    ovsa_safe_free(&issuer_dup);
    /* clear peer keys from the key slots */
    if (peer_cert_slot != -1) {
        ovsa_crypto_clear_asymmetric_key_slot(peer_cert_slot);
    }
    ovsa_safe_free(&servers);
    OVSA_DBG(DBG_I, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_validate_controlled_access_model(
    const int peer_keyslot, const char* controlled_access_model,
    ovsa_controlled_access_model_sig_t* controlled_access_model_sig) {
    ovsa_status_t ret                     = OVSA_OK;
    size_t control_access_model_file_size = 0;
    char* control_access_model_sig_buf    = NULL;
    char* control_access_model_buf        = NULL;
    char* peer_certificate                = NULL;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    if (controlled_access_model != NULL) {
        /* Load controlled access model Artifact */
        FILE* fcontrol_access_model = fopen(controlled_access_model, "r");
        if (fcontrol_access_model == NULL) {
            ret = OVSA_FILEOPEN_FAIL;
            OVSA_DBG(DBG_E,
                     "OVSA: Error opening controlled access model file failed with code %d\n", ret);
            goto out;
        }
        control_access_model_file_size = ovsa_crypto_get_file_size(fcontrol_access_model);
        ret = ovsa_safe_malloc(control_access_model_file_size * sizeof(char),
                               &control_access_model_sig_buf);
        if (ret < OVSA_OK) {
            ret = OVSA_MEMORY_ALLOC_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Error init memory failed with code %d\n", ret);
            fclose(fcontrol_access_model);
            goto out;
        }
        if (!fread(control_access_model_sig_buf, 1, control_access_model_file_size,
                   fcontrol_access_model)) {
            ret = OVSA_FILEIO_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Error read controlled access model file failed with code %d\n",
                     ret);
            fclose(fcontrol_access_model);
            goto out;
        }
        control_access_model_sig_buf[control_access_model_file_size - 1] = '\0';
        fclose(fcontrol_access_model);
        /* Extract controlled access model json blob */
        ret = ovsa_json_extract_controlled_access_model(control_access_model_sig_buf,
                                                        controlled_access_model_sig);
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E,
                     "OVSA: Error extract_controlled_access_model_json_blob failed with code %d\n",
                     ret);
            goto out;
        }
        peer_certificate = controlled_access_model_sig->controlled_access_model.isv_certificate;
        /* Verify controlled access model json_blob */
        ret = ovsa_safe_malloc(control_access_model_file_size * sizeof(char),
                               &control_access_model_buf);
        if (ret < OVSA_OK) {
            ret = OVSA_MEMORY_ALLOC_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Error init memory failed with code %d\n", ret);
            goto out;
        }
        OVSA_DBG(DBG_I, "OVSA: Verify controlled access model signature\n");
        ret =
            ovsa_crypto_verify_json_blob(peer_keyslot, control_access_model_sig_buf,
                                         control_access_model_file_size, control_access_model_buf);
        if (ret != OVSA_OK || control_access_model_buf == NULL) {
            OVSA_DBG(DBG_E,
                     "OVSA: Error verify controlled access model json blob failed with code  %d\n",
                     ret);
        }
    } else {
        OVSA_DBG(DBG_E, "OVSA: Error invalid controlled access model artifact \n");
        ret = OVSA_INVALID_PARAMETER;
    }
out:
    ovsa_safe_free(&control_access_model_sig_buf);
    ovsa_safe_free(&control_access_model_buf);
    ovsa_safe_free(&peer_certificate);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_validate_customer_license(const char* customer_license, const int asym_keyslot,
                                             ovsa_customer_license_sig_t* customer_lic_sig) {
    ovsa_status_t ret         = OVSA_OK;
    size_t cust_lic_file_size = 0;
    size_t peer_certlen       = 0;
    int peer_keyslot          = -1;
    int shared_key_slot       = -1;
    int keyiv_hmac_slot       = -1;
    char* cust_lic_sig_buf    = NULL;
    char* cust_lic_buf        = NULL;
    char* peer_cert           = NULL;
    char* encryption_key      = NULL;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    if (customer_license != NULL) {
        /* Load customer license Artifact */
        FILE* fcust_lic = fopen(customer_license, "r");
        if (fcust_lic == NULL) {
            ret = OVSA_FILEOPEN_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Error opening customer license file failed with code %d\n", ret);
            goto out;
        }
        cust_lic_file_size = ovsa_crypto_get_file_size(fcust_lic);
        ret                = ovsa_safe_malloc(cust_lic_file_size * sizeof(char), &cust_lic_sig_buf);
        if (ret < OVSA_OK) {
            ret = OVSA_MEMORY_ALLOC_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Error init memory failed with code %d\n", ret);
            fclose(fcust_lic);
            goto out;
        }
        if (!fread(cust_lic_sig_buf, 1, cust_lic_file_size, fcust_lic)) {
            ret = OVSA_FILEIO_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Error read customer license file failed with code %d\n", ret);
            fclose(fcust_lic);
            goto out;
        }
        cust_lic_sig_buf[cust_lic_file_size - 1] = '\0';
        fclose(fcust_lic);
        /* Extract customer licensce json blob */
        ret = ovsa_json_extract_customer_license(cust_lic_sig_buf, customer_lic_sig);
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error extract customer license json blob failed with code %d\n",
                     ret);
            goto out;
        }
        peer_cert = customer_lic_sig->customer_lic.isv_certificate;

        OVSA_DBG(DBG_I, "OVSA: Verify PEER certificate\n");
        /* Verifying customer license ISV Certificate */
        ret = ovsa_get_string_length(peer_cert, &peer_certlen);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error could not get length of peer certificate %d\n", ret);
            goto out;
        }
        if ((!peer_certlen) || (peer_certlen > MAX_CERT_SIZE)) {
            OVSA_DBG(DBG_E, "OVSA: Error peer certificate length is invalid \n");
            ret = OVSA_INVALID_PARAMETER;
            goto out;
        }
        ret = ovsa_crypto_extract_pubkey_verify_cert(
            /* PEER CERT */ true, peer_cert, /* lifetime_validity_check */ true, &peer_keyslot);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error get keyslot failed with code %d\n", ret);
            goto out;
        }
        /* Verify customer license json_blob */
        ret = ovsa_safe_malloc(cust_lic_file_size * sizeof(char), &cust_lic_buf);
        if (ret < OVSA_OK) {
            ret = OVSA_MEMORY_ALLOC_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Error init memory failed with code %d\n", ret);
            goto out;
        }
        OVSA_DBG(DBG_I, "OVSA: Verify customer license signature\n");
        /* Extract encryption_key from customer license */
        ret =
            ovsa_json_extract_element(cust_lic_sig_buf, "encryption_key", (void**)&encryption_key);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error extract json element failed with error code %d\n", ret);
            goto out;
        }

        /* Compute shared key using customer private key and ISV public key */
        ret = ovsa_crypto_create_ecdh_key(asym_keyslot, peer_keyslot, &shared_key_slot);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error generating shared key failed with error code %d\n", ret);
            goto out;
        }

        /* Extract salt from encryption_key and derive key/IV/HMAC for customer license */
        ret = ovsa_crypto_derive_keyiv_hmac(shared_key_slot, encryption_key,
                                            strnlen_s(encryption_key, MAX_EKEY_SIZE),
                                            &keyiv_hmac_slot);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error deriving key/IV/HAMC failed with error code %d\n", ret);
            goto out;
        }

        /* Verifies the HMAC for customer license */
        ret = ovsa_crypto_verify_hmac_json_blob(keyiv_hmac_slot, cust_lic_sig_buf,
                                                cust_lic_file_size, cust_lic_buf);
        if (ret != OVSA_OK || cust_lic_buf == NULL) {
            OVSA_DBG(DBG_E, "OVSA: Error verify customer license json blob failed with code %d\n",
                     ret);
            goto out;
        }
        ret = peer_keyslot;
    } else {
        OVSA_DBG(DBG_E, "OVSA: Error invalid customer license artifact \n");
        ret = OVSA_INVALID_PARAMETER;
    }

out:
    /* clear key/IV/HMAC from the key slot */
    ovsa_crypto_clear_symmetric_key_slot(keyiv_hmac_slot);
    /* clear shared key from the key slot */
    ovsa_crypto_clear_symmetric_key_slot(shared_key_slot);
    ovsa_safe_free(&encryption_key);
    ovsa_safe_free(&cust_lic_sig_buf);
    ovsa_safe_free(&customer_lic_sig->customer_lic.isv_certificate);
    peer_cert = NULL;
    ovsa_safe_free_url_list(&customer_lic_sig->customer_lic.license_url_list);
    ovsa_safe_free_tcb_list(&customer_lic_sig->customer_lic.tcb_signatures);
    ovsa_safe_free(&cust_lic_buf);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_do_update_cust_license(char* update_cust_lic_buf,
                                                 const char* cust_lic_file_path,
                                                 void** _ssl_session) {
    ovsa_status_t ret             = OVSA_OK;
    void* ssl_session             = NULL;
    char* update_cust_lic_payload = NULL;
    size_t buf_len                = 0;
    ssl_session                   = *_ssl_session;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    ret = ovsa_json_extract_element((char*)update_cust_lic_buf, "payload",
                                    (void*)&update_cust_lic_payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error read updated customer license payload from json failed %d\n",
                 ret);
        goto out;
    }
    /* Update customer license file */
    FILE* fcust_lic = fopen(cust_lic_file_path, "w");
    if (fcust_lic == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error opening customer license file failed with code %d\n", ret);
        goto out;
    }
    ret = ovsa_get_string_length((char*)update_cust_lic_payload, &buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of update_cust_lic_payload string %d\n",
                 ret);
        fclose(fcust_lic);
        goto out;
    }
    if (!fwrite(update_cust_lic_payload, buf_len, 1, fcust_lic)) {
        ret = OVSA_FILEIO_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error write customer license file failed with code %d\n", ret);
        fclose(fcust_lic);
        goto out;
    }
    fclose(fcust_lic);
    /* Send update cust_lic_ACK to Server */
    ret = ovsa_send_update_cust_lic_ACK(&ssl_session);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error send_update_cust_lic_ACK failed with %d\n", ret);
        goto out;
    }
out:
    ovsa_safe_free(&update_cust_lic_payload);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_do_get_license_check(const int asym_keyslot,
                                               char* cust_lic_check_status_buf) {
    ovsa_status_t ret       = OVSA_OK;
    char* lic_check_payload = NULL;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    ret = ovsa_json_extract_element((char*)cust_lic_check_status_buf, "payload",
                                    (void*)&lic_check_payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error read license check status payload from json failed %d\n", ret);
        goto out;
    }

    if (!(strcmp(lic_check_payload, "PASS"))) {
        OVSA_DBG(DBG_I, "OVSA:Received license check result from Server: '%s'\n",
                 lic_check_payload);
    } else {
        ret = OVSA_LICENSE_CHECK_FAIL;
        OVSA_DBG(DBG_I, "OVSA: %s\n", lic_check_payload);
        OVSA_DBG(DBG_E, "OVSA: Error model loader License check failed with code %d \n", ret);
    }
out:
    ovsa_safe_free(&lic_check_payload);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_socket_read(const int sockfd, char* buf, const size_t len) {
    ovsa_status_t ret = OVSA_OK;
    size_t read_bytes = 0;

    if (sockfd == 0 || len == 0) {
        OVSA_DBG(DBG_E, "OVSA: Error %s failed with invalid parameter, sockfd = %d\n", __func__,
                 sockfd);
        ret = OVSA_INVALID_PARAMETER;
        return ret;
    }
    int readdata = 0;

    while (readdata < len) {
        read_bytes = recv(sockfd, buf + readdata, len - readdata, 0);
        if (read_bytes == 0) {
            OVSA_DBG(DBG_I, "Socket connection is closed by remote...\n");
            ret = OVSA_SOCKET_CONN_CLOSED;
            goto out;
        } else if (read_bytes < 0) {
            OVSA_DBG(DBG_E, "OVSA: Error read failure over socket with error %s, errno %d\n",
                     strerror(errno), errno);
            ret = OVSA_SOCKET_READ_FAIL;
            goto out;
        }
        readdata += read_bytes;
        OVSA_DBG(DBG_D, "%s readdata %d, len to read %d, read_bytes value %d\n", __func__, readdata,
                 (int)len, (int)read_bytes);
    }
out:
    return ret;
}

ovsa_status_t ovsa_socket_write(const int sockfd, const char* buf, const size_t len) {
    ovsa_status_t ret    = OVSA_OK;
    size_t written_bytes = 0;

    if (sockfd == 0 || len == 0) {
        OVSA_DBG(DBG_E, "OVSA: Error %s failed with invalid parameter, sockfd = %d\n", __func__,
                 sockfd);
        ret = OVSA_INVALID_PARAMETER;
        return ret;
    }
    int written = 0;

    while (written < len) {
        written_bytes = send(sockfd, buf + written, len - written, 0);
        if (written_bytes == 0) {
            OVSA_DBG(DBG_I, "Socket connection is closed by remote...\n");
            ret = OVSA_SOCKET_CONN_CLOSED;
            goto out;
        } else if (written_bytes < 0) {
            OVSA_DBG(DBG_E, "OVSA: Error write failure over socket with error %s, errno %d\n",
                     strerror(errno), errno);
            ret = OVSA_SOCKET_WRITE_FAIL;
            goto out;
        }
        written += written_bytes;
        OVSA_DBG(DBG_D, "%s written %d, len to write %d, written_bytes value %d\n", __func__,
                 written, (int)len, (int)written_bytes);
    }
out:
    return ret;
}

static ovsa_status_t ovsa_do_sign_send_nounce(const int asym_keyslot, char* nonce_buf,
                                              char* cust_lic_sig_buf, void** _ssl_session) {
    ovsa_status_t ret = OVSA_OK;
    void* ssl_session = NULL;
    char nonce_signed[MAX_SIGNATURE_SIZE];
    size_t length               = 0;
    char* nonce_signbuf_str     = NULL;
    size_t sign_payload_len     = 0;
    unsigned char* json_payload = NULL;
    char* payload               = NULL;
    char* cust_lic_msg_blob_buf = NULL;
    char* cust_lic_json_payload = NULL;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    ssl_session = *_ssl_session;
    memset_s(nonce_signed, sizeof(nonce_signed), 0);

    /* Read payload from json file */
    ret = ovsa_json_extract_element((char*)nonce_buf, "payload", (void*)&payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error read payload from json failed %d\n", ret);
        goto out;
    }
    /* sign nonce */
    size_t buf_len = 0;
    ret            = ovsa_get_string_length((char*)nonce_buf, &buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of nonce_buf string %d\n", ret);
        goto out;
    }
    ret = ovsa_crypto_sign_mem(asym_keyslot, (char*)payload, buf_len, nonce_signed);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error nonce Signing failed with code %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA:Send signed nonce to server\n");

    /* create signed nonce json message blob */
    ret = ovsa_json_create_message_blob(OVSA_SEND_SIGN_NONCE, nonce_signed, &nonce_signbuf_str,
                                        &length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error create nonce_message failed with error code %d\n", ret);
        goto out;
    }
    /* Append payload length to json blob */
    sign_payload_len = length + PAYLOAD_LENGTH + 1;
    ret              = ovsa_safe_malloc(sizeof(char) * sign_payload_len, (char**)&json_payload);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error create json blob memory init failed\n");
        goto out;
    }
    ret = ovsa_append_json_payload_len_to_blob(nonce_signbuf_str, (char**)&json_payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error json blob creation failed with %d\n", ret);
        goto out;
    }
    ret = ovsa_get_string_length((char*)json_payload, &buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of json_payload string %d\n", ret);
        goto out;
    }
    /* Send signed nonce to Server */
    OVSA_DBG(DBG_I, "OVSA:Send signed nonce to server\n%s\n", json_payload);
    ret = ovsa_license_service_write(ssl_session, (char*)json_payload, buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error ovsa_license_service_write() returned %d\n", ret);
        goto out;
    }
    length                      = 0;
    buf_len                     = 0;
    size_t cust_lic_payload_len = 0;
    /* create customer license json message blob */
    ret = ovsa_json_create_message_blob(OVSA_SEND_CUST_LICENSE, cust_lic_sig_buf,
                                        &cust_lic_msg_blob_buf, &length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error create OVSA_SEND_CUST_LICENSE failed with error code %d\n",
                 ret);
        goto out;
    }
    cust_lic_payload_len = length + PAYLOAD_LENGTH + 1;
    ret = ovsa_safe_malloc(sizeof(char) * cust_lic_payload_len, (char**)&cust_lic_json_payload);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error create json blob memory init failed\n");
        goto out;
    }
    ret = ovsa_append_json_payload_len_to_blob(cust_lic_msg_blob_buf, &cust_lic_json_payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E,
                 "OVSA: Error customer license append payload json blob creation failed with %d\n",
                 ret);
        goto out;
    }
    /* Send customer license to Server */
    ret = ovsa_get_string_length((char*)cust_lic_json_payload, &buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error could not get length of cust_lic_json_payload string %d\n",
                 ret);
        goto out;
    }
    ret = ovsa_license_service_write(ssl_session, (char*)cust_lic_json_payload, buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error ovsa_license_service_write() returned %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA:Send OVSA_SEND_CUST_LICENSE to server\n%s", cust_lic_json_payload);

out:
    ovsa_safe_free(&nonce_signbuf_str);
    ovsa_safe_free(&payload);
    ovsa_safe_free((char**)&json_payload);
    ovsa_safe_free(&cust_lic_msg_blob_buf);

    ovsa_safe_free((char**)&cust_lic_json_payload);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_perform_tls_license_check(const int asym_keyslot, const char* customer_license,
                                             bool* status) {
    ovsa_status_t ret = OVSA_OK;
    void* ssl_session = NULL;
    unsigned char payload_len_str[PAYLOAD_LENGTH + 1];
    size_t payload_size         = 0;
    unsigned char* read_buf     = NULL;
    unsigned char* command      = NULL;
    bool license_check_complete = false;
    ovsa_command_type_t cmd     = OVSA_INVALID_CMD;
    char* cust_lic_sig_buf      = NULL;
    size_t cust_lic_file_size   = 0;
    ovsa_customer_license_sig_t customer_lic_sig;
    /* Set all pointers to NULL for KW fix */
    customer_lic_sig.customer_lic.isv_certificate  = NULL;
    customer_lic_sig.customer_lic.tcb_signatures   = NULL;
    customer_lic_sig.customer_lic.license_url_list = NULL;
    ovsa_license_serv_url_list_t* license_url_list = NULL;
    char license_serv_url[MAX_URL_SIZE + 1];
    bool connected_to_license_server = false;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    /* Input Parameter Validation check */
    if ((asym_keyslot >= MIN_KEY_SLOT) && (customer_license != NULL)) {
        memset_s(license_serv_url, sizeof(license_serv_url), 0);
        memset_s(payload_len_str, sizeof(payload_len_str), 0);

        /* Load customer license file */
        FILE* fcust_lic = fopen(customer_license, "r");
        if (fcust_lic == NULL) {
            ret = OVSA_FILEOPEN_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Error opening customer license file failed with code %d\n", ret);
            goto out;
        }
        cust_lic_file_size = ovsa_crypto_get_file_size(fcust_lic);
        ret                = ovsa_safe_malloc(cust_lic_file_size * sizeof(char), &cust_lic_sig_buf);
        if (ret < OVSA_OK) {
            ret = OVSA_MEMORY_ALLOC_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Error init memory failed with code %d\n", ret);
            fclose(fcust_lic);
            goto out;
        }
        if (!fread(cust_lic_sig_buf, 1, cust_lic_file_size, fcust_lic)) {
            ret = OVSA_FILEIO_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Error read customer license file failed with code %d\n", ret);
            fclose(fcust_lic);
            goto out;
        }
        fclose(fcust_lic);
        /*
         * Stage #1: Perform Platform Validation
         * Platform Validation using TLS library
         */
        OVSA_DBG(DBG_I, "OVSA: Perform Platform Validation using TLS \n");
        /* Extract customer license json blob */
        memset_s(&customer_lic_sig, sizeof(ovsa_customer_license_sig_t), 0);
        ret = ovsa_json_extract_customer_license(cust_lic_sig_buf, &customer_lic_sig);
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error extract customer license json blob failed with code %d\n",
                     ret);
            goto out;
        }
        /* Extract license server URL from customer license */
        license_url_list = customer_lic_sig.customer_lic.license_url_list;

        /* Connect to license server url */
        OVSA_DBG(DBG_I, "OVSA:Attempting to connect license server url ........\n\n");
        if (license_url_list == NULL) {
            OVSA_DBG(DBG_E, "OVSA: Error license_url_list empty \n");
            goto out;
        } else {
            int url_count = 0;
            while (license_url_list != NULL) {
                int len = strnlen_s(license_url_list->license_serv_url, MAX_URL_SIZE);
                if (len <= MAX_URL_SIZE) {
                    memcpy_s(license_serv_url, MAX_URL_SIZE, license_url_list->license_serv_url,
                             len);
                    license_serv_url[len] = '\0';
                    OVSA_DBG(DBG_I, "OVSA:License_serv_url_%d: '%s' %s\n", url_count++,
                             license_serv_url, license_url_list->license_serv_url);
                    ret = ovsa_license_service_start(license_serv_url, NULL, &ssl_session,
                                                     customer_lic_sig);
                    if (ret < OVSA_OK) {
                        OVSA_DBG(
                            DBG_E,
                            "OVSA: Error ovsa_license_service_start() failed to connect to license "
                            "server "
                            "'%s'\n\n",
                            license_serv_url);
                    } else {
                        OVSA_DBG(DBG_I,
                                 "OVSA:ovsa_license_service_start() connected to license server "
                                 "'%s' \n\n",
                                 license_serv_url);
                        connected_to_license_server = true;
                        break;
                    }
                } else {
                    OVSA_DBG(
                        DBG_E,
                        "OVSA: Error incorrect length of URL failed to connect to license server "
                        "'%s'\n\n",
                        license_serv_url);
                }
                license_url_list = license_url_list->next;
            }
        }

        OVSA_DBG(DBG_I, "OVSA:Connect to license server url status %s\n\n",
                 connected_to_license_server ? "true" : "false");
        if (!(connected_to_license_server == true)) {
            OVSA_DBG(DBG_E, "OVSA: Error connect to license server url failed with %d\n", ret);
            ret = OVSA_LICENSE_SERVER_CONNECT_FAIL;
            goto out;
        }
        OVSA_DBG(DBG_I, "OVSA: Platform Validation completed successfully\n");

        do {
            /*
             * Stage #2: Customer License Check Sequence
             * Sign the received Nonce and send back
             */

            /* Read payload length from server */
            memset_s(payload_len_str, sizeof(payload_len_str), 0);
            ret = ovsa_license_service_read(ssl_session, payload_len_str, PAYLOAD_LENGTH);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "OVSA: Error read payload length from server failed with code %d\n",
                         ret);
                goto out;
            }

            payload_size = atoi((char*)payload_len_str);
            if (payload_size < 0 || payload_size > SIZE_MAX) {
                ret = OVSA_MEMORY_ALLOC_FAIL;
                OVSA_DBG(DBG_E, "OVSA: Error read payload length from server is wrong\n");
                goto out;
            }

            /* Read payload from server */
            ret = ovsa_safe_malloc(sizeof(char) * payload_size + 1, (char**)&read_buf);
            if (ret < OVSA_OK) {
                ret = OVSA_MEMORY_ALLOC_FAIL;
                OVSA_DBG(DBG_E, "OVSA: Error memory allocation of read buf failed with code %d\n",
                         ret);
                goto out;
            }

            ret = ovsa_license_service_read(ssl_session, read_buf, payload_size);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "OVSA: Error read payload from server failed with code %d\n", ret);
                goto out;
            }
            OVSA_DBG(DBG_I, "OVSA: Received payload from server \n'%s'\n", read_buf);

            /* Read command from Payload */
            ret = ovsa_json_extract_element((char*)read_buf, "command", (void*)&command);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "OVSA: Error read command from json failed %d\n", ret);
                goto out;
            }
            cmd = ovsa_get_command_type((char*)command);

            switch (cmd) {
                case OVSA_SEND_NONCE:
                    ret = ovsa_do_sign_send_nounce(asym_keyslot + 1, (char*)read_buf,
                                                   cust_lic_sig_buf, &ssl_session);
                    if (ret < OVSA_OK) {
                        OVSA_DBG(DBG_E, "OVSA: Error read nonce from server failed with code %d\n",
                                 ret);
                        goto out;
                    }
                    break;
#ifndef ENABLE_SGX_GRAMINE
                case OVSA_SEND_EK_AK_BIND:
                    ret = ovsa_send_EK_AK_bind_info(asym_keyslot, &ssl_session);
                    if (ret < OVSA_OK) {
                        OVSA_DBG(DBG_E, "OVSA: Error process EK_AK binding failed with code %d\n",
                                 ret);
                        goto out;
                    }
                    break;
                case OVSA_SEND_QUOTE_NONCE:
                    ret = ovsa_do_get_quote_nounce(asym_keyslot, (char*)read_buf, cust_lic_sig_buf,
                                                   &ssl_session);
                    if (ret < OVSA_OK) {
                        OVSA_DBG(DBG_E,
                                 "OVSA: Error read quote nonce from server failed with code %d\n",
                                 ret);
                        goto out;
                    }
                    ovsa_remove_quote_files();
                    break;
#endif
                case OVSA_SEND_UPDATE_CUST_LICENSE:
                    ret = ovsa_do_update_cust_license((char*)read_buf, customer_license,
                                                      &ssl_session);
                    if (ret < OVSA_OK) {
                        OVSA_DBG(DBG_E,
                                 "OVSA: Error read and update customer license from server failed "
                                 "with code %d\n",
                                 ret);
                        goto out;
                    }
                    break;
                case OVSA_SEND_LICENSE_CHECK_RESP:
                    ret = ovsa_do_get_license_check(asym_keyslot, (char*)read_buf);
                    if (ret < OVSA_OK) {
                        OVSA_DBG(DBG_E,
                                 "OVSA: Error read license check status from server failed with "
                                 "code %d\n",
                                 ret);
                        goto out;
                    }
                    license_check_complete = true;
                    break;
                default:
                    ret = OVSA_INVALID_CMD_TYPE;
                    OVSA_DBG(DBG_E, "OVSA: Error received Invalid command %d from Server\n", cmd);
                    goto out;
                    break;
            }
            ovsa_safe_free((char**)&command);
            ovsa_safe_free((char**)&read_buf);

        } while (license_check_complete == false);
        *status = license_check_complete;
    } else {
        OVSA_DBG(DBG_E, "OVSA: Error invalid Input parameter \n");
        ret = OVSA_INVALID_PARAMETER;
    }
out:
    ovsa_safe_free((char**)&command);
    ovsa_safe_free((char**)&read_buf);
    ovsa_safe_free(&cust_lic_sig_buf);
    ovsa_safe_free(&customer_lic_sig.customer_lic.isv_certificate);
    ovsa_safe_free_tcb_list(&customer_lic_sig.customer_lic.tcb_signatures);
    ovsa_safe_free_url_list(&customer_lic_sig.customer_lic.license_url_list);
    mbedtls_net_free(&g_verifier_fd);
    mbedtls_ctr_drbg_free(&g_ctr_drbg);
    mbedtls_entropy_free(&g_entropy);
    ovsa_license_service_close(ssl_session);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}
