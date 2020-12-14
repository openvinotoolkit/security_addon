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
/* json.h to be included at end due to dependencies */
#include "json.h"

#ifndef DISABLE_TPM2_HWQUOTE
#define MAX_LEN              13
#define DEFAULT_HOST_IP_ADDR "192.168.122.1"
#define DEFAULT_PORT         4450
#define SA                   struct sockaddr
static char kvm_host[MAX_LEN];
#endif

extern ovsa_status_t ovsa_do_tpm2_activatecredential(char* cred_outbuf);
extern ovsa_status_t ovsa_tpm2_generatequote(char* nonce);
extern ovsa_status_t ovsa_start_model_loader(const int asym_key_slot, const int peer_slot,
                                             ovsa_customer_license_sig_t* customer_lic_sig,
                                             ovsa_protected_model_sig_t* protect_model_sig,
                                             char** decrypt_xml, char** decrypt_bin, int* xml_len,
                                             int* bin_len);

static mbedtls_ctr_drbg_context g_ctr_drbg;
static mbedtls_entropy_context g_entropy;
static mbedtls_ssl_config g_conf;
static mbedtls_net_context g_verifier_fd;
static mbedtls_ssl_context g_ssl;

static ovsa_status_t ovsa_license_service_close(void* ssl);
static ovsa_status_t ovsa_license_service_write(void* ssl, const char* buf, size_t len);
static ovsa_status_t ovsa_license_service_read(void* ssl, uint8_t* buf, size_t len);
static ovsa_status_t ovsa_license_service_start(const char* in_servers,
                                                const char* in_ca_chain_path, void** out_ssl);

#define mbedtls_printf      printf
#define READ_TIMEOUT_MS     20000 /* 20 seconds */
#define MBEDTLS_DEBUG_LEVEL 0

static const char* g_cipher_suitename[CIPHER_SUITE_SIZE] = {
    "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"};
static int g_cipher_suite[CIPHER_SUITE_SIZE];
static mbedtls_ecp_group_id g_curve_list[CURVE_LIST_SIZE];

ovsa_command_type_t ovsa_get_command_type(const char* command) {
    ovsa_command_type_t cmd = OVSA_INVALID_CMD;

    if (!strcmp(command, "OVSA_SEND_NONCE"))
        cmd = OVSA_SEND_NONCE;
    else if (!strcmp(command, "OVSA_SEND_HW_QUOTE"))
        cmd = OVSA_SEND_HW_QUOTE;
    else if (!strcmp(command, "OVSA_SEND_EK_AK_BIND"))
        cmd = OVSA_SEND_EK_AK_BIND;
    else if (!strcmp(command, "OVSA_SEND_QUOTE_NONCE"))
        cmd = OVSA_SEND_QUOTE_NONCE;
    else if (!strcmp(command, "OVSA_SEND_LICENSE_CHECK_RESP"))
        cmd = OVSA_SEND_LICENSE_CHECK_RESP;
    else
        cmd = OVSA_INVALID_CMD;

    return cmd;
}

static void ovsa_mbedtls_debug_cb(void* ctx, int level, const char* file, int line,
                                  const char* str) {
    const char *p, *basename;
    (void)ctx;

    /* Extract basename from file */
    for (p = basename = file; *p != '\0'; p++) {
        if (*p == '/' || *p == '\\') {
            basename = p + 1;
        }
    }

    mbedtls_printf("%s:%04d: |%d| %s", basename, line, level, str);
}

static ovsa_status_t ovsa_license_service_write(void* ssl, const char* buf, size_t len) {
    ovsa_status_t ret         = OVSA_OK;
    mbedtls_ssl_context* _ssl = (mbedtls_ssl_context*)ssl;

    if (!_ssl || len > INT_MAX) {
        OVSA_DBG(DBG_E, "Error: Invalid Input parameter \n");
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

    if (!_ssl || len > INT_MAX) {
        OVSA_DBG(DBG_E, "Error: Invalid Input parameter \n");
        ret = OVSA_INVALID_PARAMETER;
        return ret;
    }

    size_t read = 0;
    while (read < len) {
        ret = mbedtls_ssl_read(_ssl, buf + read, len - read);
        if (!ret) {
            OVSA_DBG(DBG_E, "Error: mbedtls_ssl_read failed with error code %d \n", ret);
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
                                                const char* in_ca_chain_path, void** out_ssl) {
    ovsa_status_t ret               = OVSA_OK;
    char* servers                   = NULL;
    char* connected_addr            = NULL;
    char* connected_port            = NULL;
    char* issuer_dup                = NULL;
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
    mbedtls_net_init(&g_verifier_fd);
    mbedtls_ssl_config_init(&g_conf);
    mbedtls_ssl_init(&g_ssl);

    if (out_ssl == NULL) {
        OVSA_DBG(DBG_E, "Error: invalid input to start license service\n");
        ret = OVSA_INVALID_PARAMETER;
        goto out;
    }

    OVSA_DBG(DBG_D, "OVSA:calling mbedtls_ctr_drbg_seed\n");
    const char* pers = "ovsa-license-check";
    ret = mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func, &g_entropy, (const uint8_t*)pers,
                                strlen(pers));
    if (ret < 0) {
        OVSA_DBG(DBG_E, "Error: mbedtls_ctr_drbg_seed failed with error code %d \n", ret);
        goto out;
    }

    servers = strdup(in_servers);
    if (!servers) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto out;
    }

    OVSA_DBG(DBG_D, "OVSA:Getting address, port\n");
    char* saveptr1;
    char* saveptr2;
    char* str1;
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
        OVSA_DBG(DBG_E, "Error: mbedtls_net_connect returned error with code %d\n", ret);
        goto out;
    }

    OVSA_DBG(DBG_D, "OVSA:calling mbedtls_ssl_config_defaults\n");
    ret = mbedtls_ssl_config_defaults(&g_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:mbedtls_ssl_config_defaults returned error with code %d\n", ret);
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

    /* mbedtls debug */
    mbedtls_ssl_conf_dbg(&g_conf, ovsa_mbedtls_debug_cb, NULL);
    mbedtls_debug_set_threshold(MBEDTLS_DEBUG_LEVEL);

    ret = mbedtls_ssl_setup(&g_ssl, &g_conf);
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
            OVSA_DBG(DBG_E, "Error:mbedtls_ssl_handshake failed with error %d\n", ret);
            goto out;
        }
    }

    /* Extract the peer certificate from ssl context and perform the certificate validation */
    g_server_cert = (mbedtls_x509_crt*)mbedtls_ssl_get_peer_cert(&g_ssl);
    if (g_server_cert == NULL) {
        ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        OVSA_DBG(DBG_E, "Error: mbedtls_ssl_get_peer_cert failed with error %d\n", ret);
        goto out;
    }

    issuer_cert_mem = BIO_new_mem_buf(g_server_cert->raw.p, g_server_cert->raw.len);
    if (issuer_cert_mem == NULL) {
        ret = OVSA_CRYPTO_BIO_ERROR;
        OVSA_DBG(DBG_E, "Error: BIO_new_mem_buf failed with error %d\n", ret);
        goto out;
    }

    /* Convert the issuer certificate from DER to PEM */
    d2i_xcert = d2i_X509_bio(issuer_cert_mem, NULL);
    if (d2i_xcert == NULL) {
        ret = OVSA_CRYPTO_BIO_ERROR;
        OVSA_DBG(DBG_E, "Error: d2i_X509_bio failed with error %d\n", ret);
        goto out;
    }

    issuer_cert_bio = BIO_new(BIO_s_mem());
    if (issuer_cert_bio == NULL) {
        ret = OVSA_CRYPTO_BIO_ERROR;
        OVSA_DBG(DBG_E, "Error: BIO_new failed with error %d\n", ret);
        goto out;
    }

    if (!PEM_write_bio_X509(issuer_cert_bio, d2i_xcert)) {
        ret = OVSA_CRYPTO_PEM_ENCODE_ERROR;
        OVSA_DBG(DBG_E, "Error: PEM_write_bio_X509 failed with error %d\n", ret);
        goto out;
    }

    BIO_get_mem_ptr(issuer_cert_bio, &issuer_cert_ptr);
    if (issuer_cert_ptr == NULL) {
        ret = OVSA_CRYPTO_BIO_ERROR;
        OVSA_DBG(DBG_E, "Error: BIO_get_mem_ptr failed with error %d\n", ret);
        goto out;
    }

    ret = ovsa_safe_malloc(issuer_cert_ptr->length + NULL_TERMINATOR, &issuer_dup);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "Error: Issuer cert memory failed with code %d\n", ret);
        goto out;
    }

    /* Copy the issuer certificate to local buffer */
    if (memcpy_s(issuer_dup, issuer_cert_ptr->length, issuer_cert_ptr->data,
                 issuer_cert_ptr->length) != EOK) {
        ret = OVSA_MEMIO_ERROR;
        OVSA_DBG(DBG_E, "Error: Getting the issuer cert failed with error %d\n", ret);
        goto out;
    }

    /* Verify the peer certificate */
    ret = ovsa_crypto_extract_pubkey_verify_cert(
        /* PEER CERT */ true, issuer_dup, /* lifetime_validity_check */ true, &peer_cert_slot);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Verifying server certificate failed with code %d\n", ret);
        goto out;
    }
    *out_ssl = &g_ssl;

out:

    if (ret < OVSA_OK || !out_ssl) {
        mbedtls_net_free(&g_verifier_fd);
        mbedtls_ssl_free(&g_ssl);
        mbedtls_ssl_config_free(&g_conf);
        mbedtls_ctr_drbg_free(&g_ctr_drbg);
        mbedtls_entropy_free(&g_entropy);
    }

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

ovsa_status_t ovsa_validate_protected_model(const int peer_keyslot, const char* protected_model,
                                            ovsa_protected_model_sig_t* protect_model_sig) {
    ovsa_status_t ret           = OVSA_OK;
    size_t prot_model_file_size = 0;
    char* prot_model_sig_buf    = NULL;
    char* prot_model_buf        = NULL;
    char* peer_certificate      = NULL;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    if (protected_model != NULL) {
        /* Load protect model Artifact */
        FILE* fprot_model = fopen(protected_model, "r");
        if (fprot_model == NULL) {
            ret = OVSA_FILEOPEN_FAIL;
            OVSA_DBG(DBG_E, "Error: Opening protect model file failed with code %d\n", ret);
            goto out;
        }
        prot_model_file_size = ovsa_crypto_get_file_size(fprot_model);
        ret = ovsa_safe_malloc(prot_model_file_size * sizeof(char), &prot_model_sig_buf);
        if (ret < OVSA_OK) {
            ret = OVSA_MEMORY_ALLOC_FAIL;
            OVSA_DBG(DBG_E, "Error: Init memory failed with code %d\n", ret);
            fclose(fprot_model);
            goto out;
        }
        if (!fread(prot_model_sig_buf, 1, prot_model_file_size, fprot_model)) {
            ret = OVSA_FILEIO_FAIL;
            OVSA_DBG(DBG_E, "Error: Read protected model file failed with code %d\n", ret);
            fclose(fprot_model);
            goto out;
        }
        prot_model_sig_buf[prot_model_file_size - 1] = '\0';
        fclose(fprot_model);
        /* Extract protected model json blob */
        ret = ovsa_json_extract_protected_model(prot_model_sig_buf, protect_model_sig);
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Extract_protected_model_json_blob failed with code %d\n", ret);
            goto out;
        }
        peer_certificate = protect_model_sig->protect_model.isv_certificate;
        /* Verify protect model json_blob */
        ret = ovsa_safe_malloc(prot_model_file_size * sizeof(char), &prot_model_buf);
        if (ret < OVSA_OK) {
            ret = OVSA_MEMORY_ALLOC_FAIL;
            OVSA_DBG(DBG_E, "Error: Init memory failed with code %d\n", ret);
            goto out;
        }
        OVSA_DBG(DBG_I, "OVSA: Verify protected model signature\n");
        ret = ovsa_crypto_verify_json_blob(peer_keyslot, prot_model_sig_buf, prot_model_file_size,
                                           prot_model_buf);
        if (ret != OVSA_OK || prot_model_buf == NULL) {
            OVSA_DBG(DBG_E, "Error: Verify protected model json blob failed with code  %d\n", ret);
        }
    } else {
        OVSA_DBG(DBG_E, "Error: Invalid protected model artifact \n");
        ret = OVSA_INVALID_PARAMETER;
    }
out:
    ovsa_safe_free(&prot_model_sig_buf);
    ovsa_safe_free(&prot_model_buf);
    ovsa_safe_free(&peer_certificate);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_validate_customer_license(const char* customer_license, const int asym_keyslot,
                                             ovsa_customer_license_sig_t* customer_lic_sig) {
    ovsa_status_t ret         = OVSA_OK;
    size_t cust_lic_file_size = 0;
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
            OVSA_DBG(DBG_E, "Error: Opening customer license file failed with code %d\n", ret);
            goto out;
        }
        cust_lic_file_size = ovsa_crypto_get_file_size(fcust_lic);
        ret                = ovsa_safe_malloc(cust_lic_file_size * sizeof(char), &cust_lic_sig_buf);
        if (ret < OVSA_OK) {
            ret = OVSA_MEMORY_ALLOC_FAIL;
            OVSA_DBG(DBG_E, "Error: Init memory failed with code %d\n", ret);
            fclose(fcust_lic);
            goto out;
        }
        if (!fread(cust_lic_sig_buf, 1, cust_lic_file_size, fcust_lic)) {
            ret = OVSA_FILEIO_FAIL;
            OVSA_DBG(DBG_E, "Error: Read customer license file failed with code %d\n", ret);
            fclose(fcust_lic);
            goto out;
        }
        cust_lic_sig_buf[cust_lic_file_size - 1] = '\0';
        fclose(fcust_lic);
        /* Extract customer licensce json blob */
        ret = ovsa_json_extract_customer_license(cust_lic_sig_buf, customer_lic_sig);
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Extract customer license json blob failed with code %d\n", ret);
            goto out;
        }
        peer_cert = customer_lic_sig->customer_lic.isv_certificate;

        OVSA_DBG(DBG_I, "OVSA: Verify PEER certificate\n");
        /* Verifying customer license ISV Certificate */
        ret = ovsa_crypto_extract_pubkey_verify_cert(
            /* PEER CERT */ true, peer_cert, /* lifetime_validity_check */ true, &peer_keyslot);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Get keyslot failed with code %d\n", ret);
            goto out;
        }
        /* Verify customer license json_blob */
        ret = ovsa_safe_malloc(cust_lic_file_size * sizeof(char), &cust_lic_buf);
        if (ret < OVSA_OK) {
            ret = OVSA_MEMORY_ALLOC_FAIL;
            OVSA_DBG(DBG_E, "Error: Init memory failed with code %d\n", ret);
            goto out;
        }

        OVSA_DBG(DBG_I, "OVSA: Verify customer license signature\n");
        /* Extract encryption_key from customer license */
        ret =
            ovsa_json_extract_element(cust_lic_sig_buf, "encryption_key", (void**)&encryption_key);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Extract json element failed with error code %d\n", ret);
            goto out;
        }

        /* Compute shared key using customer private key and ISV public key */
        ret = ovsa_crypto_create_ecdh_key(asym_keyslot, peer_keyslot, &shared_key_slot);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Generating shared key failed with error code %d\n", ret);
            goto out;
        }

        /* Extract salt from encryption_key and derive key/IV/HMAC for customer license */
        ret = ovsa_crypto_derive_keyiv_hmac(shared_key_slot, encryption_key,
                                            strnlen_s(encryption_key, MAX_EKEY_SIZE),
                                            &keyiv_hmac_slot);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Deriving key/IV/HAMC failed with error code %d\n", ret);
            goto out;
        }

        /* Verifies the HMAC for customer license */
        ret = ovsa_crypto_verify_hmac_json_blob(keyiv_hmac_slot, cust_lic_sig_buf,
                                                cust_lic_file_size, cust_lic_buf);
        if (ret != OVSA_OK || cust_lic_buf == NULL) {
            OVSA_DBG(DBG_E, "Error: Verify customer license json blob failed with code %d\n", ret);
            goto out;
        }
        ret = peer_keyslot;
    } else {
        OVSA_DBG(DBG_E, "Error: Invalid customer license artifact \n");
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

static ovsa_status_t ovsa_do_get_license_check(const int asym_keyslot,
                                               char* cust_lic_check_status_buf) {
    ovsa_status_t ret       = OVSA_OK;
    char* lic_check_payload = NULL;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    ret = ovsa_json_extract_element((char*)cust_lic_check_status_buf, "payload",
                                    (void*)&lic_check_payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
        goto out;
    }

    if (!(strcmp(lic_check_payload, "PASS"))) {
        OVSA_DBG(DBG_I, "OVSA:Received license check result from Server: '%s'\n",
                 lic_check_payload);
    } else {
        ret = OVSA_LICENSE_CHECK_FAIL;
        OVSA_DBG(DBG_I, "OVSA: %s\n", lic_check_payload);
        OVSA_DBG(DBG_E, "Error:Model loader License check failed with code %d \n", ret);
    }
out:
    ovsa_safe_free(&lic_check_payload);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_do_read_runtime_quote(ovsa_quote_info_t* sw_quote_info) {
    ovsa_status_t ret       = OVSA_OK;
    char* pcr_list_buf      = NULL;
    char* pcr_quote_buf     = NULL;
    char* pcr_signature_buf = NULL;
    size_t file_size        = 0;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /* read pcr_list */
    ret = ovsa_read_file_content(TPM2_SWQUOTE_PCR, &pcr_list_buf, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Reading TPM2_SWQUOTE_PCR file failed with error code %d\n", ret);
        goto out;
    }
    /* convert pcr bin to pem*/
    ret = ovsa_crypto_convert_bin_to_base64(pcr_list_buf, file_size - 1, &sw_quote_info->quote_pcr);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Crypto convert_bin_to_pem failed with code %d\n", ret);
        goto out;
    }
    /* read pcr quote */
    ret = ovsa_read_file_content(TPM2_SWQUOTE_MSG, &pcr_quote_buf, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Reading TPM2_SWQUOTE_PCR file failed with error code %d\n", ret);
        goto out;
    }
    /* convert pcr_quote to pem*/
    ret = ovsa_crypto_convert_bin_to_base64(pcr_quote_buf, file_size - 1,
                                            &sw_quote_info->quote_message);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Crypto convert_bin_to_pem failed with code %d\n", ret);
        goto out;
    }
    /* read pcr signature */
    ret = ovsa_read_file_content(TPM2_SWQUOTE_SIG, &pcr_signature_buf, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Reading TPM2_SWQUOTE_PCR file failed with error code %d\n", ret);
        goto out;
    }
    /* convert pcr_quote to pem*/
    ret = ovsa_crypto_convert_bin_to_base64(pcr_signature_buf, file_size - 1,
                                            &sw_quote_info->quote_sig);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Crypto convert_bin_to_pem failed with code %d\n", ret);
        goto out;
    }
    /*read Pub_key */
    ret = ovsa_read_file_content(TPM2_AK_PUB_PEM_KEY, &sw_quote_info->ak_pub_key, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Reading TPM2_SWQUOTE_PCR file failed with error code %d\n", ret);
        goto out;
    }
out:
    ovsa_safe_free(&pcr_list_buf);
    ovsa_safe_free(&pcr_quote_buf);
    ovsa_safe_free(&pcr_signature_buf);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_socket_read(const int sockfd, char* buf, const size_t len) {
    ovsa_status_t ret = OVSA_OK;

    if (sockfd == 0 || len == 0) {
        OVSA_DBG(DBG_E, "%s failed with invalid parameter, sockfd = %d\n", __func__, sockfd);
        ret = OVSA_INVALID_PARAMETER;
        return ret;
    }
    int readdata = 0;

    while (readdata < len) {
        readdata = recv(sockfd, buf + readdata, len - readdata, 0);
        if (readdata == 0) {
            OVSA_DBG(DBG_I, "Socket connection is closed by remote...\n");
            ret = OVSA_SOCKET_CONN_CLOSED;
            goto out;
        } else if (readdata < 0) {
            OVSA_DBG(DBG_E, "Read failure over socket with error %s\n", strerror(errno));
            ret = OVSA_SOCKET_READ_FAIL;
            goto out;
        }
    }
out:
    return ret;
}

ovsa_status_t ovsa_socket_write(const int sockfd, const char* buf, const size_t len) {
    ovsa_status_t ret = OVSA_OK;

    if (sockfd == 0 || len == 0) {
        OVSA_DBG(DBG_E, "%s failed with invalid parameter, sockfd = %d\n", __func__, sockfd);
        ret = OVSA_INVALID_PARAMETER;
        return ret;
    }
    int written = 0;

    while (written < len) {
        written = send(sockfd, buf + written, len - written, 0);
        if (written == 0) {
            OVSA_DBG(DBG_I, "Socket connection is closed by remote...\n");
            ret = OVSA_SOCKET_CONN_CLOSED;
        } else if (written < 0) {
            OVSA_DBG(DBG_E, "Error: Write failure over socket with error %s\n", strerror(errno));
            ret = OVSA_SOCKET_WRITE_FAIL;
        }
    }
    return ret;
}
#ifndef DISABLE_TPM2_HWQUOTE
static ovsa_status_t ovsa_read_payload(const int sockfd, char** read_buf, char** command) {
    ovsa_status_t ret   = OVSA_OK;
    size_t payload_size = 0;
    char payload_len_str[PAYLOAD_LENGTH + 1];

    OVSA_DBG(DBG_D, "OVSA: Entering %s\n", __func__);

    memset_s(payload_len_str, sizeof(payload_len_str), 0);

    /* Read payload length */
    ret = ovsa_socket_read(sockfd, payload_len_str, PAYLOAD_LENGTH);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Host server read communication failed  %d\n", ret);
        goto out;
    }
    payload_size = atoi(payload_len_str);
    OVSA_DBG(DBG_I, "OVSA: payload_size  %d\n", (int)payload_size);
    if ((payload_size < OVSA_OK || payload_size > UINT_MAX)) {
        ret = OVSA_INVALID_PARAMETER;
        OVSA_DBG(DBG_E, "Error: Host server read payload size '%d'  invalid \n", (int)payload_size);
        goto out;
    }
    ret = ovsa_safe_malloc((sizeof(char) * payload_size + 1), read_buf);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "Error: Memory init failed\n");
        goto out;
    }
    memset_s(*read_buf, payload_size + 1, 0);
    /* Read payload  */
    ret = ovsa_socket_read(sockfd, *read_buf, payload_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Host server read communication failed with code %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA:Received payload\n'%s'\n", *read_buf);
    /* Read command from json file*/
    ret = ovsa_json_extract_element(*read_buf, "command", (void*)command);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read command from json failed %d\n", ret);
        goto out;
    }
out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_create_nonce(char** nonce_buf) {
    ovsa_status_t ret  = OVSA_OK;
    BIO* out_bio       = NULL;
    BIO* nonce_bio     = NULL;
    BIO* b64           = NULL;
    BUF_MEM* nonce_ptr = NULL;
    int rng            = 0;
    unsigned char nonce[NONCE_SIZE];

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    memset_s(nonce, sizeof(nonce), 0);

    out_bio = BIO_new(BIO_s_mem());
    if (out_bio == NULL) {
        OVSA_DBG(DBG_E,
                 "Error: Generate nonce failed in getting new "
                 "BIO for the output buffer\n");
        ret = -1;
        goto out;
    }

    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        OVSA_DBG(DBG_E,
                 "Error: Client license check callback failed in getting the "
                 "b64 encode method\n");
        ret = -1;
        goto out;
    }

    nonce_bio = out_bio;
    nonce_bio = BIO_push(b64, nonce_bio);

    /* Generate nonce for customer validation */
    rng = RAND_bytes(nonce, NONCE_SIZE);
    if (rng <= OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: RAND_bytes() returned %d\n", rng);
        return -EINVAL;
    }
    if (BIO_write(nonce_bio, nonce, NONCE_SIZE) != NONCE_SIZE) {
        OVSA_DBG(DBG_E, "Error: Client license check callback failed in writing the nonce\n");
        ret = -1;
        goto out;
    }

    if (!BIO_flush(nonce_bio)) {
        OVSA_DBG(DBG_E,
                 "Error: Client license check callback failed in flushing the "
                 "output buffer\n");
        ret = -1;
        goto out;
    }

    BIO_get_mem_ptr(nonce_bio, &nonce_ptr);
    if (nonce_ptr == NULL) {
        OVSA_DBG(DBG_E, "Error: Client license check callback failed to extract the nonce\n");
        ret = -1;
        goto out;
    }

    ret = ovsa_safe_malloc((sizeof(char) * NONCE_BUF_SIZE), nonce_buf);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "Error: Memory init failed\n");
        goto out;
    }

    if (memcpy_s(*nonce_buf, NONCE_BUF_SIZE, nonce_ptr->data, nonce_ptr->length) != EOK) {
        OVSA_DBG(DBG_E, "Error: Client license check callback failed in getting the nonce\n");
        ret = -1;
        goto out;
    }

out:
    BIO_free(b64);
    BIO_free_all(out_bio);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_get_hw_quote(const int sockfd, char* nonce_buf,
                                ovsa_quote_info_t* hw_quote_info) {
    ovsa_status_t ret                 = OVSA_OK;
    char* readbuff                    = NULL;
    char* quote_buf                   = NULL;
    char* json_payload                = NULL;
    char* command                     = NULL;
    size_t length                     = 0;
    size_t payload_len                = 0;
    size_t buf_len                    = 0;
    char* hw_quote_payload            = NULL;
    bool received_all_HW_quote_params = false;
    ovsa_command_type_t cmd           = OVSA_INVALID_CMD;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /* create json message blob */
    ret = ovsa_json_create_message_blob(OVSA_SEND_HW_QUOTE, nonce_buf, &quote_buf, &length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:Create SW quote message failed with error code %d\n", ret);
        goto out;
    }
    /* Append payload length to json blob*/
    payload_len = length + PAYLOAD_LENGTH + 1;
    ret         = ovsa_safe_malloc(sizeof(char) * payload_len, &json_payload);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "Error: Create json blob memory init failed\n");
        goto out;
    }
    ret = ovsa_append_json_payload_len_to_blob(quote_buf, &json_payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:json blob creation failed with %d\n", ret);
        goto out;
    }
    ret = ovsa_get_string_length(json_payload, &buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of json_payload string %d\n", ret);
        goto out;
    }
    /* Send nonce to host Server */
    ret = ovsa_socket_write(sockfd, json_payload, buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read payload from failed %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA:Send nonce to host server\n%s\n", json_payload);

    do {
        /* Receive payload from host server*/
        ret = ovsa_read_payload(sockfd, &readbuff, &command);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Read payload from failed %d\n", ret);
            goto out;
        }
        cmd = ovsa_get_command_type((char*)command);
        if (cmd == OVSA_INVALID_CMD) {
            ret = OVSA_INVALID_CMD_TYPE;
            OVSA_DBG(DBG_E, "Error: Read payload from failed %d\n", ret);
            goto out;
        }
        switch (cmd) {
            case OVSA_SEND_HW_QUOTE:
                /* Read HW quote from json file */
                ret = ovsa_json_extract_element(readbuff, "payload", (void*)&hw_quote_payload);
                if (ret < OVSA_OK) {
                    OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
                    goto out;
                }
                received_all_HW_quote_params = true;
                break;
            default:
                ret = OVSA_INVALID_CMD_TYPE;
                OVSA_DBG(DBG_E, "Error: Received Invalid command %d from client\n", cmd);
                goto out;
                break;
        }
        ovsa_safe_free(&command);
        ovsa_safe_free(&readbuff);
    } while (received_all_HW_quote_params == false);

    /* Read HW_quote_pcr from json file */
    ret = ovsa_json_extract_element(hw_quote_payload, "HW_Quote_PCR",
                                    (void*)&hw_quote_info->quote_pcr);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read HW_Quote_PCR from json failed %d\n", ret);
        goto out;
    }
    /* Read HW_pub_key from json file */
    ret = ovsa_json_extract_element(hw_quote_payload, "HW_AK_Pub_Key",
                                    (void*)&hw_quote_info->ak_pub_key);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read HW_AK_Pub_Key from json failed %d\n", ret);
        goto out;
    }
    /* Read HW_quote_msg from json file */
    ret = ovsa_json_extract_element(hw_quote_payload, "HW_Quote_MSG",
                                    (void*)&hw_quote_info->quote_message);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read HW_Quote_MSG from json failed %d\n", ret);
        goto out;
    }
    /* Read HW_quote_sig from json file */
    ret = ovsa_json_extract_element(hw_quote_payload, "HW_Quote_SIG",
                                    (void*)&hw_quote_info->quote_sig);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read HW_Quote_SIG from json failed %d\n", ret);
        goto out;
    }
    /* Read HW_ek_cert from json file */
    ret = ovsa_json_extract_element(hw_quote_payload, "HW_EK_Cert", (void*)&hw_quote_info->ek_cert);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read HW_EK_Cert from json failed %d\n", ret);
        goto out;
    }
out:
    ovsa_safe_free(&readbuff);
    ovsa_safe_free(&command);
    ovsa_safe_free(&quote_buf);
    ovsa_safe_free(&json_payload);
    ovsa_safe_free(&hw_quote_payload);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_establish_host_connection(int* _sockfd) {
    ovsa_status_t ret = OVSA_OK;
    int sockfd;
    struct sockaddr_in servaddr;
    struct timeval timeout;
    char* port_number = NULL;
    char* kvm_host_ip = NULL;
    int port          = 0;
    static char port_str[MAX_LEN];

    /***********************************************************************/
    /* Get KVM_TCP_PORT_NUMBER & KVM_HOST_IP Using ENV Variable            */
    /***********************************************************************/
    port_number = secure_getenv("KVM_TCP_PORT_NUMBER");
    if (port_number == NULL) {
        port = DEFAULT_PORT;
    } else {
        strcpy_s(port_str, RSIZE_MAX_STR, port_number);
        port = atoi(port_str);
    }

    kvm_host_ip = secure_getenv("KVM_HOST_IP");
    if (kvm_host_ip == NULL) {
        strcpy_s(kvm_host, RSIZE_MAX_STR, DEFAULT_HOST_IP_ADDR);
    } else {
        strcpy_s(kvm_host, RSIZE_MAX_STR, kvm_host_ip);
    }
    OVSA_DBG(DBG_I, "\nOVSA: port_number:%d\n", port);
    OVSA_DBG(DBG_I, "OVSA: kvm_host_IP Address:%s\n", kvm_host);

    /* socket create and varification */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        OVSA_DBG(DBG_E, "Error: socket creation failed with error %s\n", strerror(errno));
        ret = OVSA_SOCKET_CONN_FAIL;
        return ret;
    }
    OVSA_DBG(DBG_I, "OVSA: Socket creation successful..\n");
    bzero(&servaddr, sizeof(servaddr));

    /* assign IP, PORT */
    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(kvm_host);
    servaddr.sin_port        = htons(port);

    /* connect lient socket to server socket */
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
        OVSA_DBG(DBG_E, "Error: connection with the server failed with error %s\n",
                 strerror(errno));
        close(sockfd);
        ret = OVSA_SOCKET_CONN_FAIL;
        return ret;
    }
    OVSA_DBG(DBG_I, "OVSA: Connection to the server successful...\n");
    timeout.tv_sec  = 15;
    timeout.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) < 0) {
        OVSA_DBG(DBG_E,
                 "Error: Setsockopt failed while setting receive timeout with "
                 "error %s\n",
                 strerror(errno));
        close(sockfd);
        ret = OVSA_SOCKET_CONN_FAIL;
        return ret;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout)) < 0) {
        OVSA_DBG(DBG_E, "Error: Setsockopt failed while setting send timeout with error %s\n",
                 strerror(errno));
        close(sockfd);
        ret = OVSA_SOCKET_CONN_FAIL;
        return ret;
    }

    *_sockfd = sockfd;
    return ret;
}

static ovsa_status_t ovsa_tpm2_generate_runtime_HW_quote(ovsa_quote_info_t* hw_quote_info,
                                                         char* quote_nonce) {
    ovsa_status_t ret = OVSA_OK;
    int sockfd        = -1;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /********************************************/
    /*       GET HW QUOTE using SSL connection  */
    /********************************************/
    /* Estabish host connection */
    ret = ovsa_establish_host_connection(&sockfd);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: ovsa_establish_host_connection failed with code %d\n", ret);
        goto out;
    }
    /* Get HWQuote */
    ret = ovsa_get_hw_quote(sockfd, quote_nonce, hw_quote_info);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: ovsa_establish_host_connection failed with code %d\n", ret);
        goto out;
    }
    close(sockfd);
    OVSA_DBG(DBG_I, "OVSA:Generated HW quote successfully \n");

out:
    if (sockfd != -1) {
        close(sockfd);
    }
    OVSA_DBG(DBG_D, "\nOVSA:%s Exit\n", __func__);
    return ret;
}
#endif

static ovsa_status_t ovsa_extract_server_quote_nonce(char* payload, char** quote_nonce) {
    ovsa_status_t ret = OVSA_OK;
    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    char* nonce_bin_buff    = NULL;
    size_t nonce_bin_length = 0;
    size_t size             = 0;

    /* Read server nonce from json file */
    ret = ovsa_json_extract_element(payload, "quote_nonce", (void*)quote_nonce);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
        goto out;
    }
    ret = ovsa_get_string_length(*quote_nonce, &size);
    ret = ovsa_safe_malloc((sizeof(char) * size), &nonce_bin_buff);
    if (ret < OVSA_OK || nonce_bin_buff == NULL) {
        OVSA_DBG(DBG_E, "OVSA: pcr quote buffer allocation failed %d\n", ret);
        goto out;
    }
    ret = ovsa_crypto_convert_base64_to_bin(*quote_nonce, size, nonce_bin_buff, &nonce_bin_length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Crypto convert_base64_to_bin failed with code %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_D, "OVSA: nonce_bin_length %d\n", (int)nonce_bin_length);

    /* write quote nounce to file  */
    FILE* fquote_nonce = fopen(SERVER_NONCE, "w");
    if (fquote_nonce == NULL) {
        OVSA_DBG(DBG_E, "\n Error: opening quote_nonce.bin !\n");
        ret = OVSA_FILEOPEN_FAIL;
        goto out;
    }
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of nonce_buf string %d\n", ret);
        goto out;
    }
    fwrite(nonce_bin_buff, nonce_bin_length, 1, fquote_nonce);
    fclose(fquote_nonce);
out:
    ovsa_safe_free(&nonce_bin_buff);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_tpm2_generate_runtime_SW_quote(char* payload,
                                                         ovsa_quote_info_t* sw_quote_info) {
    ovsa_status_t ret = OVSA_OK;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /* Generate tpm2 quote*/
    ret = ovsa_tpm2_generatequote(SERVER_NONCE);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: ovsa_tpm2_generatequote failed with code %d\n", ret);
        goto out;
    }
    ret = ovsa_do_read_runtime_quote(sw_quote_info);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: read_SW_quote failed with code %d\n", ret);
        goto out;
    }
out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_do_tpm2_activatecredential_quote_nonce(char* payload,
                                                                 char** actcred_buf) {
    ovsa_status_t ret         = OVSA_OK;
    char* cred_outbuf         = NULL;
    char* credout_bin         = NULL;
    size_t credout_bin_length = 0;
    size_t size               = 0;
    size_t file_size          = 0;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /* Read credout from json file */
    ret = ovsa_json_extract_element(payload, "cred_blob", (void*)&cred_outbuf);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Read payload from json failed %d\n", ret);
        goto out;
    }
    ret = ovsa_get_string_length(cred_outbuf, &size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of payload string %d\n", ret);
        goto out;
    }
    ret = ovsa_safe_malloc((sizeof(char) * size), (char**)&credout_bin);
    if (ret < OVSA_OK || credout_bin == NULL) {
        OVSA_DBG(DBG_E, "Error: credout buffer allocation failed %d\n", ret);
        goto out;
    }
    ret = ovsa_crypto_convert_base64_to_bin(cred_outbuf, size, credout_bin, &credout_bin_length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error Crypto convert_base64_to_bin failed with code %d\n", ret);
        goto out;
    }
    /* write credout bin to file  */
    FILE* fptr_credout = fopen(TPM2_CREDOUT_FILE, "wb");
    if (fptr_credout == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "Error: Opening file cred.out.bin failed with code %d\n", ret);
        goto out;
    }
    fwrite(credout_bin, credout_bin_length, 1, fptr_credout);
    fclose(fptr_credout);

    /* process tpm2_activatecredential*/
    ret = ovsa_do_tpm2_activatecredential(credout_bin);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: ovsa_do_tpm2_activatecredential failed %d\n", ret);
        goto out;
    }
    /* read decrypted secret */
    file_size = 0;
    ret       = ovsa_read_file_content(TPM2_ACTCRED_OUT, actcred_buf, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Reading TPM2_ACTCRED_OUT file failed with error code %d\n", ret);
        goto out;
    }

out:
    ovsa_safe_free(&credout_bin);
    ovsa_safe_free(&cred_outbuf);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_do_get_quote_nounce(const int asym_keyslot, char* quote_credout_blob,
                                              char* cust_lic_sig_buf, void** _ssl_session) {
    ovsa_status_t ret           = OVSA_OK;
    void* ssl_session           = NULL;
    size_t length               = 0;
    size_t quote_payload_len    = 0;
    unsigned char* json_payload = NULL;
    char* payload               = NULL;
    char* cust_lic_msg_blob_buf = NULL;
    size_t cust_lic_payload_len = 0;
    char* cust_lic_json_payload = NULL;
    char* quote_info            = NULL;
    char* quote_buf             = NULL;
    char* actcred_buf           = NULL;
    char* quote_nonce           = NULL;
    size_t buf_len              = 0;
    ovsa_quote_info_t sw_quote_info;
    ovsa_quote_info_t hw_quote_info;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    ssl_session = *_ssl_session;
    memset_s(&sw_quote_info, sizeof(ovsa_quote_info_t), 0);
    memset_s(&hw_quote_info, sizeof(ovsa_quote_info_t), 0);

    /* Read payload from json file*/
    ret = ovsa_json_extract_element((char*)quote_credout_blob, "payload", (void*)&payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:Read payload from json failed %d\n", ret);
        goto out;
    }
    ret = ovsa_do_tpm2_activatecredential_quote_nonce(payload, &actcred_buf);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E,
                 "Error: ovsa_do_tpm2_activatecredential_quote_nonce failed with error code %d\n",
                 ret);
        goto out;
    }
    ret = ovsa_extract_server_quote_nonce(payload, &quote_nonce);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Extract quote failed with error code %d\n", ret);
        goto out;
    }
    ret = ovsa_tpm2_generate_runtime_SW_quote(payload, &sw_quote_info);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Get quote measurements failed with error code %d\n", ret);
        goto out;
    }
#ifndef DISABLE_TPM2_HWQUOTE
    ret = ovsa_tpm2_generate_runtime_HW_quote(&hw_quote_info, quote_nonce);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Get quote measurements failed with error code %d\n", ret);
        goto out;
    }
#endif
    ret = ovsa_json_create_quote_info_blob(actcred_buf, sw_quote_info, hw_quote_info, &quote_info,
                                           &length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:Create create quote update info blob failed with error code %d\n",
                 ret);
        goto out;
    }
    /* create json message blob */
    ret = ovsa_json_create_message_blob(OVSA_SEND_QUOTE_INFO, quote_info, &quote_buf, &length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:Create SW quote message failed with error code %d\n", ret);
        goto out;
    }
    /* Append payload length to json blob*/
    quote_payload_len = length + PAYLOAD_LENGTH + 1;
    ret               = ovsa_safe_malloc(sizeof(char) * quote_payload_len, (char**)&json_payload);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "Error: Create json blob memory init failed\n");
        goto out;
    }

    ret = ovsa_append_json_payload_len_to_blob(quote_buf, (char**)&json_payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:json blob creation failed with %d\n", ret);
        goto out;
    }
    ret = ovsa_get_string_length((char*)json_payload, &buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of json_payload string %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA:Send quote to server\n%s", json_payload);
    /* Send pcr quote to Server */
    ret = ovsa_license_service_write(ssl_session, (char*)json_payload, buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: ovsa_license_service_write() returned %d\n", ret);
        goto out;
    }
    /* create customer license json message blob */
    ret = ovsa_json_create_message_blob(OVSA_SEND_CUST_LICENSE, cust_lic_sig_buf,
                                        &cust_lic_msg_blob_buf, &length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Create nonce_message failed with error code %d\n", ret);
        goto out;
    }
    cust_lic_payload_len = length + PAYLOAD_LENGTH + 1;
    ret = ovsa_safe_malloc(sizeof(char) * cust_lic_payload_len, (char**)&cust_lic_json_payload);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "Error: Create json blob memory init failed\n");
        goto out;
    }
    ret = ovsa_append_json_payload_len_to_blob(cust_lic_msg_blob_buf, &cust_lic_json_payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:json blob creation failed with %d\n", ret);
        goto out;
    }
    /* Send customer license to Server */
    ret = ovsa_get_string_length((char*)cust_lic_json_payload, &buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of cust_lic_json_payload string %d\n", ret);
        goto out;
    }
    ret = ovsa_license_service_write(ssl_session, (char*)cust_lic_json_payload, buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: ovsa_license_service_write() returned %d\n", ret);
        goto out;
    }
out:
    ovsa_safe_free(&quote_buf);
    ovsa_safe_free(&payload);
    ovsa_safe_free(&sw_quote_info.quote_pcr);
    ovsa_safe_free(&sw_quote_info.quote_message);
    ovsa_safe_free(&sw_quote_info.quote_sig);
    ovsa_safe_free(&sw_quote_info.ak_pub_key);
    ovsa_safe_free(&sw_quote_info.ek_pub_key);
    ovsa_safe_free(&sw_quote_info.ek_cert);
#ifndef DISABLE_TPM2_HWQUOTE
    ovsa_safe_free(&hw_quote_info.quote_pcr);
    ovsa_safe_free(&hw_quote_info.quote_message);
    ovsa_safe_free(&hw_quote_info.quote_sig);
    ovsa_safe_free(&hw_quote_info.ak_pub_key);
    ovsa_safe_free(&hw_quote_info.ek_pub_key);
    ovsa_safe_free(&hw_quote_info.ek_cert);
#endif
    ovsa_safe_free(&quote_info);
    ovsa_safe_free((char**)&json_payload);
    ovsa_safe_free(&cust_lic_msg_blob_buf);
    ovsa_safe_free((char**)&cust_lic_json_payload);
    ovsa_safe_free(&actcred_buf);
    ovsa_safe_free(&quote_nonce);

    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_do_sign_send_nounce(const int asym_keyslot, char* nonce_buf,
                                              char* cust_lic_sig_buf, void** _ssl_session) {
    ovsa_status_t ret = OVSA_OK;
    void* ssl_session = NULL;
    char nonce_signed[MAX_SIGNATURE_SIZE];
    size_t length                        = 0;
    char* nonce_signbuf_str              = NULL;
    size_t sign_payload_len              = 0;
    unsigned char* json_payload          = NULL;
    char* payload                        = NULL;
    char* cust_lic_msg_blob_buf          = NULL;
    unsigned char* cust_lic_json_payload = NULL;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    ssl_session = *_ssl_session;
    memset_s(nonce_signed, sizeof(nonce_signed), 0);

    /* Read payload from json file */
    ret = ovsa_json_extract_element((char*)nonce_buf, "payload", (void*)&payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:Read payload from json failed %d\n", ret);
        goto out;
    }
    /* sign nonce */
    size_t buf_len = 0;
    ret            = ovsa_get_string_length((char*)nonce_buf, &buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of nonce_buf string %d\n", ret);
        goto out;
    }
    ret = ovsa_crypto_sign_mem(asym_keyslot, (char*)payload, buf_len, nonce_signed);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: nonce Signing failed with code %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA:Send signed nonce to server\n");

    /* create signed nonce json message blob */
    ret = ovsa_json_create_message_blob(OVSA_SEND_SIGN_NONCE, nonce_signed, &nonce_signbuf_str,
                                        &length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:Create nonce_message failed with error code %d\n", ret);
        goto out;
    }
    /* Append payload length to json blob */
    sign_payload_len = length + PAYLOAD_LENGTH + 1;
    ret              = ovsa_safe_malloc(sizeof(char) * sign_payload_len, (char**)&json_payload);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "Error: Create json blob memory init failed\n");
        goto out;
    }
    ret = ovsa_append_json_payload_len_to_blob(nonce_signbuf_str, (char**)&json_payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:json blob creation failed with %d\n", ret);
        goto out;
    }
    ret = ovsa_get_string_length((char*)json_payload, &buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of json_payload string %d\n", ret);
        goto out;
    }
    /* Send signed nonce to Server */
    OVSA_DBG(DBG_I, "OVSA:Send signed nonce to server\n%s\n", json_payload);
    ret = ovsa_license_service_write(ssl_session, (char*)json_payload, buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: ovsa_license_service_write() returned %d\n", ret);
        goto out;
    }

out:
    ovsa_safe_free(&nonce_signbuf_str);
    ovsa_safe_free(&payload);
    ovsa_safe_free((char**)&json_payload);
    ovsa_safe_free(&cust_lic_msg_blob_buf);

    ovsa_safe_free((char**)&cust_lic_json_payload);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_do_sign_EKpub_EKcert(const int asym_keyslot,
                                               ovsa_sw_ek_ak_bind_info_t* sw_ek_ak_bind_info) {
    ovsa_status_t ret = OVSA_OK;
    size_t file_size = 0, buf_len = 0;
    char* ekpub_buf = NULL;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /*
     * Check if EK Certificate exists. If so, read and send it to server
     */
    if (ovsa_check_if_file_exists(TPM2_SW_EK_CERT) == true) {
        OVSA_DBG(DBG_D, "OVSA:TPM2_SW_EK certificate file exists \n");
        /* Read EK cert */
        ret = ovsa_read_file_content(TPM2_SW_EK_CERT, (char**)sw_ek_ak_bind_info->sw_ek_cert,
                                     &file_size);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Reading TPM2_SW_EK Certificate failed with error code %d\n",
                     ret);
            goto out;
        }
        ret = ovsa_safe_malloc(sizeof(char) * MAX_SIGNATURE_SIZE,
                               &sw_ek_ak_bind_info->sw_ek_cert_sig);
        if (ret < OVSA_OK) {
            ret = OVSA_MEMORY_ALLOC_FAIL;
            OVSA_DBG(DBG_E, "Error: Create ek_ak_bind_info memory init failed\n");
            goto out;
        }
        /* Sign Ekcert */
        ret = ovsa_crypto_sign_mem(asym_keyslot, sw_ek_ak_bind_info->sw_ek_cert, file_size - 1,
                                   sw_ek_ak_bind_info->sw_ek_cert_sig);
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: EKCert Signing failed with code %d\n", ret);
            goto out;
        }
        OVSA_DBG(DBG_I, "OVSA:EKcertificate signed...!\n");
    } else {
        OVSA_DBG(DBG_D, "OVSA:SW_EK_certificate doesn't exists, read ek_pub key...\n");

        /* Read EK public */
        ret = ovsa_read_file_content(TPM2_EK_PUB_KEY, &ekpub_buf, &file_size);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Reading tpm_ek.pub failed with error code %d\n", ret);
            goto out;
        }
        /* convert bin to pem */
        ret = ovsa_crypto_convert_bin_to_base64(ekpub_buf, file_size - 1,
                                                &sw_ek_ak_bind_info->sw_ek_pub_key);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Crypto convert_bin_to_pem failed with code %d\n", ret);
            goto out;
        }
        ret = ovsa_get_string_length(sw_ek_ak_bind_info->sw_ek_pub_key, &buf_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Could not get length of ekpub_buf_pem string %d\n", ret);
            goto out;
        }
        ret =
            ovsa_safe_malloc(sizeof(char) * MAX_SIGNATURE_SIZE, &sw_ek_ak_bind_info->sw_ek_pub_sig);
        if (ret < OVSA_OK) {
            ret = OVSA_MEMORY_ALLOC_FAIL;
            OVSA_DBG(DBG_E, "Error: Create ek_ak_bind_info memory init failed\n");
            goto out;
        }
        /* Sign Ekpub key */
        ret = ovsa_crypto_sign_mem(asym_keyslot, sw_ek_ak_bind_info->sw_ek_pub_key, buf_len,
                                   sw_ek_ak_bind_info->sw_ek_pub_sig);
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: EKpub Signing failed with code %d\n", ret);
            goto out;
        }
        OVSA_DBG(DBG_I, "OVSA:EKpublic key signed...!\n");
    }
out:
    ovsa_safe_free(&ekpub_buf);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_do_read_AK_pubkey_AKname(ovsa_sw_ek_ak_bind_info_t* sw_ek_ak_bind_info) {
    ovsa_status_t ret = OVSA_OK;
    size_t file_size  = 0;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    /* Read AKpub pem */
    ret =
        ovsa_read_file_content(TPM2_AK_PUB_PEM_KEY, &sw_ek_ak_bind_info->sw_ak_pub_key, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Reading TPM2_AK_PUB_PEM_KEY file failed with error code %d\n", ret);
        goto out;
    }
    /* Read AKname */
    file_size = 0;
    ret = ovsa_read_file_content(TPM2_AK_NAME_HEX, &sw_ek_ak_bind_info->sw_ak_name, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Reading TPM2_AK_NAME_HEX file failed with error code %d\n", ret);
        goto out;
    }
out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static ovsa_status_t ovsa_send_EK_AK_bind_info(const int asym_keyslot, void** _ssl_session) {
    ovsa_status_t ret        = OVSA_OK;
    void* ssl_session        = NULL;
    char* EK_AK_binding_info = NULL;
    size_t length            = 0;
    char* json_buf           = NULL;
    char* json_payload       = NULL;
    size_t payload_len       = 0;
    size_t buf_len           = 0;
    ovsa_sw_ek_ak_bind_info_t sw_ek_ak_bind_info;

    ssl_session = *_ssl_session;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    memset_s(&sw_ek_ak_bind_info, sizeof(ovsa_sw_ek_ak_bind_info_t), 0);

    /* Read and sign EKpub/EKcert */
    ret = ovsa_do_sign_EKpub_EKcert(asym_keyslot, &sw_ek_ak_bind_info);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:Sign EK_pub using platform priv key failed with code %d\n", ret);
        goto out;
    }
    /* Read AKpub and AKname */
    ret = ovsa_do_read_AK_pubkey_AKname(&sw_ek_ak_bind_info);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:Sign EK_pub using platform private key failed with code %d\n", ret);
        goto out;
    }
    /* Get customer certificate from key slot */
    ret = ovsa_crypto_get_certificate(asym_keyslot, &sw_ek_ak_bind_info.platform_cert);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Get customer certificate failed with code %d\n", ret);
        goto out;
    }
    ret =
        ovsa_json_create_EK_AK_binding_info_blob(sw_ek_ak_bind_info, &EK_AK_binding_info, &length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:Create create quote update info blob failed with error code %d\n",
                 ret);
        goto out;
    }
    /* create json message blob */
    ret = ovsa_json_create_message_blob(OVSA_SEND_EK_AK_BIND_INFO, EK_AK_binding_info, &json_buf,
                                        &length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:Create EK_AK_BIND_INFO message failed with error code %d\n", ret);
        goto out;
    }
    /* Append payload length to json blob */
    payload_len = length + PAYLOAD_LENGTH + 1;
    ret         = ovsa_safe_malloc(sizeof(char) * payload_len, (char**)&json_payload);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "Error: Create json blob memory init failed\n");
        goto out;
    }
    ret = ovsa_append_json_payload_len_to_blob(json_buf, (char**)&json_payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:json blob creation failed with %d\n", ret);
        goto out;
    }
    ret = ovsa_get_string_length((char*)json_payload, &buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of json_payload string %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA:Send EK_AK_BIND_INFO to server\n%s", json_payload);
    /* Send EK_AK_BIND_INFO to Server */
    ret = ovsa_license_service_write(ssl_session, (char*)json_payload, buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: ovsa_license_service_write() returned %d\n", ret);
        goto out;
    }
out:
    ovsa_safe_free(&sw_ek_ak_bind_info.sw_ak_pub_key);
    ovsa_safe_free(&sw_ek_ak_bind_info.sw_ak_name);
    ovsa_safe_free(&sw_ek_ak_bind_info.sw_ek_pub_key);
    ovsa_safe_free(&sw_ek_ak_bind_info.sw_ek_pub_sig);
    ovsa_safe_free(&sw_ek_ak_bind_info.sw_ek_cert);
    ovsa_safe_free(&sw_ek_ak_bind_info.sw_ek_cert_sig);
    ovsa_safe_free(&sw_ek_ak_bind_info.platform_cert);
    ovsa_safe_free(&json_buf);
    ovsa_safe_free(&json_payload);
    ovsa_safe_free(&EK_AK_binding_info);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

static void ovsa_remove_quote_files(void) {
    remove(TPM2_SWQUOTE_PCR);
    remove(TPM2_SWQUOTE_MSG);
    remove(TPM2_SWQUOTE_SIG);
    remove(SERVER_NONCE);
    remove(TPM2_CREDOUT_FILE);
    remove(TPM2_ACTCRED_OUT);

    OVSA_DBG(DBG_D, "OVSA:Removed the Quote files from /tmp directory\n");
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
    customer_lic_sig.customer_lic.license_url_list = NULL;
    ovsa_license_serv_url_list_t* license_url_list = NULL;
    char license_serv_url[MAX_URL_SIZE + 1];
    bool connected_to_license_server = false;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    /* Input Parameter Validation check */
    if ((asym_keyslot >= MIN_KEY_SLOT) && (customer_license != NULL)) {
        memset_s(license_serv_url, sizeof(license_serv_url), 0);

        /* Load customer license file */
        FILE* fcust_lic = fopen(customer_license, "r");
        if (fcust_lic == NULL) {
            ret = OVSA_FILEOPEN_FAIL;
            OVSA_DBG(DBG_E, "Error: Opening customer license file failed with code %d\n", ret);
            goto out;
        }
        cust_lic_file_size = ovsa_crypto_get_file_size(fcust_lic);
        ret                = ovsa_safe_malloc(cust_lic_file_size * sizeof(char), &cust_lic_sig_buf);
        if (ret < OVSA_OK) {
            ret = OVSA_MEMORY_ALLOC_FAIL;
            OVSA_DBG(DBG_E, "Error: Init memory failed with code %d\n", ret);
            fclose(fcust_lic);
            goto out;
        }
        if (!fread(cust_lic_sig_buf, 1, cust_lic_file_size, fcust_lic)) {
            ret = OVSA_FILEIO_FAIL;
            OVSA_DBG(DBG_E, "Error: Read customer license file failed with code %d\n", ret);
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
            OVSA_DBG(DBG_E, "Error: Extract customer license json blob failed with code %d\n", ret);
            goto out;
        }
        /* Extract license server URL from customer license */
        license_url_list = customer_lic_sig.customer_lic.license_url_list;

        /* Connect to license server url */
        OVSA_DBG(DBG_I, "OVSA:Attempting to connect license server url ........\n\n");
        if (license_url_list == NULL) {
            OVSA_DBG(DBG_E, "Error: license_url_list empty \n");
            goto out;
        } else {
            int url_count = 0;
            while (license_url_list != NULL) {
                int len = strnlen_s(license_url_list->license_serv_url, MAX_URL_SIZE);
                if (len <= MAX_URL_SIZE) {
                    memcpy_s(license_serv_url, len, license_url_list->license_serv_url, len);
                    license_serv_url[len] = '\0';
                    OVSA_DBG(DBG_I, "OVSA:License_serv_url_%d: '%s' %s\n", url_count++,
                             license_serv_url, license_url_list->license_serv_url);
                    ret = ovsa_license_service_start(license_serv_url, NULL, &ssl_session);
                    if (ret < OVSA_OK) {
                        OVSA_DBG(DBG_E,
                                 "Error:ovsa_license_service_start() failed to connect to license "
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
                    OVSA_DBG(DBG_E,
                             "Error: Incorrect length of URL failed to connect to license server "
                             "'%s'\n\n",
                             license_serv_url);
                }
                license_url_list = license_url_list->next;
            }
        }

        OVSA_DBG(DBG_I, "OVSA:Connect to license server url status %s\n\n",
                 connected_to_license_server ? "true" : "false");
        if (!(connected_to_license_server == true)) {
            OVSA_DBG(DBG_E, "Error: Connect to license server url failed with %d\n", ret);
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
                OVSA_DBG(DBG_E, "Error: Read payload length from server failed with code %d\n",
                         ret);
                goto out;
            }

            payload_size = atoi((char*)payload_len_str);
            if (payload_size < 0 || payload_size > RSIZE_MAX_STR) {
                ret = OVSA_MEMORY_ALLOC_FAIL;
                OVSA_DBG(DBG_E, "Error: Read payload length from server is wrong\n");
                goto out;
            }

            /* Read payload from server */
            ret = ovsa_safe_malloc(sizeof(char) * payload_size + 1, (char**)&read_buf);
            if (ret < OVSA_OK) {
                ret = OVSA_MEMORY_ALLOC_FAIL;
                OVSA_DBG(DBG_E, "Error: Memory allocation of read buf failed with code %d\n", ret);
                goto out;
            }

            ret = ovsa_license_service_read(ssl_session, read_buf, payload_size);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "Error: Read payload from server failed with code %d\n", ret);
                goto out;
            }
            OVSA_DBG(DBG_I, "OVSA: Received nonce payload from server \n'%s'\n", read_buf);

            /* Read command from Payload */
            ret = ovsa_json_extract_element((char*)read_buf, "command", (void*)&command);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "Error: Read command from json failed %d\n", ret);
                goto out;
            }
            cmd = ovsa_get_command_type((char*)command);

            switch (cmd) {
                case OVSA_SEND_NONCE:
                    ret = ovsa_do_sign_send_nounce(asym_keyslot, (char*)read_buf, cust_lic_sig_buf,
                                                   &ssl_session);
                    if (ret < OVSA_OK) {
                        OVSA_DBG(DBG_E, "Error: Read nonce from server failed with code %d\n", ret);
                        goto out;
                    }
                    break;
                case OVSA_SEND_EK_AK_BIND:
                    ret = ovsa_send_EK_AK_bind_info(asym_keyslot, &ssl_session);
                    if (ret < OVSA_OK) {
                        OVSA_DBG(DBG_E, "Error:ovsa process EK_AK binding failed with code %d\n",
                                 ret);
                        goto out;
                    }
                    break;
                case OVSA_SEND_QUOTE_NONCE:
                    ret = ovsa_do_get_quote_nounce(asym_keyslot, (char*)read_buf, cust_lic_sig_buf,
                                                   &ssl_session);
                    if (ret < OVSA_OK) {
                        OVSA_DBG(DBG_E, "Error: Read nonce from server failed with code %d\n", ret);
                        goto out;
                    }
                    ovsa_remove_quote_files();
                    break;
                case OVSA_SEND_LICENSE_CHECK_RESP:
                    ret = ovsa_do_get_license_check(asym_keyslot, (char*)read_buf);
                    if (ret < OVSA_OK) {
                        OVSA_DBG(
                            DBG_E,
                            "Error: Read license check status from server failed with code %d\n",
                            ret);
                        goto out;
                    }
                    license_check_complete = true;
                    break;
                default:
                    ret = OVSA_INVALID_CMD_TYPE;
                    OVSA_DBG(DBG_E, "Error: Received Invalid command %d from Server\n", cmd);
                    goto out;
                    break;
            }
            ovsa_safe_free((char**)&command);
            ovsa_safe_free((char**)&read_buf);

        } while (license_check_complete == false);
        *status = license_check_complete;
    } else {
        OVSA_DBG(DBG_E, "Error: Invalid Input parameter \n");
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

ovsa_status_t ovsa_license_check_module(const char* keystore, const char* protected_model,
                                        const char* customer_license, char** decrypt_model,
                                        char** decrypt_weight, int* xml_len, int* bin_len) {
    ovsa_status_t ret = OVSA_OK;
    int asym_keyslot  = -1;
    char* certificate = NULL;
    int peer_keyslot  = -1;
    ovsa_protected_model_sig_t prot_model_sig;

    ovsa_customer_license_sig_t cust_lic_sig;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);
    memset_s(&prot_model_sig, sizeof(ovsa_protected_model_sig_t), 0);
    memset_s(&cust_lic_sig, sizeof(ovsa_customer_license_sig_t), 0);

    /* Input Parameter Validation check */
    if ((protected_model != NULL) && (customer_license != NULL) && (keystore != NULL)) {
        OVSA_DBG(DBG_I, "OVSA: Load Asymmetric Key\n");
        /* Get Asym Key Slot from Key store */
        ret = ovsa_crypto_load_asymmetric_key(keystore, &asym_keyslot);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Get keyslot failed with code %d\n", ret);
            goto out;
        }

        /* Get customer certificate from key slot */
        ret = ovsa_crypto_get_certificate(asym_keyslot, &certificate);
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Get customer certificate failed with code %d\n", ret);
            goto out;
        }

        OVSA_DBG(DBG_I, "OVSA: Verify customer certificate\n");
        /*Verify customer certificate*/
        ret = ovsa_crypto_verify_certificate(asym_keyslot, /* PEER CERT */ false, certificate,
                                             /* lifetime_validity_check */ true);

        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Verify customer certificate failed with code %d\n", ret);
            goto out;
        }
        /* Validate Customer license artefact */
        peer_keyslot =
            ovsa_validate_customer_license(customer_license, asym_keyslot, &cust_lic_sig);
        if ((peer_keyslot < MIN_KEY_SLOT) || (peer_keyslot >= MAX_KEY_SLOT)) {
            ret = peer_keyslot;
            OVSA_DBG(DBG_E, "Error:Customer license artifact validation failed with code %d\n",
                     ret);
            goto out;
        }
        /* Validate protect model artifact*/
        ret = ovsa_validate_protected_model(peer_keyslot, protected_model, &prot_model_sig);
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "Error:Protected model artifact validation failed with code %d\n", ret);
            goto out;
        }
    } else {
        OVSA_DBG(DBG_E, "Error: Invalid artifacts \n");
        ret = OVSA_INVALID_PARAMETER;
    }
    /* Perform License Check Sequence */
    bool status = false;
    ret         = ovsa_perform_tls_license_check(asym_keyslot, customer_license, &status);
    if ((!status) || ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: TLS Licence check failed with code %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_I, "OVSA: Platform and License Validation completed successfully\n");
    OVSA_DBG(DBG_I, "OVSA: Invoking model loader\n");
    /* Invoke Model Loader */
    ret = ovsa_start_model_loader(asym_keyslot, peer_keyslot, &cust_lic_sig, &prot_model_sig,
                                  decrypt_model, decrypt_weight, xml_len, bin_len);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Model Loader Init failed with code %d\n", ret);
    }

out:
    /* clear asymmetric key pairs from the key slot */
    ovsa_crypto_clear_asymmetric_key_slot(asym_keyslot);
    /* clear peer keys from the key slots */
    ovsa_crypto_clear_asymmetric_key_slot(peer_keyslot);
    ovsa_safe_free(&certificate);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}
