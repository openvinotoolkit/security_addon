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

#include <curl/curl.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>
#include <string.h>

#include "asymmetric.h"

#define ROOT_CA_CERTIFICATES "/etc/ssl/certs/ca-certificates.crt"
/* CA Issuers - URI: */
#define CA_ISSUERS_URI_LEN  17
#define openssl_fdset(a, b) FD_SET(a, b)
/* Maximum leeway in validity period: 10 minutes */
#define MAX_VALIDITY_PERIOD (10 * 60)
/* Specify the timeout for OCSP request in seconds */
#define OCSP_REQ_TIMEOUT 10

static int ovsa_crypto_cert_check(X509_STORE* ctx, const char* cert);

static X509_STORE* ovsa_crypto_setup_chain(const char* ca_file);

static void ovsa_crypto_nodes_print(const char* name, STACK_OF(X509_POLICY_NODE) * nodes);

static void ovsa_crypto_policies_print(X509_STORE_CTX* ctx);

static int ovsa_crypto_verify_cb(int ok, X509_STORE_CTX* ctx);

static ovsa_status_t ovsa_crypto_form_chain_do_ocsp_check(const char* cert, const char* chain_file);

static size_t ovsa_crypto_write_callback(void* data, size_t size, size_t num_items,
                                         FILE* issuer_fp);

static ovsa_status_t ovsa_crypto_get_issuer_cert(const char* issuer_file_name,
                                                 const char* ca_issuers_uri);

static ovsa_status_t ovsa_crypto_extract_ca_cert(X509* xcert, char** ca_cert);

static void ovsa_crypto_print_name(BIO* out, const char* title, const X509_NAME* name,
                                   unsigned long flags);

static ovsa_status_t ovsa_crypto_print_x509v3_exts(BIO* bio, const X509* xcert,
                                                   const char* ext_name);

static ovsa_status_t ovsa_crypto_check_issuer_subject_match(const X509* issuer_cert,
                                                            const X509* xcert, bool* ca_cert);

#ifdef ENABLE_OCSP_CHECK
static ovsa_status_t ovsa_crypto_ocsp_revocation_check(char* ocsp_uri, const X509* xcert,
                                                       const char* issuer_cert);

static ovsa_status_t ovsa_crypto_extract_ocsp_uri(X509* xcert, char** ocsp_uri);

static ovsa_status_t ovsa_crypto_add_ocsp_cert(OCSP_REQUEST** req, const X509* xcert,
                                               const EVP_MD* cert_id_md, const X509* issuer,
                                               STACK_OF(OCSP_CERTID) * ids);

static OCSP_RESPONSE* ovsa_crypto_process_responder(OCSP_REQUEST* req, const char* host,
                                                    const char* path, const char* port, int use_ssl,
                                                    int req_timeout);

static ovsa_status_t ovsa_crypto_print_ocsp_summary(BIO* out, OCSP_BASICRESP* basic_response,
                                                    OCSP_REQUEST* req,
                                                    STACK_OF(OPENSSL_STRING) * names,
                                                    STACK_OF(OCSP_CERTID) * ids, long nsec,
                                                    long maxage);

static OCSP_RESPONSE* ovsa_crypto_query_responder(BIO* connect_bio, const char* host,
                                                  const char* path, OCSP_REQUEST* req,
                                                  int req_timeout);
#endif /* ENABLE_OCSP_CHECK */

ovsa_status_t ovsa_crypto_extract_pubkey_verify_cert(bool peer_cert, const char* cert,
                                                     bool lifetime_validity_check, int* peer_slot) {
    ovsa_status_t ret = OVSA_OK;
    int asym_key_slot = -1, asym_key_slot_dup = -1;
    ovsa_isv_keystore_t keystore;

    if ((cert == NULL) || (peer_slot == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting public key and verifying certificate failed with "
                   "invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    memset_s(&keystore, sizeof(ovsa_isv_keystore_t), 0);

    ret = ovsa_crypto_extract_pubkey_certificate(cert, keystore.public_key);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting public key and verifying certificate failed in "
                   "extracting the "
                   "public key\n");
        goto end;
    }

    if (pthread_mutex_lock(&g_asymmetric_index_lock) != 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting public key and verifying certificate failed in "
                   "acquiring the "
                   "mutex with error code = %s\n",
                   strerror(errno));
        ret = OVSA_MUTEX_LOCK_FAIL;
        goto end;
    }

    ret = ovsa_crypto_add_asymmetric_keystore_array(&keystore, &asym_key_slot);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting public key and verifying certificate failed in "
                   "adding to asymmetric keystore array\n");
        goto exit;
    }

    /* Make a copy of the peer's public key to next index */
    ret = ovsa_crypto_add_asymmetric_keystore_array(&keystore, &asym_key_slot_dup);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting public key and verifying certificate failed in "
                   "adding the peer's public key copy to asymmetric keystore array\n");
        goto exit;
    }

    if (pthread_mutex_unlock(&g_asymmetric_index_lock) != 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting public key and verifying certificate failed in "
                   "releasing the "
                   "mutex with error code = %s\n",
                   strerror(errno));
        ret = OVSA_MUTEX_UNLOCK_FAIL;
        goto end;
    }

    ret = ovsa_crypto_verify_certificate(asym_key_slot, peer_cert, cert, lifetime_validity_check);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting public key and verifying certificate failed in "
                   "verifying the certificate\n");
        goto end;
    }

    /* Return the peer slot containing public key and certificate */
    *peer_slot = asym_key_slot;
    goto end;

exit:
    if (pthread_mutex_unlock(&g_asymmetric_index_lock) != 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting public key and verifying certificate failed in "
                   "releasing the "
                   "mutex with error code = %s\n",
                   strerror(errno));
        ret = OVSA_MUTEX_UNLOCK_FAIL;
        goto end;
    }

end:
    memset_s(&keystore, sizeof(ovsa_isv_keystore_t), 0);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

static int ovsa_crypto_cert_check(X509_STORE* ctx, const char* cert) {
    ovsa_status_t ret   = OVSA_OK;
    X509* xcert         = NULL;
    X509_STORE_CTX* csc = NULL;
    static int vflags   = 0;
    int verify_cert     = 0;

    if ((ctx == NULL) || (cert == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error certificate check failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    xcert = ovsa_crypto_load_cert(cert, "certificate");
    if (xcert == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error certificate check failed to read certificate\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    csc = X509_STORE_CTX_new();
    if (csc == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error certificate check failed in X.509 store context allocation\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    X509_STORE_set_flags(ctx, vflags);
    if (!X509_STORE_CTX_init(csc, ctx, xcert, NULL)) {
        X509_STORE_CTX_free(csc);
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error certificate check failed in X.509 store context initialization\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    verify_cert = X509_verify_cert(csc);
    if (verify_cert > 0 && X509_STORE_CTX_get_error(csc) == X509_V_OK) {
        BIO_printf(g_bio_err, "LibOVSA: Certificate verified OK\n");
    } else {
        BIO_printf(g_bio_err, "LibOVSA: Certificate verification failed\n");
        ret = OVSA_CRYPTO_X509_ERROR;
    }
    X509_STORE_CTX_free(csc);

end:
    if (verify_cert <= 0) {
        ERR_print_errors(g_bio_err);
    }
    X509_free(xcert);
    return ret;
}

static X509_STORE* ovsa_crypto_setup_chain(const char* ca_file) {
    X509_LOOKUP* lookup = NULL;

    if (ca_file == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error setting up chain failed with invalid parameter\n");
        return NULL;
    }

    X509_STORE* store = X509_STORE_new();
    if (store == NULL) {
        goto end;
    }

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (lookup == NULL) {
        goto end;
    }

    if (!X509_LOOKUP_load_file(lookup, ca_file, X509_FILETYPE_PEM)) {
        BIO_printf(g_bio_err, "LibOVSA: Error setting up chain failed in loading file %s\n",
                   ca_file);
        goto end;
    }

    ERR_clear_error();
    return store;
end:
    X509_STORE_free(store);
    return NULL;
}

static void ovsa_crypto_nodes_print(const char* name, STACK_OF(X509_POLICY_NODE) * nodes) {
    X509_POLICY_NODE* node = NULL;
    int index              = 0;

    if ((name == NULL) || (nodes == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Explicit certificate policies not found\n");
        return;
    }

    BIO_printf(g_bio_err, "%s Policies:", name);
    if (nodes) {
        BIO_puts(g_bio_err, "\n");
        for (index = 0; index < sk_X509_POLICY_NODE_num(nodes); index++) {
            node = sk_X509_POLICY_NODE_value(nodes, index);
            X509_POLICY_NODE_print(g_bio_err, node, 2);
        }
    } else {
        BIO_puts(g_bio_err, " <empty>\n");
    }

    return;
}

static void ovsa_crypto_policies_print(X509_STORE_CTX* ctx) {
    X509_POLICY_TREE* tree = NULL;
    int explicit_policy    = 0;

    if (ctx == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error printing explicit policies failed with invalid parameter\n");
        return;
    }

    tree            = X509_STORE_CTX_get0_policy_tree(ctx);
    explicit_policy = X509_STORE_CTX_get_explicit_policy(ctx);

    BIO_printf(g_bio_err, "LibOVSA: Require explicit Policy: %s\n",
               explicit_policy ? "True" : "False");

    ovsa_crypto_nodes_print("LibOVSA: Authority", X509_policy_tree_get0_policies(tree));
    ovsa_crypto_nodes_print("LibOVSA: User", X509_policy_tree_get0_user_policies(tree));

    return;
}

static int ovsa_crypto_verify_cb(int ok, X509_STORE_CTX* ctx) {
    int cert_error       = 0;
    X509* current_cert   = NULL;
    static int v_verbose = 0;

    if (ctx == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error certificate verification callback failed with invalid parameter\n");
        return 0;
    }

    cert_error   = X509_STORE_CTX_get_error(ctx);
    current_cert = X509_STORE_CTX_get_current_cert(ctx);

    if (!ok) {
        if (current_cert != NULL) {
            X509_NAME_print_ex(g_bio_err, X509_get_subject_name(current_cert), 0, XN_FLAG_ONELINE);
            BIO_printf(g_bio_err, "\n");
        }

        BIO_printf(g_bio_err, "LibOVSA: %s %d at %d depth lookup: %s\n",
                   X509_STORE_CTX_get0_parent_ctx(ctx) ? "[CRL path] error" : "Error", cert_error,
                   X509_STORE_CTX_get_error_depth(ctx), X509_verify_cert_error_string(cert_error));

        /*
         * Pretend that some errors are ok, so they don't stop further
         * processing of the certificate chain. Setting ok = 1 does this.
         * After X509_verify_cert() is done, we verify that there were
         * no actual errors, even if the returned value was positive.
         */
        switch (cert_error) {
            case X509_V_ERR_NO_EXPLICIT_POLICY:
                ovsa_crypto_policies_print(ctx);
                /* Fall through */
            case X509_V_ERR_CERT_HAS_EXPIRED:
                /* Continue even if the leaf is a self signed cert */
            case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
                /* Continue after extension errors too */
            case X509_V_ERR_INVALID_CA:
            case X509_V_ERR_INVALID_NON_CA:
            case X509_V_ERR_PATH_LENGTH_EXCEEDED:
            case X509_V_ERR_INVALID_PURPOSE:
            case X509_V_ERR_CRL_HAS_EXPIRED:
            case X509_V_ERR_CRL_NOT_YET_VALID:
            case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
                ok = 1;
        }

        return ok;
    }

    if (cert_error == X509_V_OK && ok == 2) {
        ovsa_crypto_policies_print(ctx);
    }

    if (!v_verbose) {
        ERR_clear_error();
    }
    return ok;
}

#ifdef ENABLE_OCSP_CHECK
static ovsa_status_t ovsa_crypto_add_ocsp_cert(OCSP_REQUEST** req, const X509* xcert,
                                               const EVP_MD* cert_id_md, const X509* issuer,
                                               STACK_OF(OCSP_CERTID) * ids) {
    ovsa_status_t ret = OVSA_OK;
    OCSP_CERTID* id   = NULL;

    if ((req == NULL) || (xcert == NULL) || (cert_id_md == NULL) || (issuer == NULL) ||
        (ids == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error adding ocsp certificate failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    *req = OCSP_REQUEST_new();
    if (*req == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error adding ocsp certificate failed to allocate ocsp request\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    id = OCSP_cert_to_id(cert_id_md, xcert, issuer);
    if (id == NULL || !sk_OCSP_CERTID_push(ids, id)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error adding ocsp certificate failed to create ocsp cert_id\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    if (!OCSP_request_add0_id(*req, id)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error adding ocsp certificate failed to create ocsp request\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

end:
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

static OCSP_RESPONSE* ovsa_crypto_query_responder(BIO* connect_bio, const char* host,
                                                  const char* path, OCSP_REQUEST* req,
                                                  int req_timeout) {
    OCSP_REQ_CTX* ctx   = NULL;
    OCSP_RESPONSE* resp = NULL;
    int fd = 0, ret = 0, add_host = 1;
    fd_set confds;
    struct timeval tv;

    if ((connect_bio == NULL) || (host == NULL) || (path == NULL) || (req == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error querying responder failed with invalid parameter\n");
        return NULL;
    }

    if (req_timeout != -1) {
        BIO_set_nbio(connect_bio, 1);
    }

    ret = BIO_do_connect(connect_bio);
    if ((ret <= 0) && ((req_timeout == -1) || !BIO_should_retry(connect_bio))) {
        BIO_printf(g_bio_err, "LibOVSA: Error querying responder failed in connecting BIO\n");
        return NULL;
    }

    if (BIO_get_fd(connect_bio, &fd) < 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error querying responder failed in getting connection fd\n");
        goto end;
    }

    if (req_timeout != -1 && ret <= 0) {
        FD_ZERO(&confds);
        openssl_fdset(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec  = req_timeout;
        ret        = select(fd + 1, NULL, (void*)&confds, NULL, &tv);
        if (ret == 0) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error querying responder failed to connect due to timeout\n");
            return NULL;
        }
    }

    ctx = OCSP_sendreq_new(connect_bio, path, NULL, -1);
    if (ctx == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error querying responder failed to send OCSP request\n");
        return NULL;
    }

    if (add_host == 1 && OCSP_REQ_CTX_add1_header(ctx, "Host", host) == 0) {
        BIO_printf(g_bio_err, "LibOVSA: Error querying responder failed to add header\n");
        goto end;
    }

    if (!OCSP_REQ_CTX_set1_req(ctx, req)) {
        BIO_printf(g_bio_err, "LibOVSA: Error querying responder failed to set OCSP request\n");
        goto end;
    }

    for (;;) {
        ret = OCSP_sendreq_nbio(&resp, ctx);
        if (ret != -1) {
            if (ret == 0) {
                BIO_printf(g_bio_err,
                           "LibOVSA: Error querying responder failed to perform I/O on the OCSP "
                           "request\n");
            }
            break;
        }

        if (req_timeout == -1) {
            continue;
        }

        FD_ZERO(&confds);
        openssl_fdset(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec  = req_timeout;

        if (BIO_should_read(connect_bio)) {
            ret = select(fd + 1, (void*)&confds, NULL, NULL, &tv);
        } else if (BIO_should_write(connect_bio)) {
            ret = select(fd + 1, NULL, (void*)&confds, NULL, &tv);
        } else {
            BIO_printf(
                g_bio_err,
                "LibOVSA: Error querying responder failed due to unexpected retry condition\n");
            goto end;
        }
        if (ret == 0) {
            BIO_printf(g_bio_err, "LibOVSA: Error querying responder timed out on request\n");
            break;
        }
        if (ret == -1) {
            BIO_printf(g_bio_err, "LibOVSA: Error querying responder failed in select\n");
            break;
        }
    }

end:
    OCSP_REQ_CTX_free(ctx);
    return resp;
}

static OCSP_RESPONSE* ovsa_crypto_process_responder(OCSP_REQUEST* req, const char* host,
                                                    const char* path, const char* port, int use_ssl,
                                                    int req_timeout) {
    BIO* connect_bio    = NULL;
    BIO* ssl_bio        = NULL;
    SSL_CTX* ctx        = NULL;
    OCSP_RESPONSE* resp = NULL;

    if ((req == NULL) || (host == NULL) || (path == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error process responder failed with invalid parameter\n");
        return NULL;
    }

    connect_bio = BIO_new_connect(host);
    if (connect_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error process responder failed in getting the connect BIO\n");
        goto end;
    }

    if (port != NULL) {
        BIO_set_conn_port(connect_bio, port);
    }

    if (use_ssl == 1) {
        ctx = SSL_CTX_new(TLS_client_method());
        if (ctx == NULL) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error process responder failed in creating SSL context\n");
            goto end;
        }

        SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
        ssl_bio     = BIO_new_ssl(ctx, 1);
        connect_bio = BIO_push(ssl_bio, connect_bio);
    }

    resp = ovsa_crypto_query_responder(connect_bio, host, path, req, req_timeout);
    if (resp == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error OCSP process responder failed in querying\n");
    }

end:
    BIO_free_all(connect_bio);
    SSL_CTX_free(ctx);
    return resp;
}

static ovsa_status_t ovsa_crypto_print_ocsp_summary(BIO* out, OCSP_BASICRESP* basic_response,
                                                    OCSP_REQUEST* req,
                                                    STACK_OF(OPENSSL_STRING) * names,
                                                    STACK_OF(OCSP_CERTID) * ids, long nsec,
                                                    long maxage) {
    ovsa_status_t ret                 = OVSA_OK;
    ASN1_GENERALIZEDTIME* revocation  = NULL;
    ASN1_GENERALIZEDTIME* this_update = NULL;
    ASN1_GENERALIZEDTIME* next_update = NULL;
    OCSP_CERTID* id                   = NULL;
    const char* name                  = NULL;
    int cert_id_count = 0, status = 0, reason = 0;

    if ((out == NULL) || (basic_response == NULL) || (req == NULL) ||
        (!sk_OPENSSL_STRING_num(names)) || (!sk_OCSP_CERTID_num(ids))) {
        BIO_printf(out, "LibOVSA: Error, no OCSP summary found\n");
        return OVSA_INVALID_PARAMETER;
    }

    for (cert_id_count = 0; cert_id_count < sk_OCSP_CERTID_num(ids); cert_id_count++) {
        id   = sk_OCSP_CERTID_value(ids, cert_id_count);
        name = sk_OPENSSL_STRING_value(names, cert_id_count);

        if (!OCSP_resp_find_status(basic_response, id, &status, &reason, &revocation, &this_update,
                                   &next_update)) {
            BIO_printf(out, "LibOVSA: Error, no OCSP status found for %s\n", name);
            return OVSA_CRYPTO_X509_ERROR;
        }

        /*
         * Check validity: if invalid write to output BIO so we know which
         * response this refers to.
         */
        if (!OCSP_check_validity(this_update, next_update, nsec, maxage)) {
            BIO_puts(out, "LibOVSA: Warning, OCSP status times invalid\n");
        }
        BIO_printf(out, "LibOVSA: Status of %s is: %s\n", name, OCSP_cert_status_str(status));

        BIO_puts(out, "\tThis Update: ");
        ASN1_GENERALIZEDTIME_print(out, this_update);
        BIO_puts(out, "\n");

        if (next_update) {
            BIO_puts(out, "\tNext Update: ");
            ASN1_GENERALIZEDTIME_print(out, next_update);
            BIO_puts(out, "\n");
        }

        if (status != V_OCSP_CERTSTATUS_REVOKED) {
            continue;
        }

        if (reason != -1) {
            BIO_printf(out, "\tReason: %s\n", OCSP_crl_reason_str(reason));
        }

        BIO_puts(out, "\tRevocation Time: ");
        ASN1_GENERALIZEDTIME_print(out, revocation);
        BIO_puts(out, "\n");

        if (status != V_OCSP_CERTSTATUS_GOOD) {
            BIO_printf(out, "LibOVSA: Error OCSP response verification failed with status: %s\n",
                       OCSP_cert_status_str(status));
            return OVSA_CRYPTO_OCSP_ERROR;
        }
    }

    return ret;
}
#endif

static ovsa_status_t ovsa_crypto_print_x509v3_exts(BIO* bio, const X509* xcert,
                                                   const char* ext_name) {
    ovsa_status_t ret                    = OVSA_OK;
    const STACK_OF(X509_EXTENSION)* exts = NULL;
    STACK_OF(X509_EXTENSION)* exts_stack = NULL;
    X509_EXTENSION* ext                  = NULL;
    ASN1_OBJECT* obj                     = NULL;
    const char* ext_check                = NULL;
    size_t ext_check_len                 = 0;
    int ext_count = 0, ext_match_count = 0;
    int ext_num = 0, ext_name_size = 1;
    int indicator = 0, ext_found = 0;

    if ((bio == NULL) || (xcert == NULL) || (ext_name == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error printing x509v3 extensions failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    exts = X509_get0_extensions(xcert);
    if ((ext_num = sk_X509_EXTENSION_num(exts)) <= 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error printing x509v3 extensions since certificate doesn't "
                   "have x509v3 extensions\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    for (ext_count = 0; ext_count < ext_num; ext_count++) {
        ext = sk_X509_EXTENSION_value(exts, ext_count);

        /* Check if this ext is what we want */
        obj = X509_EXTENSION_get_object(ext);

        ext_check = OBJ_nid2sn(OBJ_obj2nid(obj));
        if (ext_check == NULL) {
            continue;
        } else {
            ret = ovsa_get_string_length((char*)ext_check, &ext_check_len);
            if ((ret < OVSA_OK) || (ext_check_len == EOK)) {
                BIO_printf(
                    g_bio_err,
                    "LibOVSA: Error printing x509v3 extensions failed in getting the size of the "
                    "extension\n");
                ret = OVSA_INVALID_FILE_PATH;
                goto end;
            }

            if (strcmp_s(ext_check, ext_check_len, "UNDEF", &indicator) != EOK) {
                BIO_printf(g_bio_err,
                           "LibOVSA: Error printing x509v3 extensions failed in comparing the "
                           "UNDEF string for extension\n");
                ret = OVSA_CRYPTO_GENERIC_ERROR;
                goto end;
            }

            if (indicator == 0) {
                continue;
            }
        }

        for (ext_match_count = 0; ext_match_count < ext_name_size; ext_match_count++) {
            ret = ovsa_get_string_length((char*)ext_check, &ext_check_len);
            if ((ret < OVSA_OK) || (ext_check_len == EOK)) {
                BIO_printf(
                    g_bio_err,
                    "LibOVSA: Error printing x509v3 extensions failed in getting the size of the "
                    "extension check\n");
                ret = OVSA_INVALID_FILE_PATH;
                goto end;
            }

            if (strcmp_s(ext_check, ext_check_len, ext_name, &indicator) != EOK) {
                BIO_printf(g_bio_err,
                           "LibOVSA: Error printing x509v3 extensions failed in comparing the "
                           "string for extension check\n");
                ret = OVSA_CRYPTO_GENERIC_ERROR;
                goto end;
            }

            if (indicator == 0) {
                /* Push the extension into a new stack */
                if (exts_stack == NULL && (exts_stack = sk_X509_EXTENSION_new_null()) == NULL) {
                    BIO_printf(g_bio_err,
                               "LibOVSA: Error printing x509v3 extensions failed to allocate x509 "
                               "extension\n");
                    ret = OVSA_CRYPTO_X509_ERROR;
                    goto end;
                }

                if (!sk_X509_EXTENSION_push(exts_stack, ext)) {
                    BIO_printf(g_bio_err,
                               "LibOVSA: Error printing x509v3 extensions failed to push the x509 "
                               "extension\n");
                    ret = OVSA_CRYPTO_X509_ERROR;
                    goto end;
                }
                ext_found = 1;
            }
        }
        if (ext_found == 1) {
            break;
        }
    }

    if (!sk_X509_EXTENSION_num(exts_stack)) {
        BIO_printf(g_bio_err, "LibOVSA: Extensions didnt match with %s\n", ext_name);
        goto end;
    }

    if (!X509V3_extensions_print(bio, NULL, exts_stack, 0, 0)) {
        BIO_printf(g_bio_err, "LibOVSA: Error printing x509v3 extensions failed\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

end:
    sk_X509_EXTENSION_free(exts_stack);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

static void ovsa_crypto_print_name(BIO* out, const char* title, const X509_NAME* name,
                                   unsigned long flags) {
    char* name_buff = NULL;
    char mline      = 0;
    int indent      = 0;

    if ((out == NULL) || (name == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error printing certificate fields failed with invalid parameter\n");
        return;
    }

    if (title) {
        BIO_puts(out, title);
    }

    if ((flags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE) {
        mline  = 1;
        indent = 4;
    }

    if (flags == XN_FLAG_COMPAT) {
        name_buff = X509_NAME_oneline(name, 0, 0);
        if (name_buff != NULL) {
            BIO_puts(out, name_buff);
            BIO_puts(out, "\n");
            ovsa_crypto_openssl_free(&name_buff);
        }
    } else {
        if (mline) {
            BIO_puts(out, "\n");
        }
        X509_NAME_print_ex(out, name, indent, flags);
        BIO_puts(out, "\n");
    }

    return;
}

/* Write the received certificate into issuer_fp */
static size_t ovsa_crypto_write_callback(void* data, size_t size, size_t num_items,
                                         FILE* issuer_fp) {
    if ((data == NULL) || (issuer_fp == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error writing the issuer certificate failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    return fwrite(data, size, num_items, issuer_fp);
}

static ovsa_status_t ovsa_crypto_get_issuer_cert(const char* issuer_file_name,
                                                 const char* ca_issuers_uri) {
    ovsa_status_t ret = OVSA_OK;
    FILE* issuer_fp   = NULL;

    if ((issuer_file_name == NULL) || (ca_issuers_uri == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error getting the issuer certificate failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    issuer_fp = fopen(issuer_file_name, "w");
    if (issuer_fp == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error getting the issuer certificate failed in opening the issuer file\n");
        return OVSA_FILEOPEN_FAIL;
    }

    CURL* curl = curl_easy_init();
    if (curl == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error getting the issuer certificate failed to initialize curl\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    curl_easy_setopt(curl, CURLOPT_URL, ca_issuers_uri);

    /* Complete the transfer operation within 1 second */
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1L);

    /* Fail the request if the HTTP code returned is equal to or larger than 400 */
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);

    /* If the specified URL is redirected, tell curl to follow redirection */
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    /* When data arrives, curl will call ovsa_crypto_write_callback */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ovsa_crypto_write_callback);

    /* Recieved data will be written to issuer_fp */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)issuer_fp);

    /* Perform the request, result will get the return code */
    CURLcode result = curl_easy_perform(curl);
    if (result != CURLE_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error getting the issuer certificate failed with %s, while "
                   "performing the curl request\n",
                   curl_easy_strerror(result));
        ret = OVSA_CRYPTO_GENERIC_ERROR;
    }

    curl_easy_cleanup(curl);

end:
    if (issuer_fp != NULL) {
        fclose(issuer_fp);
    }
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

static ovsa_status_t ovsa_crypto_check_issuer_subject_match(const X509* issuer_cert,
                                                            const X509* xcert, bool* ca_cert) {
    ovsa_status_t ret    = OVSA_OK;
    BIO* issuer_bio      = NULL;
    BIO* subject_bio     = NULL;
    BUF_MEM* issuer_ptr  = NULL;
    BUF_MEM* subject_ptr = NULL;
    char* issuer         = NULL;
    char* subject        = NULL;
    int indicator        = 0;

    if ((issuer_cert == NULL) || (xcert == NULL) || (ca_cert == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error checking whether issuer and subject match failed with invalid "
                   "parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    issuer_bio = BIO_new(BIO_s_mem());
    if (issuer_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error checking whether issuer and subject match failed in getting new "
                   "BIO for issuer\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    subject_bio = BIO_new(BIO_s_mem());
    if (subject_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error checking whether issuer and subject match failed in getting new "
                   "BIO for subject\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    /* Extract the issuer name from the certificate */
    ovsa_crypto_print_name(issuer_bio, NULL, X509_get_issuer_name(issuer_cert), XN_FLAG_ONELINE);

    BIO_get_mem_ptr(issuer_bio, &issuer_ptr);
    if (issuer_ptr == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error checking whether issuer and subject match failed to extract the "
                   "issuer\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    issuer = (char*)ovsa_crypto_app_malloc(issuer_ptr->length + NULL_TERMINATOR, "issuer");
    if (issuer == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error checking whether issuer and subject match failed in allocating "
                   "memory for issuer\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    /* Copy the issuer field from the certificate into local buffer */
    if (memcpy_s(issuer, issuer_ptr->length, issuer_ptr->data, issuer_ptr->length) != EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting ca certificate failed in getting the issuer\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

    /* Extract the subject name from the certificate */
    ovsa_crypto_print_name(subject_bio, NULL, X509_get_subject_name(xcert), XN_FLAG_ONELINE);

    BIO_get_mem_ptr(subject_bio, &subject_ptr);
    if (subject_ptr == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error checking whether issuer and subject match failed to extract the "
                   "subject\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    subject = (char*)ovsa_crypto_app_malloc(subject_ptr->length + NULL_TERMINATOR, "subject");
    if (subject == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error checking whether issuer and subject match failed in allocating "
                   "memory for subject\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    /* Copy the subject field from the certificate into local buffer */
    if (memcpy_s(subject, subject_ptr->length, subject_ptr->data, subject_ptr->length) != EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error checking whether issuer and subject match failed in getting the "
                   "subject\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

    if (strcmp_s(issuer, issuer_ptr->length, subject, &indicator) != EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error checking whether issuer and subject match failed in comparing "
                   "the string for issuer\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    /* Check whether issuer and subject is matching */
    if (indicator == 0) {
        *ca_cert = true;
    } else {
        *ca_cert = false;
    }

end:
    ovsa_crypto_openssl_free(&issuer);
    ovsa_crypto_openssl_free(&subject);
    BIO_free_all(issuer_bio);
    BIO_free_all(subject_bio);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

static ovsa_status_t ovsa_crypto_extract_ca_cert(X509* xcert, char** ca_cert) {
    ovsa_status_t ret     = OVSA_OK;
    X509_STORE* store     = NULL;
    X509_STORE_CTX* csc   = NULL;
    STACK_OF(X509)* chain = NULL;
    BIO* cert_bio         = NULL;
    BUF_MEM* cert_ptr     = NULL;
    bool check_ca_cert    = false;
    static int vflags     = 0;
    int verify_cert = 0, chain_count = 0;
#ifdef ENABLE_OCSP_CHECK
    char* ocsp_uri = NULL;
#endif

    if ((xcert == NULL) || (ca_cert == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting ca certificate failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    if ((store = ovsa_crypto_setup_chain(ROOT_CA_CERTIFICATES)) == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error extracting ca certificate failed in storing the certificate chain\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    X509_STORE_set_verify_cb(store, ovsa_crypto_verify_cb);

    csc = X509_STORE_CTX_new();
    if (csc == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error extracting ca certificate failed in X.509 store context allocation\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    X509_STORE_set_flags(store, vflags);
    if (!X509_STORE_CTX_init(csc, store, xcert, NULL)) {
        X509_STORE_CTX_free(csc);
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting ca certificate failed in X.509 store context "
                   "initialization\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    /* Discover and validate the certificate chain */
    verify_cert = X509_verify_cert(csc);
    if ((verify_cert <= 0) || (X509_STORE_CTX_get_error(csc) != X509_V_OK)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting ca certificate failed in discovering and validating "
                   "certificate chain\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    /* Get the complete validated chain */
    chain = X509_STORE_CTX_get1_chain(csc);
    for (chain_count = 0; chain_count < sk_X509_num(chain); chain_count++) {
        X509* cert = sk_X509_value(chain, chain_count);
        if (cert == NULL) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error extracting ca certificate failed to read the certificate\n");
            ret = OVSA_CRYPTO_X509_ERROR;
            goto end;
        }

        /* Check whether certificate's issuer and subject is matching */
        ret = ovsa_crypto_check_issuer_subject_match(xcert, cert, &check_ca_cert);
        if (ret < OVSA_OK) {
            BIO_printf(
                g_bio_err,
                "LibOVSA: Error extracting ca certificate failed to check whether issuer and "
                "subject is matching\n");
            goto end;
        }

        /* Get the CA certificate */
        if (check_ca_cert == true) {
            cert_bio = BIO_new(BIO_s_mem());
            if (cert_bio == NULL) {
                BIO_printf(g_bio_err,
                           "LibOVSA: Error extracting ca certificate failed in getting new BIO for "
                           "certificate\n");
                ret = OVSA_CRYPTO_BIO_ERROR;
                goto end;
            }

            /* Write the CA certificate to certificate BIO */
            if (!(PEM_write_bio_X509(cert_bio, cert))) {
                BIO_printf(g_bio_err,
                           "LibOVSA: Error extracting ca certificate failed in writing X509 "
                           "certificate\n");
                ret = OVSA_CRYPTO_PEM_ENCODE_ERROR;
                goto end;
            }

            BIO_get_mem_ptr(cert_bio, &cert_ptr);
            if (cert_ptr == NULL) {
                BIO_printf(
                    g_bio_err,
                    "LibOVSA: Error extracting ca certificate failed to extract the certificate\n");
                ret = OVSA_CRYPTO_BIO_ERROR;
                goto end;
            }

            *ca_cert =
                (char*)ovsa_crypto_app_malloc(cert_ptr->length + NULL_TERMINATOR, "certificate");
            if (*ca_cert == NULL) {
                BIO_printf(g_bio_err,
                           "LibOVSA: Error extracting ca certificate failed in allocating memory "
                           "for ca certificate\n");
                ret = OVSA_MEMORY_ALLOC_FAIL;
                goto end;
            }

            /* Copy CA certificate to local buffer */
            if (memcpy_s(*ca_cert, cert_ptr->length, cert_ptr->data, cert_ptr->length) != EOK) {
                BIO_printf(g_bio_err,
                           "LibOVSA: Error extracting ca certificate failed in getting the ca "
                           "certificate\n");
                ret = OVSA_MEMIO_ERROR;
                goto end;
            }

#ifdef ENABLE_OCSP_CHECK
            /* Extract the OCSP URI from the certificate */
            ret = ovsa_crypto_extract_ocsp_uri(xcert, &ocsp_uri);
            if (ret < OVSA_OK) {
                BIO_printf(
                    g_bio_err,
                    "LibOVSA: Error extracting ca certificate failed to extract the ocsp_uri\n");
                ovsa_crypto_openssl_free(&ocsp_uri);
                goto end;
            }

            /* If OCSP URI available, check for OCSP revocation */
            ret = ovsa_crypto_ocsp_revocation_check(ocsp_uri, xcert, *ca_cert);
            if (ret < OVSA_OK) {
                BIO_printf(g_bio_err,
                           "LibOVSA: Error extracting ca certificate failed to perform the OCSP "
                           "revocation check\n");
                goto end;
            }
#endif
            break;
        }
    }
end:
    sk_X509_pop_free(chain, X509_free);
    X509_STORE_CTX_free(csc);
    X509_STORE_free(store);
    BIO_free_all(cert_bio);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

#ifdef ENABLE_OCSP_CHECK
static ovsa_status_t ovsa_crypto_ocsp_revocation_check(char* ocsp_uri_field, const X509* xcert,
                                                       const char* issuer_cert) {
    ovsa_status_t ret                  = OVSA_OK;
    STACK_OF(X509)* issuers            = NULL;
    X509* issuer                       = NULL;
    OCSP_REQUEST* req                  = NULL;
    OCSP_RESPONSE* resp                = NULL;
    STACK_OF(OCSP_CERTID)* ids         = NULL;
    STACK_OF(OPENSSL_STRING)* reqnames = NULL;
    OCSP_BASICRESP* basic_response     = NULL;
    X509_NAME* subject                 = NULL;
    X509_NAME_ENTRY* common_name_entry = NULL;
    STACK_OF(X509)* signer_issuer      = NULL;
    unsigned const char* common_name   = NULL;
    char* host                         = NULL;
    char* port                         = NULL;
    char* path                         = NULL;
    int ocsp_verify = 0, use_ssl = -1;
    int lastpos = -1, req_timeout = OCSP_REQ_TIMEOUT;
    size_t ocsp_uri_field_len = 0;
    long nsec = MAX_VALIDITY_PERIOD, maxage = -1;
    char ocsp_uri[MAX_URL_SIZE];

    if ((ocsp_uri_field == NULL) || (xcert == NULL) || (issuer_cert == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error ocsp revocation check failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    issuer = ovsa_crypto_load_cert(issuer_cert, "certificate");
    if (issuer == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error ocsp revocation check failed to read certificate\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    if ((issuers = sk_X509_new_null()) == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error ocsp revocation check failed to allocate stack for issuers\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }
    sk_X509_push(issuers, issuer);

    reqnames = sk_OPENSSL_STRING_new_null();
    if (reqnames == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error ocsp revocation check failed to allocate string\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    ids = sk_OCSP_CERTID_new_null();
    if (ids == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error ocsp revocation check failed to allocate ocsp cert_id\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    /* Add the certificates along with issuer for checking OCSP revocation */
    ret = ovsa_crypto_add_ocsp_cert(&req, xcert, EVP_sha1(), issuer, ids);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error ocsp revocation check failed to add certificate for ocsp check\n");
        goto end;
    }

    /* Extract the subject from the certificate */
    subject = X509_get_subject_name(xcert);
    if (subject == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error ocsp revocation check failed to get the subject\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    /* Extract the common name from subject */
    for (;;) {
        lastpos = X509_NAME_get_index_by_NID(subject, NID_commonName, lastpos);
        if (lastpos == -1) {
            break;
        }

        common_name_entry = X509_NAME_get_entry(subject, lastpos);
        common_name       = ASN1_STRING_get0_data(X509_NAME_ENTRY_get_data(common_name_entry));
    }

    if (common_name != NULL) {
        if (!sk_OPENSSL_STRING_push(reqnames, (char*)common_name)) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error ocsp revocation check failed to push the common name\n");
            ret = OVSA_CRYPTO_X509_ERROR;
            goto end;
        }
    } else {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error ocsp revocation check failed to get the common name\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    /* Add nonce to the OCSP request */
    if (!OCSP_request_add1_nonce(req, NULL, -1)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error ocsp revocation check failed to add nonce to OCSP request\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    /* Print the OCSP request */
    if ((req != NULL) && !OCSP_REQUEST_print(g_bio_err, req, 0)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error ocsp revocation check failed to print the OCSP request\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    memset_s(ocsp_uri, MAX_URL_SIZE, 0);

    ret = ovsa_get_string_length(ocsp_uri_field, &ocsp_uri_field_len);
    if ((ret < OVSA_OK) || (ocsp_uri_field_len == EOK)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error ocsp revocation check failed in getting the size of the "
                   "ocsp_uri field\n");
        ret = OVSA_INVALID_FILE_PATH;
        goto end;
    }

    /* Copy the OCSP URI */
    if (memcpy_s(ocsp_uri, MAX_URL_SIZE, ocsp_uri_field, ocsp_uri_field_len - 1) != EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error ocsp revocation check failed in getting the ocsp_uri\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

    /* Parse the OCSP URL for doing the OCSP revocation check */
    if (!OCSP_parse_url(ocsp_uri, &host, &port, &path, &use_ssl)) {
        BIO_printf(g_bio_err, "LibOVSA: Error ocsp revocation check failed in parsing URL\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    /* Get the OCSP response */
    resp = ovsa_crypto_process_responder(req, host, ocsp_uri, port, use_ssl, req_timeout);
    if (resp == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error ocsp revocation check failed in getting the ocsp "
                   "response\nPlease try with proxy: Ex: export PROXY=<proxy-name:port_number>\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    /* Check the OCSP response status */
    ocsp_verify = OCSP_response_status(resp);
    if (ocsp_verify != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        BIO_printf(g_bio_err, "LibOVSA: OCSP Responder Error: %s (%d)\n",
                   OCSP_response_status_str(ocsp_verify), ocsp_verify);
    }

    /* Print the OCSP response */
    if (!OCSP_RESPONSE_print(g_bio_err, resp, 0)) {
        BIO_printf(g_bio_err,
                   "\nLibOVSA: Error ocsp revocation check failed to print the OCSP response\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    /* Decode the OCSP response */
    basic_response = OCSP_response_get1_basic(resp);
    if (basic_response == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error ocsp revocation check failed in parsing response\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    /* Verify the nonce in OCSP response */
    if (req != NULL && ((ocsp_verify = OCSP_check_nonce(req, basic_response)) <= 0)) {
        if (ocsp_verify == -1)
            BIO_printf(g_bio_err, "LibOVSA: Warning, no nonce in OCSP response\n");
        else {
            BIO_printf(g_bio_err, "LibOVSA: OCSP nonce Verify error\n");
            ret = OVSA_CRYPTO_X509_ERROR;
            goto end;
        }
    }

    /* Verify the OCSP response */
    ocsp_verify = OCSP_basic_verify(basic_response, NULL, NULL, 0);
    if (ocsp_verify <= 0 && issuers) {
        signer_issuer = (STACK_OF(X509)*)OCSP_resp_get0_certs(basic_response);
        if (signer_issuer == NULL) {
            signer_issuer = issuers;
        }

        ocsp_verify = OCSP_basic_verify(basic_response, signer_issuer, NULL, OCSP_TRUSTOTHER);
        if (ocsp_verify > 0) {
            ERR_clear_error();
        }
    }
    if (ocsp_verify <= 0) {
        BIO_printf(g_bio_err, "LibOVSA: OCSP Response Verify Failure\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    } else {
        BIO_printf(g_bio_err, "LibOVSA: OCSP Response verify OK = %d\n", ocsp_verify);
    }

    /* Print the OCSP summary */
    ret =
        ovsa_crypto_print_ocsp_summary(g_bio_err, basic_response, req, reqnames, ids, nsec, maxage);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error ocsp revocation check failed in getting the ocsp status\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

end:
    ovsa_crypto_openssl_free(&ocsp_uri_field);
    sk_X509_pop_free(issuers, X509_free);
    OCSP_REQUEST_free(req);
    OCSP_RESPONSE_free(resp);
    OCSP_BASICRESP_free(basic_response);
    sk_OPENSSL_STRING_free(reqnames);
    sk_OCSP_CERTID_free(ids);
    ovsa_crypto_openssl_free(&host);
    ovsa_crypto_openssl_free(&port);
    ovsa_crypto_openssl_free(&path);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

static ovsa_status_t ovsa_crypto_extract_ocsp_uri(X509* xcert, char** ocsp_uri) {
    STACK_OF(OPENSSL_STRING)* ocsp_uri_list = NULL;
    ovsa_status_t ret                       = OVSA_OK;
    BIO* ocsp_bio                           = NULL;
    BUF_MEM* ocsp_ptr                       = NULL;
    int ocsp_uri_count                      = 0;

    if ((xcert == NULL) || (ocsp_uri == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error extracting ocsp uri failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    /* Extract the OCSP URI from the certificate */
    ocsp_uri_list = X509_get1_ocsp(xcert);
    if (ocsp_uri_list != NULL) {
        ocsp_bio = BIO_new(BIO_s_mem());
        if (ocsp_bio == NULL) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error extracting ocsp uri failed in getting new BIO for ocsp\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }

        for (ocsp_uri_count = 0; ocsp_uri_count < sk_OPENSSL_STRING_num(ocsp_uri_list);
             ocsp_uri_count++) {
            BIO_printf(ocsp_bio, "%s\n", sk_OPENSSL_STRING_value(ocsp_uri_list, ocsp_uri_count));
        }

        BIO_get_mem_ptr(ocsp_bio, &ocsp_ptr);
        if (ocsp_ptr == NULL) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error extracting ocsp uri failed to extract the ocsp_uri\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }

        *ocsp_uri =
            (char*)ovsa_crypto_app_malloc(ocsp_ptr->length + NULL_TERMINATOR, "certificate");
        if (*ocsp_uri == NULL) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error extracting ocsp uri failed in allocating memory for the "
                       "ocsp\n");
            ret = OVSA_MEMORY_ALLOC_FAIL;
            goto end;
        }

        /* Copy the extracted OCSP URI to local buffer */
        if (memcpy_s(*ocsp_uri, ocsp_ptr->length, ocsp_ptr->data, ocsp_ptr->length) != EOK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error extracting ocsp uri failed in getting the ocsp_uri\n");
            ret = OVSA_MEMIO_ERROR;
            goto end;
        }
    } else {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting ocsp uri since certificate doesn't have OCSP URI\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

end:
    X509_email_free(ocsp_uri_list);
    BIO_free_all(ocsp_bio);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}
#endif

static ovsa_status_t ovsa_crypto_check_cert_trust_store(const X509* xcert,
                                                        bool* check_cert_trust_store) {
    STACK_OF(X509_INFO)* certstack = NULL;
    const char ca_filestr[]        = ROOT_CA_CERTIFICATES;
    BIO* stackbio                  = NULL;
    ovsa_status_t ret              = OVSA_OK;
    int i;

    if (xcert == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error Certificate check in Linux Trust Store failed with invalid "
                   "parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    stackbio = BIO_new(BIO_s_file());
    if (stackbio == NULL) {
        BIO_printf(
            g_bio_err,
            "OVSA: Error Certificate check in Linux Trust Store failed in getting new BIO \n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (BIO_read_filename(stackbio, ca_filestr) <= 0) {
        BIO_printf(g_bio_err, "LibOVSA: Error while loading cert bundle into memory\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    certstack = PEM_X509_INFO_read_bio(stackbio, NULL, NULL, NULL);
    if (certstack == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error in reading X509 certificate stack\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    /* ---------------------------------------------------------- *
     * Cycle through the stack for Certificate            *
     * ---------------------------------------------------------- */
    for (i = 0; i < sk_X509_INFO_num(certstack); i++) {
        X509_INFO* itmp;

        itmp = sk_X509_INFO_value(certstack, i);

        if (X509_cmp(xcert, itmp->x509) == 0) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Certificate is available in Linux Trust Store and trusted...\n");
            *check_cert_trust_store = true;
            break;
        }
    }
    /* ---------------------------------------------------------- *
     * Free up the resources                                      *
     * ---------------------------------------------------------- */
end:
    sk_X509_INFO_pop_free(certstack, X509_INFO_free);
    BIO_free_all(stackbio);

    return ret;
}

static ovsa_status_t ovsa_crypto_form_chain_do_ocsp_check(const char* cert,
                                                          const char* chain_file) {
    ovsa_status_t ret           = OVSA_OK;
    BIO* ca_issuers_bio         = NULL;
    BIO* issuer_cert_bio        = NULL;
    BIO* issuer_cert_mem        = NULL;
    BUF_MEM* ca_issuers_ptr     = NULL;
    BUF_MEM* issuer_cert_ptr    = NULL;
    X509* xcert                 = NULL;
    X509* d2i_xcert             = NULL;
    char* cert_dup              = NULL;
    char* d2i_cert              = NULL;
    char* ca_issuers            = NULL;
    char* ca_cert               = NULL;
    char* issuer_cert           = NULL;
    char* issuer_dup            = NULL;
    const char* exts            = "authorityInfoAccess";
    bool check_ca_cert          = false;
    bool check_cert_trust_store = false;
    FILE* chain_fp              = NULL;
    FILE* issuer_fp             = NULL;
    static int cert_flag        = 0;
    int safe_exit               = 0;
    size_t ca_cert_len = 0, cert_len = 0;
    size_t issuer_cert_len = 0, cert_file_size = 0;
    char* issuer_file_name      = "/opt/ovsa/tmp_dir/issuer_cert.der";
    size_t ca_issuers_field_len = 0;
    int ca_issuers_uri_len = 0, count = 0;
    char ca_issuers_uri[MAX_URL_SIZE];
    char ca_issuers_field[MAX_URL_SIZE];
#ifdef ENABLE_OCSP_CHECK
    char* ocsp_uri = NULL;
#endif

    if ((cert == NULL) || (chain_file == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error forming chain failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    ca_issuers_bio = BIO_new(BIO_s_mem());
    if (ca_issuers_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error forming chain failed in getting new BIO for ca_issuers\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    issuer_cert_bio = BIO_new(BIO_s_mem());
    if (issuer_cert_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error forming chain failed in getting new BIO for certificate\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    ret = ovsa_get_string_length(cert, &cert_len);
    if ((ret < OVSA_OK) || (cert_len == EOK)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error forming chain failed in getting the size of the certificate\n");
        ret = OVSA_INVALID_FILE_PATH;
        goto end;
    }

    /* Write the client certificate to chain file */
    chain_fp = fopen(chain_file, "w");
    if (chain_fp == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error forming chain failed in opening the chain file\n");
        ret = OVSA_FILEOPEN_FAIL;
        goto end;
    }

    if (!fwrite(cert, cert_len, 1, chain_fp)) {
        BIO_printf(g_bio_err, "LibOVSA: Error forming chain failed in writing to chain file\n");
        fclose(chain_fp);
        ret = OVSA_FILEIO_FAIL;
        goto end;
    }
    fclose(chain_fp);

    while (cert != NULL) {
        if (issuer_cert_len != 0) {
            cert_len = issuer_cert_len;
        }

        cert_dup = (char*)ovsa_crypto_app_malloc(cert_len + NULL_TERMINATOR, "certificate");
        if (cert_dup == NULL) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error forming chain failed in allocating memory for the "
                       "certificate\n");
            ret = OVSA_MEMORY_ALLOC_FAIL;
            goto end;
        }

        /* Copy the certficate to local buffer */
        if (cert_flag == 0) {
            if (memcpy_s(cert_dup, cert_len, cert, cert_len) != EOK) {
                BIO_printf(g_bio_err,
                           "LibOVSA: Error forming chain failed in getting the certificate\n");
                ret = OVSA_MEMIO_ERROR;
                goto end;
            }
            cert_flag = 1;
        } else {
            if (memcpy_s(cert_dup, cert_len, d2i_cert, issuer_cert_len) != EOK) {
                BIO_printf(g_bio_err,
                           "LibOVSA: Error forming chain failed in getting the certificate\n");
                ret = OVSA_MEMIO_ERROR;
                goto end;
            }
            (void)BIO_reset(issuer_cert_bio);
        }

        xcert = ovsa_crypto_load_cert(cert_dup, "certificate");
        if (xcert == NULL) {
            BIO_printf(g_bio_err, "LibOVSA: Error forming chain failed to read certificate\n");
            ret = OVSA_CRYPTO_X509_ERROR;
            goto end;
        }
        if (check_cert_trust_store != true) {
            BIO_printf(g_bio_err, "OVSA: Checking certificate in Linux Trust Store...\n");
            ret = ovsa_crypto_check_cert_trust_store(xcert, &check_cert_trust_store);
            if (ret < OVSA_OK) {
                BIO_printf(g_bio_err,
                           "OVSA: ovsa crypto check cert trust store failed with error code:%d\n",
                           ret);
                goto end;
            }
        }
        /* Check whether certificate's issuer and subject is matching */
        ret = ovsa_crypto_check_issuer_subject_match(xcert, xcert, &check_ca_cert);
        if (ret < OVSA_OK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error forming chain failed to check whether issuer and "
                       "subject is matching\n");
            goto end;
        }

        if (check_ca_cert == true) {
            if (check_cert_trust_store == false) {
                BIO_printf(
                    g_bio_err,
                    "OVSA: RootCA cert can't be trusted as its not available in Trust Store...\n");
                ret = OVSA_CRYPTO_BIO_ERROR;
                goto end;
            }
            break;
        }

        /* Extract the AIA field from certificate */
        ret = ovsa_crypto_print_x509v3_exts(ca_issuers_bio, xcert, exts);
        if (ret < OVSA_OK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error forming chain failed in getting the x509 extensions\n");
            ret = OVSA_CRYPTO_GENERIC_ERROR;
            goto end;
        }

        BIO_get_mem_ptr(ca_issuers_bio, &ca_issuers_ptr);
        if (ca_issuers_ptr == NULL) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error forming chain failed to extract the CA issuers uri\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }

        /* Find the CAIssuers URI occurance */
        if (ca_issuers_ptr->data != NULL) {
            ca_issuers = strstr(ca_issuers_ptr->data, "CA Issuers - URI:");
        }

        /*
         * Check whether the CAIssuers URI is present. If present, get
         * the Intermediate certificate else get the CA certificate
         */
        if (ca_issuers == NULL) {
            /* Extract the CA certificate from host */
            ret = ovsa_crypto_extract_ca_cert(xcert, &ca_cert);
            if (ret < OVSA_OK) {
                BIO_printf(g_bio_err,
                           "LibOVSA: Error forming chain failed to extract the CA certificate\n");
                goto end;
            }

            ret = ovsa_get_string_length(ca_cert, &ca_cert_len);
            if ((ret < OVSA_OK) || (ca_cert_len == EOK)) {
                BIO_printf(g_bio_err,
                           "LibOVSA: Error forming chain failed in getting the size of the "
                           "certificate\n");
                ret = OVSA_INVALID_FILE_PATH;
                goto end;
            }

            /* Write the CA certificate to chain file */
            chain_fp = fopen(chain_file, "a");
            if (chain_fp == NULL) {
                BIO_printf(g_bio_err,
                           "LibOVSA: Error forming chain failed in opening the chain file\n");
                ret = OVSA_FILEOPEN_FAIL;
                goto end;
            }

            if (!fwrite(ca_cert, ca_cert_len, 1, chain_fp)) {
                BIO_printf(g_bio_err,
                           "LibOVSA: Error forming chain failed in writing to chain file\n");
                fclose(chain_fp);
                ret = OVSA_FILEIO_FAIL;
                goto end;
            }
            fclose(chain_fp);
            break;
        }

        memset_s(ca_issuers_field, MAX_URL_SIZE, 0);

        /* Get the CAIssuers field alone */
        while (count < MAX_URL_SIZE) {
            if (ca_issuers[count] == '\n') {
                count = 0;
                break;
            }
            ca_issuers_field[count] = ca_issuers[count];
            count++;
        }

        ret = ovsa_get_string_length(ca_issuers_field, &ca_issuers_field_len);
        if ((ret < OVSA_OK) || (ca_issuers_field_len == EOK)) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error forming chain failed in getting the size of the CA issuers "
                       "field\n");
            ret = OVSA_CRYPTO_GENERIC_ERROR;
            goto end;
        }

        memset_s(ca_issuers_uri, MAX_URL_SIZE, 0);
        ca_issuers_uri_len = ca_issuers_field_len - CA_ISSUERS_URI_LEN;

        if (ca_issuers_uri_len < MAX_URL_SIZE) {
            if (strncpy_s(ca_issuers_uri, MAX_URL_SIZE, ca_issuers_field + CA_ISSUERS_URI_LEN,
                          ca_issuers_uri_len)) {
                BIO_printf(g_bio_err,
                           "LibOVSA: Error forming chain failed in getting the CA issuers uri\n");
                ret = OVSA_CRYPTO_GENERIC_ERROR;
                goto end;
            }
        } else {
            BIO_printf(
                g_bio_err,
                "LibOVSA: Error forming chain failed since the CA issuers uri length is more "
                "than MAX_URL_SIZE\n");
            ret = OVSA_CRYPTO_GENERIC_ERROR;
            goto end;
        }

        /* Get the issuer certificate from CAIssuers URI */
        ret = ovsa_crypto_get_issuer_cert(issuer_file_name, ca_issuers_uri);
        if (ret < OVSA_OK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error forming chain failed in getting the issuer certificate\n");
            ret = OVSA_CRYPTO_X509_ERROR;
            goto end;
        }

        /* Read the downloaded issuer certificate */
        issuer_fp = fopen(issuer_file_name, "rb");
        if (issuer_fp == NULL) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error forming chain failed in opening the issuer file\n");
            ret = OVSA_FILEOPEN_FAIL;
            goto end;
        }

        safe_exit = 0;
        ret       = ovsa_crypto_get_file_size(issuer_fp, &cert_file_size);
        if (ret < OVSA_OK || cert_file_size == 0) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error forming chain failed in reading the issuer certificate file "
                       "size\n");
            ret = OVSA_FILEIO_FAIL;
            goto exit;
        }

        issuer_cert = (char*)ovsa_crypto_app_malloc(cert_file_size, "certificate");
        if (issuer_cert == NULL) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error forming chain failed in allocating memory for issuer "
                       "certificate\n");
            ret = OVSA_MEMORY_ALLOC_FAIL;
            goto exit;
        }

        if (!fread(issuer_cert, 1, cert_file_size, issuer_fp)) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error forming chain failed in reading the issuer file\n");
            ret = OVSA_FILEIO_FAIL;
            goto exit;
        }
        issuer_cert[cert_file_size - 1] = '\0';

        issuer_cert_mem = BIO_new_mem_buf(issuer_cert, (cert_file_size - 1));
        if (issuer_cert_mem == NULL) {
            BIO_printf(
                g_bio_err,
                "LibOVSA: Error forming chain failed in writing to issuer certificate BIO\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto exit;
        }

        /* Convert the issuer certificate from DER to PEM */
        d2i_xcert = d2i_X509_bio(issuer_cert_mem, NULL);
        if (d2i_xcert == NULL) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error forming chain failed in decoding the issuer certificate\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto exit;
        }

        if (!PEM_write_bio_X509(issuer_cert_bio, d2i_xcert)) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error forming chain failed in writing X509 issuer certificate\n");
            ret = OVSA_CRYPTO_PEM_ENCODE_ERROR;
            goto exit;
        }

        BIO_get_mem_ptr(issuer_cert_bio, &issuer_cert_ptr);
        if (issuer_cert_ptr == NULL) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error forming chain failed to extract the issuer certificate\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto exit;
        }

        issuer_dup =
            (char*)ovsa_crypto_app_malloc(issuer_cert_ptr->length + NULL_TERMINATOR, "certificate");
        if (issuer_dup == NULL) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error forming chain failed in allocating memory for "
                       "issuer\n");
            ret = OVSA_MEMORY_ALLOC_FAIL;
            goto exit;
        }

        /* Copy the issuer certificate to local buffer */
        if (memcpy_s(issuer_dup, issuer_cert_ptr->length, issuer_cert_ptr->data,
                     issuer_cert_ptr->length) != EOK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error forming chain failed in getting the issuer "
                       "certificate\n");
            ret = OVSA_MEMIO_ERROR;
            goto exit;
        }

#ifdef ENABLE_OCSP_CHECK
        /* Extract the OCSP URI from the certificate */
        ret = ovsa_crypto_extract_ocsp_uri(xcert, &ocsp_uri);
        if (ret < OVSA_OK) {
            BIO_printf(g_bio_err, "LibOVSA: Error forming chain failed to extract the ocsp_uri\n");
            ovsa_crypto_openssl_free(&ocsp_uri);
            goto exit;
        }

        /* If OCSP URI available, check for OCSP revocation */
        ret = ovsa_crypto_ocsp_revocation_check(ocsp_uri, xcert, issuer_dup);
        if (ret < OVSA_OK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error forming chain failed to perform the OCSP revocation "
                       "check\n");
            goto exit;
        }
#endif
        /* Write the Intermediate certificate to chain file */
        chain_fp = fopen(chain_file, "a");
        if (chain_fp == NULL) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error forming chain failed in opening the chain file\n");
            ret = OVSA_FILEOPEN_FAIL;
            goto exit;
        }

        if (!fwrite(issuer_cert_ptr->data, issuer_cert_ptr->length, 1, chain_fp)) {
            BIO_printf(g_bio_err, "LibOVSA: Error forming chain failed in writing to chain file\n");
            fclose(chain_fp);
            ret = OVSA_FILEIO_FAIL;
            goto exit;
        }
        fclose(chain_fp);

        d2i_cert        = issuer_cert_ptr->data;
        issuer_cert_len = issuer_cert_ptr->length;
        safe_exit       = 1;

    exit:
        if (issuer_fp != NULL) {
            fclose(issuer_fp);
        }
        ovsa_crypto_openssl_free(&issuer_cert);
        ovsa_crypto_openssl_free(&issuer_dup);
        ovsa_crypto_openssl_free(&cert_dup);
        (void)BIO_reset(ca_issuers_bio);
        BIO_free_all(issuer_cert_mem);
        X509_free(xcert);
        xcert = NULL;
        X509_free(d2i_xcert);
        d2i_xcert = NULL;
        if (safe_exit != 1) {
            goto end;
        }
    }

end:
    cert_flag = 0;
    ovsa_crypto_openssl_free(&cert_dup);
    ovsa_crypto_openssl_free(&ca_cert);
    BIO_free_all(ca_issuers_bio);
    BIO_free_all(issuer_cert_bio);
    X509_free(xcert);
    xcert = NULL;
    if (remove(issuer_file_name) != 0) {
        BIO_printf(g_bio_err, "LibOVSA: Warning could not delete %s file\n", issuer_file_name);
    }
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

#ifdef ENABLE_SELF_SIGNED_CERT
static ovsa_status_t ovsa_crypto_check_cert_is_self_signed(const X509* xcert,
                                                           bool* check_self_signed_cert) {
    ovsa_status_t ret = OVSA_OK;

    ret = ovsa_crypto_check_issuer_subject_match(xcert, xcert, check_self_signed_cert);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error checking self signed cert failed to check whether issuer and "
                   "subject is matching\n");
        ERR_print_errors(g_bio_err);
    }

    return ret;
}
#endif

ovsa_status_t ovsa_crypto_verify_certificate(int asym_key_slot, bool peer_cert, const char* cert,
                                             bool lifetime_validity_check) {
    X509_STORE* store           = NULL;
    char* chain_file            = "/opt/ovsa/tmp_dir/chain.pem";
    EVP_PKEY* cert_pkey         = NULL;
    bool check_self_signed_cert = false;
    ovsa_status_t ret           = OVSA_OK;
    EVP_PKEY* pkey              = NULL;
    X509* xcert                 = NULL;
    int cert_verify             = 0;
    char public_key[MAX_KEY_SIZE];

    if ((asym_key_slot < MIN_KEY_SLOT) || (asym_key_slot >= MAX_KEY_SLOT) || (cert == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying certificate failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    if (lifetime_validity_check == true) {
        ret = ovsa_crypto_check_cert_lifetime_validity(cert);
        if (ret < OVSA_OK) {
            BIO_printf(
                g_bio_err,
                "LibOVSA: Error verifying certificate failed in checking certificate validity\n");
            goto end;
        }
    }

    ret = ovsa_crypto_compare_certkey_and_keystore(asym_key_slot, cert, &pkey, &xcert);
    if (ret < OVSA_OK) {
        X509_free(xcert);
        EVP_PKEY_free(pkey);
        ret = ovsa_crypto_compare_certkey_and_keystore(asym_key_slot + 1, cert, &pkey, &xcert);
        if (ret < OVSA_OK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Certificate key is not matching with secondary keystore values\n");
            goto end;
        }
    }

    if (xcert == NULL || pkey == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error certificate or public key extracted is NULL\n");
        goto end;
    }
    /* Decode public key from certificate */
    cert_pkey = X509_get0_pubkey(xcert);
    if (cert_pkey == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying certificate failed to decode the public key from "
                   "certificate\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    cert_verify = EVP_PKEY_cmp(pkey, cert_pkey);
    if (cert_verify != 1) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying certificate failed since certificate's public key "
                   "doesn't match with the keystore public key\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

#ifdef ENABLE_SELF_SIGNED_CERT
    ret = ovsa_crypto_check_cert_is_self_signed(xcert, &check_self_signed_cert);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying certificate failed to check whether certificate is"
                   "self signed created\n");
        goto end;
    }

    if (check_self_signed_cert == true) {
        cert_verify = X509_verify(xcert, pkey);
        if (cert_verify < 0) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error verifying certificate failed to verify the signature\n");
            ret = OVSA_CRYPTO_X509_ERROR;
            goto end;
        }
        if (cert_verify == 0) {
            BIO_printf(g_bio_err, "LibOVSA: Certificate signature verification failed\n");
            ret = OVSA_CRYPTO_X509_ERROR;
            goto end;
        } else {
            BIO_printf(g_bio_err, "LibOVSA: Certificate signature verified OK\n");
        }
    } else
#endif
    {

        ret = ovsa_crypto_form_chain_do_ocsp_check(cert, chain_file);
        if (ret < OVSA_OK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error verifying certificate failed since chain file could not be "
                       "created\n");
            goto end;
        }

        if ((store = ovsa_crypto_setup_chain(chain_file)) == NULL) {
            BIO_printf(
                g_bio_err,
                "LibOVSA: Error verifying certificate failed in storing the certificate chain\n");
            ret = OVSA_CRYPTO_X509_ERROR;
            goto end;
        }

        X509_STORE_set_verify_cb(store, ovsa_crypto_verify_cb);

        if (ovsa_crypto_cert_check(store, cert) != 0) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error verifying certificate failed in certificate verification\n");
            ret = OVSA_CRYPTO_X509_ERROR;
            goto end;
        }
    }

    if (peer_cert == true) {
        if (pthread_mutex_lock(&g_asymmetric_index_lock) != 0) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error verifying certificate failed in acquiring the "
                       "mutex with error code = %s\n",
                       strerror(errno));
            ret = OVSA_MUTEX_LOCK_FAIL;
            goto end;
        }

        ret = ovsa_crypto_add_cert_keystore_array(asym_key_slot, cert);
        if (ret < OVSA_OK) {
            BIO_printf(
                g_bio_err,
                "LibOVSA: Error verifying certificate failed in adding certificate to keystore"
                "array\n");
            goto exit;
        }

        /* Make a copy of the peer certificate to next index */
        ret = ovsa_crypto_add_cert_keystore_array(asym_key_slot + 1, cert);
        if (ret < OVSA_OK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error verifying certificate failed in adding the peer certificate "
                       "copy to keystore array\n");
            goto exit;
        }

    exit:
        if (pthread_mutex_unlock(&g_asymmetric_index_lock) != 0) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error verifying certificate failed in releasing the "
                       "mutex with error code = %s\n",
                       strerror(errno));
            ret = OVSA_MUTEX_UNLOCK_FAIL;
            goto end;
        }
    }

end:
    OPENSSL_cleanse(public_key, MAX_KEY_SIZE);
    X509_free(xcert);
    EVP_PKEY_free(pkey);
    if (store != NULL) {
        X509_STORE_free(store);
    }
    if (check_self_signed_cert == false) {
        if (remove(chain_file) != 0) {
            BIO_printf(g_bio_err, "LibOVSA: Warning could not delete %s file\n", chain_file);
        }
    }
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_compare_certkey_and_keystore(int asym_key_slot, const char* cert,
                                                       EVP_PKEY** pkey, X509** xcert) {
    EVP_PKEY* cert_pkey   = NULL;
    ovsa_status_t ret     = OVSA_OK;
    size_t public_key_len = 0;
    int cert_verify       = 0;
    char public_key[MAX_KEY_SIZE];

    if ((asym_key_slot < MIN_KEY_SLOT) || (asym_key_slot >= MAX_KEY_SLOT) || (cert == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying certificate failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    public_key_len = strnlen_s(g_key_store[asym_key_slot].public_key, MAX_KEY_SIZE);
    if (public_key_len == EOK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error verifying certificate failed in getting the size of the public key\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    memset_s(public_key, MAX_KEY_SIZE, 0);

    if (memcpy_s(public_key, public_key_len, g_key_store[asym_key_slot].public_key,
                 public_key_len) != EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying certificate failed in getting the public key\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

    *xcert = NULL;
    *xcert = ovsa_crypto_load_cert(cert, "certificate");
    if (*xcert == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error verifying certificate failed to read certificate\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    *pkey = NULL;
    *pkey = ovsa_crypto_load_key(public_key, "public Key");
    if (*pkey == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error verifying certificate failed in loading the public key into memory\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }

    /* Decode public key from certificate */
    cert_pkey = X509_get0_pubkey(*xcert);
    if (cert_pkey == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying certificate failed to decode the public key from "
                   "certificate\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    cert_verify = EVP_PKEY_cmp(*pkey, cert_pkey);
    if (cert_verify != 1) {
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

end:
    OPENSSL_cleanse(public_key, MAX_KEY_SIZE);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}
