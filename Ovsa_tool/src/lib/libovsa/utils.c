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

#include "utils.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <string.h>

BIO* g_bio_err = NULL;

pthread_mutex_t g_asymmetric_index_lock;
pthread_mutex_t g_symmetric_index_lock;

ovsa_isv_keystore_t g_key_store[MAX_KEY_SLOT];
char g_sym_key[MAX_KEY_SLOT][MAX_EKEY_SIZE];

static unsigned int ovsa_crypto_initialised = 0;

static int ovsa_crypto_do_sign_init(EVP_MD_CTX* ctx, EVP_PKEY* pkey, const EVP_MD* md);

static int ovsa_crypto_do_X509_REQ_sign(X509_REQ* req, EVP_PKEY* pkey, const EVP_MD* md);

static int ovsa_crypto_build_subject(X509_REQ* req, const char* subj, unsigned long chtype);

static X509_NAME* ovsa_crypto_parse_name(const char* sub, long chtype);

#ifdef ENABLE_SELF_SIGNED_CERT
static ovsa_status_t ovsa_crypto_set_cert_validity(const X509* xcert, int days);

static ovsa_status_t ovsa_crypto_sign_cert(X509* xcert, EVP_PKEY* pkey, int days,
                                           const EVP_MD* digest);

static ovsa_status_t ovsa_crypto_generate_rand_serial_num(BIGNUM* bnum, ASN1_INTEGER* serial_num);
#endif

EVP_PKEY* ovsa_crypto_load_key(const char* p_key, const char* key_descrip) {
    BIO* key       = NULL;
    EVP_PKEY* pkey = NULL;
    int indicator  = 0;

    if ((p_key == NULL) || (key_descrip == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error loading the key failed with invalid parameter\n");
        return NULL;
    }

    key = BIO_new(BIO_s_mem());
    if (key == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error loading the key failed in getting the new BIO\n");
        goto end;
    }

    if (BIO_puts(key, p_key) <= 0) {
        BIO_printf(g_bio_err, "LibOVSA: Error loading the key failed in writing to key BIO\n");
        goto end;
    }

    if (strcmp_s(key_descrip, MAX_NAME_SIZE, "private key", &indicator) != EOK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error loading the key failed in comparing the string for private key\n");
        goto end;
    }

    if (indicator == 0) {
        pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);
    } else {
        pkey = PEM_read_bio_PUBKEY(key, NULL, NULL, NULL);
    }

end:
    BIO_free_all(key);
    if (pkey == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error loading the key failed in loading the %s into memory\n",
                   key_descrip);
        ERR_print_errors(g_bio_err);
    }
    return pkey;
}

X509* ovsa_crypto_load_cert(const char* cert, const char* cert_descrip) {
    BIO* cert_mem = NULL;
    X509* xcert   = NULL;

    if ((cert == NULL) || (cert_descrip == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error loading the certificate failed with invalid parameter\n");
        return NULL;
    }

    cert_mem = BIO_new(BIO_s_mem());
    if (cert_mem == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error loading the certificate failed in getting the new BIO\n");
        goto end;
    }

    if (BIO_puts(cert_mem, cert) <= 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error loading the certificate failed in writing to certificate BIO\n");
        goto end;
    }

    xcert = PEM_read_bio_X509_AUX(cert_mem, NULL, NULL, NULL);

end:
    if (xcert == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error in loading the %s into memory\n", cert_descrip);
        ERR_print_errors(g_bio_err);
    }

    BIO_free_all(cert_mem);
    return xcert;
}

ovsa_status_t ovsa_crypto_init(void) {
    ovsa_status_t ret = OVSA_OK;

    if (ovsa_crypto_initialised) {
        return ret;
    }

    memset_s(&g_key_store, sizeof(ovsa_isv_keystore_t) * MAX_KEY_SLOT, 0);
    memset_s(g_sym_key, sizeof(g_sym_key), 0);

    g_bio_err = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (g_bio_err == NULL) {
        OVSA_DBG(DBG_E, "LibOVSA: Error crypto initialization failed in creating a file BIO\n");
        return OVSA_CRYPTO_BIO_ERROR;
    }

    if (pthread_mutex_init(&g_asymmetric_index_lock, NULL) != 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error crypto initialization failed in intializing mutex for "
                   "asymmetric index with error code = %s\n",
                   strerror(errno));
        return OVSA_MUTEX_INIT_FAIL;
    }

    if (pthread_mutex_init(&g_symmetric_index_lock, NULL) != 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error crypto initialization failed in intializing mutex for "
                   "symmetric index with error code = %s\n",
                   strerror(errno));
        return OVSA_MUTEX_INIT_FAIL;
    }

    ovsa_crypto_initialised = 1;

    return ret;
}

ovsa_status_t ovsa_crypto_deinit(void) {
    ovsa_status_t ret = OVSA_OK;
    size_t cert_len   = 0;
    int index         = 0;

    for (index = 0; index < MAX_KEY_SLOT; index++) {
        if (g_key_store[index].isv_certificate != NULL) {
            ret = ovsa_get_string_length(g_key_store[index].isv_certificate, &cert_len);
            if (ret < OVSA_OK) {
                BIO_printf(g_bio_err,
                           "LibOVSA: Error crypto deinitialization failed in getting the size of "
                           "the certificate\n");
                goto end;
            }
            if (cert_len != 0) {
                ovsa_crypto_openssl_free(&g_key_store[index].isv_certificate);
            }
        }
    }

    /* Clear all the keys in asymmetric and symmetric key slots */
    memset_s(&g_key_store, sizeof(ovsa_isv_keystore_t) * MAX_KEY_SLOT, 0);
    memset_s(g_sym_key, sizeof(g_sym_key), 0);

    if (pthread_mutex_destroy(&g_asymmetric_index_lock) != 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error crypto deinitialization failed in destroying the mutex for "
                   "asymmetric index with error code = %s\n",
                   strerror(errno));
        ret = OVSA_MUTEX_DESTROY_FAIL;
        goto end;
    }

    if (pthread_mutex_destroy(&g_symmetric_index_lock) != 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error crypto deinitialization failed in destroying the mutex for "
                   "symmetric index with error code = %s\n",
                   strerror(errno));
        ret = OVSA_MUTEX_DESTROY_FAIL;
        goto end;
    }

    ovsa_crypto_initialised = 0;

end:
    BIO_free_all(g_bio_err);
    return ret;
}

void ovsa_crypto_clear_asymmetric_key_slot(int asym_key_slot) {
    size_t cert_len = 0;
    int index       = 0;

    if (pthread_mutex_lock(&g_asymmetric_index_lock) != 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error clearing asymmetric key slot failed in acquiring the mutex with "
                   "error code = %s\n",
                   strerror(errno));
        return;
    }

    if ((asym_key_slot >= MIN_KEY_SLOT) && (asym_key_slot < (MAX_KEY_SLOT - 1))) {
        /* Clear primary & secondary certificate from the keystore array */
        for (index = asym_key_slot; index <= asym_key_slot + 1; index++) {
            if (g_key_store[index].isv_certificate != NULL) {
                ovsa_get_string_length(g_key_store[index].isv_certificate, &cert_len);
                if (cert_len != 0) {
                    ovsa_crypto_openssl_free(&g_key_store[index].isv_certificate);
                }
            }
        }

        /* Clear primary key from the asymmetric key slot */
        memset_s(&g_key_store[asym_key_slot], sizeof(ovsa_isv_keystore_t), 0);

        /* Clear secondary key from the asymmetric key slot */
        memset_s(&g_key_store[asym_key_slot + 1], sizeof(ovsa_isv_keystore_t), 0);
    }

    if (pthread_mutex_unlock(&g_asymmetric_index_lock) != 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error clearing asymmetric key slot failed in releasing the mutex with "
                   "error code = %s\n",
                   strerror(errno));
        return;
    }

    return;
}

void ovsa_crypto_clear_symmetric_key_slot(int sym_key_slot) {
    if (pthread_mutex_lock(&g_symmetric_index_lock) != 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error clearing symmetric key slot failed in acquiring the mutex with "
                   "error code = %s\n",
                   strerror(errno));
        return;
    }

    if ((sym_key_slot >= MIN_KEY_SLOT) && (sym_key_slot < MAX_KEY_SLOT)) {
        /* Clears the specified symmetric key from the symmetric key slot */
        memset_s(&g_sym_key[sym_key_slot], sizeof(g_sym_key[sym_key_slot]), 0);
    }

    if (pthread_mutex_unlock(&g_symmetric_index_lock) != 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error clearing symmetric key slot failed in releasing the mutex with "
                   "error code = %s\n",
                   strerror(errno));
        return;
    }

    return;
}

ovsa_status_t ovsa_crypto_do_sign_verify_hash(unsigned char* buf, BIO* inp, const EVP_PKEY* key,
                                              const unsigned char* sigin, int siglen,
                                              const char* file, BIO* out) {
    int read = 0, verify = 0, count = 0;
    unsigned char* sigbuf = NULL;
    ovsa_status_t ret     = OVSA_OK;
    size_t len            = BUFSIZE;

    if ((buf == NULL) || (inp == NULL) || (file == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing/verifying/hashing failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    while (BIO_pending(inp) || !BIO_eof(inp)) {
        read = BIO_read(inp, (char*)buf, BUFSIZE);
        if (read < 0) {
            BIO_printf(
                g_bio_err,
                "LibOVSA: Error signing/verifying/hashing failed in reading the input file\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }
        if (read == 0) {
            break;
        }
    }

    if (sigin != NULL) {
        EVP_MD_CTX* ctx;
        BIO_get_md_ctx(inp, &ctx);

        verify = EVP_DigestVerifyFinal(ctx, sigin, (unsigned int)siglen);
        if (verify > 0) {
            BIO_printf(g_bio_err, "LibOVSA: Verified OK\n");
        } else if (verify == 0) {
            BIO_printf(g_bio_err, "LibOVSA: Verification Failure\n");
            ret = OVSA_CRYPTO_EVP_ERROR;
            goto end;
        } else {
            BIO_printf(g_bio_err, "LibOVSA: Error Verifying Data\n");
            ret = OVSA_CRYPTO_EVP_ERROR;
            goto end;
        }
        return ret;
    }

    if (key != NULL) {
        EVP_MD_CTX* ctx;
        int pkey_len = 0;
        BIO_get_md_ctx(inp, &ctx);
        pkey_len = EVP_PKEY_size(key);
        if (pkey_len > BUFSIZE) {
            len    = pkey_len;
            sigbuf = (unsigned char*)ovsa_crypto_app_malloc(len, "Signature buffer");
            buf    = sigbuf;
        }

        if (!EVP_DigestSignFinal(ctx, buf, &len)) {
            BIO_printf(g_bio_err, "LibOVSA: Error signing failed to sign the data\n");
            ret = OVSA_CRYPTO_EVP_ERROR;
            goto end;
        }

        if (!BIO_write(out, buf, len)) {
            BIO_printf(g_bio_err, "LibOVSA: Error signing failed in writing the signature\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }
    } else {
        len = BIO_gets(inp, (char*)buf, BUFSIZE);
        if ((int)len <= 0) {
            BIO_printf(g_bio_err, "LibOVSA: Error hashing failed with invalid input file length\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }
        for (count = 0; count < (int)len; count++) {
            BIO_printf(out, "%02x", buf[count]);
        }
    }

    if (!BIO_flush(out)) {
        BIO_printf(g_bio_err, "LibOVSA: Error signing failed in flushing the signature\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (key != NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Signing Done\n");
    }

end:
    if (sigbuf != NULL) {
        OPENSSL_clear_free(sigbuf, len);
    }
    return ret;
}

static int ovsa_crypto_do_sign_init(EVP_MD_CTX* ctx, EVP_PKEY* pkey, const EVP_MD* md) {
    EVP_PKEY_CTX* pkctx = NULL;
    int def_nid         = 0;
    int status          = 0;

    if ((ctx == NULL) || (pkey == NULL) || (md == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error signing init failed with invalid parameter\n");
        return status;
    }

    /*
     * EVP_PKEY_get_default_digest_nid() returns 2 if the digest is mandatory
     * for this algorithm.
     */
    if ((EVP_PKEY_get_default_digest_nid(pkey, &def_nid) == 2) && (def_nid == NID_undef)) {
        /* The signing algorithm requires there to be no digest */
        md = NULL;
    }

    status = EVP_DigestSignInit(ctx, &pkctx, md, NULL, pkey);
    if (status <= 0) {
        BIO_printf(g_bio_err, "LibOVSA: Error signing init failed to set up the signing context\n");
        return status;
    }

    return status;
}

static int ovsa_crypto_do_X509_REQ_sign(X509_REQ* req, EVP_PKEY* pkey, const EVP_MD* md) {
    int result = 0;

    if ((req == NULL) || (pkey == NULL) || (md == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing certificate request failed with invalid parameter\n");
        return result;
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    result            = ovsa_crypto_do_sign_init(mdctx, pkey, md);
    if (result > 0) {
        result = X509_REQ_sign_ctx(req, mdctx);
    }

    EVP_MD_CTX_free(mdctx);
    return result > 0 ? 1 : 0;
}

/*
 * Name is expected to be in the format /type0=value0/type1=value1/type2=...
 * where characters may be escaped by \
 */
static X509_NAME* ovsa_crypto_parse_name(const char* sub, long chtype) {
    ovsa_status_t ret     = OVSA_OK;
    unsigned char* valstr = NULL;
    X509_NAME* name       = NULL;
    char* typestr         = NULL;
    char* temp            = NULL;
    char* buff            = NULL;
    size_t str_len        = 0;
    int nid               = 0;

    if (sub == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error parsing the name failed with invalid parameter\n");
        return NULL;
    }

    if (*sub++ != '/') {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error parsing the name failed since name is expected to be in the format "
            "/type0=value0/type1=value1/type2=... where characters may "
            "be escaped by \\. This name is not in that format: '%s'\n",
            --sub);
        return NULL;
    }

    name = X509_NAME_new();
    if (name == NULL) {
        return NULL;
    }

    buff = OPENSSL_strdup(sub);
    if (buff == NULL) {
        goto end;
    }

    while (*sub) {
        temp    = buff;
        typestr = temp;

        /* Collect the type */
        while (*sub && *sub != '=') {
            *temp++ = *sub++;
        }

        if (*sub == '\0') {
            BIO_printf(
                g_bio_err,
                "LibOVSA: Error parsing the name failed since end of string reached before finding "
                "the equals.\n");
            goto end;
        }

        *temp++ = '\0';
        ++sub;

        /* Collect the value. */
        valstr = (unsigned char*)temp;
        for (; *sub && *sub != '/'; *temp++ = *sub++) {
            if (*sub == '\\' && *++sub == '\0') {
                BIO_printf(g_bio_err,
                           "LibOVSA: Error parsing the name failed as escape character at end of "
                           "string\n");
                goto end;
            }
        }

        *temp++ = '\0';

        /* If not at EOS (must be + or /), move forward. */
        if (*sub) {
            ++sub;
        }

        /* Parse */
        nid = OBJ_txt2nid(typestr);
        if (nid == NID_undef) {
            BIO_printf(g_bio_err, "Parsing the name skipped unknown attribute \"%s\"\n", typestr);
            continue;
        }

        if (*valstr == '\0') {
            BIO_printf(
                g_bio_err,
                "Parsing the name didn't provide any value for subject attribute %s, skipped\n",
                typestr);
            continue;
        }

        ret = ovsa_get_string_length((char*)valstr, &str_len);
        if ((ret < OVSA_OK) || (str_len == EOK)) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error parsing the name failed in getting the size of the subject "
                       "elements\n");
            goto end;
        }

        if (!X509_NAME_add_entry_by_NID(name, nid, chtype, valstr, str_len, -1, 0))
            goto end;
    }

    ovsa_crypto_openssl_free(&buff);
    return name;

end:
    X509_NAME_free(name);
    ovsa_crypto_openssl_free(&buff);
    return NULL;
}

/*
 * Subject is expected to be in the format /type0=value0/type1=value1/type2=...
 * where characters may be escaped by \
 */
static int ovsa_crypto_build_subject(X509_REQ* req, const char* subject, unsigned long chtype) {
    X509_NAME* name = NULL;

    if ((req == NULL) || (subject == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error parsing the subject failed with invalid parameter\n");
        return 0;
    }

    if ((name = ovsa_crypto_parse_name(subject, chtype)) == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error in parsing the subject\n");
        return 0;
    }

    if (!X509_REQ_set_subject_name(req, name)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error parsing the subject failed to set the subject for certificate "
                   "request\n");
        X509_NAME_free(name);
        return 0;
    }

    X509_NAME_free(name);
    return 1;
}

void* ovsa_crypto_app_malloc(size_t size, const char* what) {
    void* buff = OPENSSL_malloc(size);
    if (buff == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error in allocating memory for %s\n", what);
        return NULL;
    }

    memset_s(buff, size, 0);

    return buff;
}

void ovsa_crypto_openssl_free(char** buff) {
    size_t buff_len = 0;

    if (*buff != NULL) {
        ovsa_get_string_length(*buff, &buff_len);
        OPENSSL_clear_free(*buff, buff_len);
        *buff = NULL;
    }

    return;
}

#ifdef ENABLE_SELF_SIGNED_CERT
static ovsa_status_t ovsa_crypto_set_cert_validity(const X509* xcert, int days) {
    ovsa_status_t ret = OVSA_OK;

    if (xcert == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error setting certificate validity failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    if (X509_gmtime_adj(X509_getm_notBefore(xcert), 0) == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error setting certificate validity failed in setting the start date\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    if (X509_time_adj_ex(X509_getm_notAfter(xcert), days, 0, NULL) == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error setting certificate validity failed in setting the end date\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

end:
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

static ovsa_status_t ovsa_crypto_sign_cert(X509* xcert, EVP_PKEY* pkey, int days,
                                           const EVP_MD* digest) {
    ovsa_status_t ret = OVSA_OK;

    if ((xcert == NULL) || (pkey == NULL) || (digest == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error signing certificate failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    if (ovsa_crypto_set_cert_validity(xcert, days) < 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing certificate failed in setting the validity\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    if (!X509_set_pubkey(xcert, pkey)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error signing certificate failed in setting the public key\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    if (!X509_sign(xcert, pkey, digest)) {
        BIO_printf(g_bio_err, "LibOVSA: Error in signing the certificate\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

end:
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

static ovsa_status_t ovsa_crypto_generate_rand_serial_num(BIGNUM* bnum, ASN1_INTEGER* serial_num) {
    ovsa_status_t ret = OVSA_OK;
    BIGNUM* bnum_tmp  = NULL;

    if (serial_num == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error random serial number generation failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    bnum_tmp = (bnum == NULL) ? BN_new() : bnum;
    if (bnum_tmp == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error random serial number generation failed to allocate bignum structure\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    if (!BN_rand(bnum_tmp, SERIAL_RAND_BITS, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error random serial number generation failed to generate "
                   "pseudo-random number\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    if (serial_num && !BN_to_ASN1_INTEGER(bnum_tmp, serial_num)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error random serial number generation failed to convert bignum to "
                   "ASN1 integer\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

end:
    if (bnum_tmp != bnum) {
        BN_free(bnum_tmp);
    }
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}
#endif
ovsa_status_t ovsa_crypto_generate_csr(const char* private_key, const char* subject,
                                       const char* csr_file) {
    ovsa_status_t ret    = OVSA_OK;
    const EVP_MD* digest = EVP_sha512();
    unsigned long chtype = MBSTRING_ASC;
    EVP_PKEY* pkey       = NULL;
    BIO* csr_out_bio     = NULL;
    X509_REQ* req        = NULL;
#ifdef ENABLE_SELF_SIGNED_CERT
    char cert_file_ext[MAX_NAME_SIZE] = ".crt";
    EVP_PKEY* pubkey                  = NULL;
    BIO* cert_out_bio                 = NULL;
    X509* xcert                       = NULL;
    ASN1_INTEGER* serial_num          = NULL;
    size_t csr_file_name_len          = 0;
    int cert_validity_days            = 0;
    int signature_verify = 0, elapsedtime = 0;
    time_t ovsa_current_time, ovsa_cert_valid_time;
    struct tm* ovsa_current_time_tm = {0};
    char cert_file[MAX_NAME_SIZE];
#endif

    if ((private_key == NULL) || (subject == NULL) || (csr_file == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error CSR generation failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    pkey = ovsa_crypto_load_key(private_key, "private key");
    if (pkey == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error CSR generation failed in loading the private key into memory\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }

    /* Create a new request */
    if (!(req = X509_REQ_new())) {
        BIO_printf(g_bio_err, "LibOVSA: Error CSR generation failed in creating X509 object\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    /* Setup version number */
    if (!X509_REQ_set_version(req, 0L)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error CSR generation failed in getting the version field\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    if (!ovsa_crypto_build_subject(req, subject, chtype)) {
        BIO_printf(g_bio_err, "LibOVSA: Error CSR generation failed in setting the subject\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    if (!X509_REQ_set_pubkey(req, pkey)) {
        BIO_printf(g_bio_err, "LibOVSA: Error CSR generation failed to decode the public key\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    /* Sign using SHA512 */
    if (!ovsa_crypto_do_X509_REQ_sign(req, pkey, digest)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error CSR generation failed to sign the certificate request\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    csr_out_bio = BIO_new_file(csr_file, "wx");
    if (csr_out_bio == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error CSR generation failed in creating the CSR file\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (!PEM_write_bio_X509_REQ(csr_out_bio, req)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error CSR generation failed in writing X509 certificate request\n");
        ret = OVSA_CRYPTO_PEM_ENCODE_ERROR;
        goto end;
    }

#ifdef ENABLE_SELF_SIGNED_CERT
    if ((pubkey = X509_REQ_get0_pubkey(req)) == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error extracting pub key from certificate\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    signature_verify = X509_REQ_verify(req, pubkey);
    if (signature_verify < 0) {
        BIO_printf(g_bio_err, "LibOVSA: Error Signature verification failed\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }
    if (signature_verify == 0) {
        BIO_printf(g_bio_err, "LibOVSA: Error Signature verification failed\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    } else {
        BIO_printf(g_bio_err, "LibOVSA: Signature verified OK\n");
    }

    if (!(xcert = X509_new())) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error certificate generation failed in creating X509 object\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    serial_num = ASN1_INTEGER_new();
    if (ovsa_crypto_generate_rand_serial_num(NULL, serial_num)) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error certificate generation failed in generating random serial number\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    if (!X509_set_serialNumber(xcert, serial_num)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error certificate generation failed in setting serial number\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    if (!X509_set_issuer_name(xcert, X509_REQ_get_subject_name(req))) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error certificate generation failed in setting issuer name\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    if (!X509_set_subject_name(xcert, X509_REQ_get_subject_name(req))) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error certificate generation failed in setting subject name\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    memset_s(&ovsa_current_time, sizeof(time_t), 0);
    memset_s(&ovsa_cert_valid_time, sizeof(time_t), 0);

    ret = ovsa_get_current_time(&ovsa_current_time, &ovsa_current_time_tm);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error certificate generation failed in getting current time\n");
        goto end;
    }

    ovsa_current_time_tm->tm_mon += MAX_CERT_VALIDITY_PERIOD;
    ovsa_cert_valid_time = mktime(ovsa_current_time_tm);

    elapsedtime = difftime(ovsa_cert_valid_time, ovsa_current_time);
    if (elapsedtime < 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error checking certificate validity failed since elapsed time is out "
                   "of range\n");
        ret = OVSA_TIME_DURATIONEXCEEDS_ERROR;
        goto end;
    }

    cert_validity_days = elapsedtime / NUM_OF_SECONDS_IN_DAY;

    if (ovsa_crypto_sign_cert(xcert, pkey, cert_validity_days, digest)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error certificate generation failed in signing certificate\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    csr_file_name_len = strnlen_s(csr_file, MAX_NAME_SIZE);
    if (csr_file_name_len == EOK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error certificate generation failed in getting the size of CSR file name\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    memset_s(cert_file, MAX_NAME_SIZE, 0);
    if (strncpy_s(cert_file, MAX_NAME_SIZE, csr_file, csr_file_name_len)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error certificate generation failed in copying the CSR file name\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    if (strncat_s(cert_file, MAX_NAME_SIZE, cert_file_ext, sizeof(cert_file_ext)) != EOK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error certificate generation failed in copying the cert file extension\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    cert_out_bio = BIO_new_file(cert_file, "wx");
    if (cert_out_bio == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error certificate generation failed in creating the certificate file\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (!(PEM_write_bio_X509(cert_out_bio, xcert))) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error certificate generation failed in writing X509 certificate\n");
        ret = OVSA_CRYPTO_PEM_ENCODE_ERROR;
        goto end;
    }
#endif

    BIO_printf(g_bio_err,
               "LibOVSA WARNING: Generated key lifetime is only for 18 Months, please don't "
               "request certificate for more than 18 Months!!!\n");

end:
#ifdef ENABLE_SELF_SIGNED_CERT
    X509_free(xcert);
    BIO_free_all(cert_out_bio);
    ASN1_INTEGER_free(serial_num);
#endif
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    BIO_free_all(csr_out_bio);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_extract_pubkey_certificate(const char* cert, char* public_key) {
    ovsa_status_t ret   = OVSA_OK;
    BUF_MEM* pubkey_ptr = NULL;
    BIO* pubkey_mem     = NULL;
    EVP_PKEY* pkey      = NULL;
    X509* xcert         = NULL;

    if ((cert == NULL) || (public_key == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting public key from certificate failed with invalid "
                   "parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    pubkey_mem = BIO_new(BIO_s_mem());
    if (pubkey_mem == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error extracting public key from certificate failed in getting new BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    xcert = ovsa_crypto_load_cert(cert, "certificate");
    if (xcert == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error extracting public key from certificate failed to read certificate\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    /* Extract public key from certificate */
    pkey = X509_get0_pubkey(xcert);
    if (pkey == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error in extracting the public key from certificate\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    if (!PEM_write_bio_PUBKEY(pubkey_mem, pkey)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting public key from certificate failed in writing the "
                   "public key\n");
        ret = OVSA_CRYPTO_PEM_ENCODE_ERROR;
        goto end;
    }

    BIO_get_mem_ptr(pubkey_mem, &pubkey_ptr);
    if (pubkey_ptr == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting public key from certificate failed to extract the "
                   "public key\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (memcpy_s(public_key, MAX_KEY_SIZE, pubkey_ptr->data, pubkey_ptr->length) != EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting public key from certificate failed in getting the "
                   "public key\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

end:
    X509_free(xcert);
    BIO_free_all(pubkey_mem);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_compute_hash(const char* in_buff, int hash_alg, unsigned char* out_buff,
                                       bool b64_format) {
    unsigned char* compute_hash_buff = NULL;
    ovsa_status_t ret                = OVSA_OK;
    BUF_MEM* compute_hash_ptr        = NULL;
    const EVP_MD* md                 = NULL;
    EVP_MD_CTX* mctx                 = NULL;
    BIO* write_bio                   = NULL;
    BIO* input_bio                   = NULL;
    BIO* read_bio                    = NULL;
    BIO* out_bio                     = NULL;
    BIO* bmd                         = NULL;
    BIO* b64                         = NULL;
    size_t hash_length               = 0;

    if ((in_buff == NULL) || (out_buff == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error computing hash failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    /* Default HASH Algorithm is SHA512, unless requested for SHA256 */
    if (hash_alg == HASH_ALG_SHA256) {
        md          = EVP_sha256();
        hash_length = 32;
    } else if (hash_alg == HASH_ALG_SHA384) {
        md          = EVP_sha384();
        hash_length = 48;
    } else {
        md          = EVP_sha512();
        hash_length = 64;
    }

    read_bio = BIO_new(BIO_s_mem());
    if (read_bio == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error computing hash failed in getting new BIO");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    bmd = BIO_new(BIO_f_md());
    if (bmd == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error computing hash failed in getting the message digest\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (b64_format == true) {
        if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error computing hash failed in getting the b64 encode method\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }
    }

    write_bio = BIO_new(BIO_s_mem());
    if (write_bio == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error computing hash failed in getting new BIO for the output buffer\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    out_bio = write_bio;
    if (b64_format == true)
        out_bio = BIO_push(b64, out_bio);

    input_bio = BIO_push(bmd, read_bio);
    if (BIO_puts(read_bio, in_buff) <= 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error computing hash failed in writing to input buffer BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (!BIO_get_md_ctx(bmd, &mctx)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error computing hash failed in getting the context for digest\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (!EVP_DigestInit_ex(mctx, md, NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error computing hash failed in setting up the digest context\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }

    compute_hash_buff = (unsigned char*)ovsa_crypto_app_malloc(EVP_ENCODE_LENGTH(BUFSIZE),
                                                               "evp compute_hash buffer");
    if (compute_hash_buff == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error computing hash failed in allocating memory for evp compute hash "
                   "buffer\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    ret = ovsa_crypto_do_sign_verify_hash(compute_hash_buff, input_bio, NULL, NULL, 0, in_buff,
                                          out_bio);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err, "LibOVSA: Error computing hash failed in generating the hash\n");
        goto end;
    }

    if (b64_format == true) {
        BIO_get_mem_ptr(out_bio, &compute_hash_ptr);
        if (compute_hash_ptr == NULL) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error computing hash failed to extract the computed hash\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }

        if (memcpy_s(out_buff, HASH_SIZE, compute_hash_ptr->data, compute_hash_ptr->length) !=
            EOK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error computing hash failed in getting the output buffer\n");
            ret = OVSA_MEMIO_ERROR;
            goto end;
        }
    } else {
        if (memcpy_s(out_buff, hash_length, compute_hash_buff, hash_length) != EOK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error computing hash failed in getting the output buffer\n");
            ret = OVSA_MEMIO_ERROR;
            goto end;
        }
    }

    (void)BIO_reset(bmd);
end:
    ovsa_crypto_openssl_free((char**)&compute_hash_buff);
    if (b64_format == true)
        BIO_free(b64);
    BIO_free_all(write_bio);
    BIO_free(bmd);
    BIO_free_all(read_bio);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_convert_bin_to_base64(const char* in_buff, size_t in_buff_len,
                                                char** out_buff) {
    ovsa_status_t ret      = OVSA_OK;
    BIO* pem_bio           = NULL;
    BIO* write_bio         = NULL;
    BIO* b64               = NULL;
    BUF_MEM* pem_write_ptr = NULL;

    if ((in_buff == NULL) || (in_buff_len == 0) || (out_buff == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting bin to base64 failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting bin to base64 failed in getting the b64 encode "
                   "method\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    pem_bio = BIO_new(BIO_s_mem());
    if (pem_bio == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error converting bin to base64 failed in getting new BIO for the pem\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    write_bio = pem_bio;
    write_bio = BIO_push(b64, write_bio);

    if (!BIO_write(write_bio, in_buff, in_buff_len)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting bin to base64 failed in writing to pem BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (!BIO_flush(write_bio)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting bin to base64 failed in flushing the pem BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    BIO_get_mem_ptr(write_bio, &pem_write_ptr);
    if (pem_write_ptr == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting bin to base64 failed to extract the pem BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    /* App needs to free this memory */
    *out_buff = ovsa_crypto_app_malloc(pem_write_ptr->length + NULL_TERMINATOR, "pem buffer");
    if (*out_buff == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting bin to base64 failed in allocating memory for "
                   "pem buffer\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    if (memcpy_s(*out_buff, pem_write_ptr->length, pem_write_ptr->data, pem_write_ptr->length) !=
        EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting bin to base64 failed in getting the output buffer\n");
        ovsa_crypto_openssl_free(out_buff);
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

end:
    BIO_free(b64);
    BIO_free_all(pem_bio);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_convert_base64_to_bin(const char* in_buff, size_t in_buff_len,
                                                char* out_buff, size_t* out_buff_len) {
    ovsa_status_t ret = OVSA_OK;
    BIO* bin_bio      = NULL;
    BIO* write_bio    = NULL;
    BIO* b64          = NULL;
    size_t bin_len    = 0;

    if ((in_buff == NULL) || (in_buff_len == 0) || (out_buff == NULL) || (out_buff_len == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting base64 to bin failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting base64 to bin failed in getting the b64 encode "
                   "method\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    bin_bio = BIO_new_mem_buf(in_buff, in_buff_len);
    if (bin_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting base64 to bin failed in writing to bin BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    write_bio = bin_bio;
    write_bio = BIO_push(b64, write_bio);
    bin_len   = BIO_read(write_bio, out_buff, in_buff_len);
    if (bin_len <= 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting base64 to bin failed in reading the bin\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    *out_buff_len = bin_len;

end:
    BIO_free(b64);
    BIO_free_all(bin_bio);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_extract_cert_date(const char* cert, char* issue_date, char* expiry_date) {
    ovsa_status_t ret        = OVSA_OK;
    BIO* issue_date_bio      = NULL;
    BIO* expiry_date_bio     = NULL;
    BUF_MEM* issue_date_ptr  = NULL;
    BUF_MEM* expiry_date_ptr = NULL;
    X509* xcert              = NULL;

    if ((cert == NULL) || (issue_date == NULL) || (expiry_date == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting certificate date failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    issue_date_bio = BIO_new(BIO_s_mem());
    if (issue_date_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting certificate date failed in getting new BIO for the "
                   "issue date\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    expiry_date_bio = BIO_new(BIO_s_mem());
    if (expiry_date_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting certificate date failed in getting new BIO for the "
                   "expiry date\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    xcert = ovsa_crypto_load_cert(cert, "certificate");
    if (xcert == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting certificate date failed to read certificate\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    if (!ASN1_TIME_print(issue_date_bio, X509_get0_notBefore(xcert))) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting certificate date failed to write the issue date\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    BIO_get_mem_ptr(issue_date_bio, &issue_date_ptr);
    if (issue_date_ptr == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting certificate date failed to extract the issue date\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (memcpy_s(issue_date, MAX_DATE_TIME_SIZE, issue_date_ptr->data, issue_date_ptr->length) !=
        EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting certificate date failed in getting issue date\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

    if (!ASN1_TIME_print(expiry_date_bio, X509_get0_notAfter(xcert))) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting certificate date failed to write the expiry date\n");
        ret = OVSA_CRYPTO_X509_ERROR;
        goto end;
    }

    BIO_get_mem_ptr(expiry_date_bio, &expiry_date_ptr);
    if (expiry_date_ptr == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error extracting certificate date failed to extract the expiry date\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (memcpy_s(expiry_date, MAX_DATE_TIME_SIZE, expiry_date_ptr->data, expiry_date_ptr->length) !=
        EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error extracting certificate date failed in getting expiry date\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

end:
    X509_free(xcert);
    BIO_free_all(issue_date_bio);
    BIO_free_all(expiry_date_bio);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_get_current_time(time_t* ovsa_current_time, struct tm** ovsa_current_time_tm) {
    ovsa_status_t ret = OVSA_OK;
    time_t ovsa_time_now;

    if (ovsa_current_time == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error getting current time failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    memset_s(&ovsa_time_now, sizeof(time_t), 0);
    /* Get the current time in UTC format */
    ovsa_time_now = time(&ovsa_time_now);
    if (ovsa_time_now == -1) {
        BIO_printf(g_bio_err, "LibOVSA: Error in getting current time\n");
        return OVSA_TIME_SYSTIME_ERROR;
    }

    *ovsa_current_time_tm = gmtime(&ovsa_time_now);
    if (*ovsa_current_time_tm == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error in filling the current time to the tm structure\n");
        return OVSA_TIME_SYSTIME_ERROR;
    }

    *ovsa_current_time = mktime(*ovsa_current_time_tm);

    return ret;
}

ovsa_status_t ovsa_crypto_check_cert_lifetime_validity(const char* cert) {
    ovsa_status_t ret = OVSA_OK;
    int elapsedtime   = 0;
    time_t ovsa_current_time, ovsa_cert_valid_time;
    struct tm ovsa_cert_issue_tm;
    struct tm* ovsa_current_time_tm = {0};
    char cert_issue_date[MAX_DATE_TIME_SIZE];
    char cert_expiry_date[MAX_DATE_TIME_SIZE];

    if (cert == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error checking certificate validity failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    memset_s(&ovsa_current_time, sizeof(time_t), 0);
    memset_s(&ovsa_cert_valid_time, sizeof(time_t), 0);
    memset_s(&ovsa_cert_issue_tm, sizeof(struct tm), 0);
    memset_s(cert_issue_date, sizeof(cert_issue_date), 0);
    memset_s(cert_expiry_date, sizeof(cert_expiry_date), 0);

    ret = ovsa_get_current_time(&ovsa_current_time, &ovsa_current_time_tm);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error checking certificate validity failed in getting current time\n");
        return ret;
    }

    ret = ovsa_crypto_extract_cert_date(cert, cert_issue_date, cert_expiry_date);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error checking certificate validity failed in extracting certificate date\n");
        goto end;
    }

    /* Check certificate validity */
    strptime(cert_issue_date, "%b %d %H:%M:%S %Y", &ovsa_cert_issue_tm);
    ovsa_cert_issue_tm.tm_mon += MAX_CERT_VALIDITY_PERIOD;
    ovsa_cert_valid_time = mktime(&ovsa_cert_issue_tm);

    /*
     * If current time exceeds max certificate validity period, it indicates certificate validity
     * expired
     */
    elapsedtime = difftime(ovsa_current_time, ovsa_cert_valid_time);
    if (elapsedtime > 0) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error checking certificate validity failed since certificate has expired\n");
        ret = OVSA_TIME_DURATIONEXCEEDS_ERROR;
        goto end;
    }

end:
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_generate_guid(char* guid) {
    ovsa_status_t ret = OVSA_OK;

    if (RAND_bytes(uuid.__rnd, sizeof(uuid)) <= 0) {
        BIO_printf(g_bio_err, "LibOVSA: Error in generating guid\n");
        return OVSA_CRYPTO_GENERIC_ERROR;
    }

    uuid.clk_seq_hi_res      = (uint8_t)((uuid.clk_seq_hi_res & 0x3F) | 0x80);
    uuid.time_hi_and_version = (uint16_t)((uuid.time_hi_and_version & 0x0FFF) | 0x4000);

    snprintf(guid, 38, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", uuid.time_low,
             uuid.time_mid, uuid.time_hi_and_version, uuid.clk_seq_hi_res, uuid.clk_seq_low,
             uuid.node[0], uuid.node[1], uuid.node[2], uuid.node[3], uuid.node[4], uuid.node[5]);

    return ret;
}

ovsa_status_t ovsa_crypto_get_file_size(FILE* fp, size_t* file_size) {
    size_t fsize      = 0;
    ovsa_status_t ret = OVSA_FILEIO_FAIL;
    *file_size        = 0;

    if (fp == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error getting file size failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    if (!(fseek(fp, 0L, SEEK_END) == 0)) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error getting file size failed in setting the fp to end of the file\n");
        goto end;
    }

    fsize = ftell(fp);
    if (fsize == 0) {
        BIO_printf(g_bio_err, "LibOVSA: Error file size is zero\n");
        goto end;
    }

    if (fseek(fp, 0L, SEEK_SET) != 0) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error getting file size failed in setting the fp to begining of the file\n");
        goto end;
    }

    *file_size = fsize + NULL_TERMINATOR;
    ret        = OVSA_OK;

end:
    if (!ret) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_safe_add(size_t* var1, size_t var2) {
    ovsa_status_t ret = OVSA_OK;

    if (*var1 >= 0) {
        if (var2 > SIZE_MAX - *var1) {
            /* overflow */
            OVSA_DBG(DBG_E, "LibOVSA: Error integer overflow detected\n");
            ret = OVSA_INTEGER_OVERFLOW;
            goto out;
        }
    } else {
        if (var2 < INT_MIN - *var1) {
            /* underflow */
            OVSA_DBG(DBG_E, "LibOVSA: Error integer underflow detected\n");
            ret = OVSA_INTEGER_UNDERFLOW;
            goto out;
        }
    }
    *var1 = *var1 + var2;

out:
    return ret;
}
ovsa_status_t ovsa_get_string_length(const char* in_buff, size_t* in_buff_len) {
    ovsa_status_t ret = OVSA_OK;
    size_t total_len = 0, buff_len = 0;

    if ((in_buff == NULL) || (in_buff_len == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error getting length failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    buff_len = strnlen_s(in_buff, RSIZE_MAX_STR);
    if (buff_len < RSIZE_MAX_STR) {
        *in_buff_len = buff_len;
    } else {
        while (buff_len == RSIZE_MAX_STR) {
            ret = ovsa_safe_add(&total_len, RSIZE_MAX_STR);
            if (ret < OVSA_OK) {
                BIO_printf(g_bio_err, "LibOVSA: Error ovsa_safe_add failed %d\n", ret);
                return ret;
            }

            buff_len = strnlen_s(in_buff + total_len, RSIZE_MAX_STR);
            if (buff_len < RSIZE_MAX_STR) {
                ret = ovsa_safe_add(&total_len, buff_len);
                if (ret < OVSA_OK) {
                    BIO_printf(g_bio_err, "LibOVSA: Error ovsa_safe_add failed %d\n", ret);
                    return ret;
                }
                break;
            }
        }
        *in_buff_len = total_len;
    }

    return ret;
}

ovsa_status_t ovsa_compare_strings(const char* src_buff, const char* dest_buff, int* indicator) {
    ovsa_status_t ret   = OVSA_OK;
    char* src_buff_ptr  = NULL;
    char* dest_buff_ptr = NULL;
    size_t buff_len     = 0;
    size_t src_buff_len = 0, dest_buff_len = 0;

    if ((src_buff == NULL) || (dest_buff == NULL) || (indicator == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error comparing strings failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    src_buff_ptr  = (char*)src_buff;
    dest_buff_ptr = (char*)dest_buff;
    ret           = ovsa_get_string_length(src_buff, &src_buff_len);
    if ((ret < OVSA_OK) || (src_buff_len == EOK)) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error comparing strings failed in getting the size of source buffer\n");
        return OVSA_INVALID_FILE_PATH;
    }

    ret = ovsa_get_string_length(dest_buff, &dest_buff_len);
    if ((ret < OVSA_OK) || (dest_buff_len == EOK)) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error comparing strings failed in getting the size of destination buffer\n");
        return OVSA_INVALID_FILE_PATH;
    }

    if (src_buff_len != dest_buff_len) {
        *indicator = -1;
        return ret;
    }

    buff_len = src_buff_len;
    if (buff_len < RSIZE_MAX_STR) {
        if (strcmp_s(src_buff, buff_len, dest_buff, indicator) != EOK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error comparing strings failed for the complete buffer\n");
            return OVSA_CRYPTO_GENERIC_ERROR;
        }
    } else {
        if (strcmp_s(src_buff, RSIZE_MAX_STR, dest_buff, indicator) != EOK) {
            BIO_printf(g_bio_err, "LibOVSA: Error comparing strings failed for the start buffer\n");
            return OVSA_CRYPTO_GENERIC_ERROR;
        }
        while (buff_len >= RSIZE_MAX_STR) {
            src_buff_ptr += RSIZE_MAX_STR;
            dest_buff_ptr += RSIZE_MAX_STR;

            ret = ovsa_get_string_length(src_buff_ptr, &buff_len);
            if (ret < OVSA_OK) {
                BIO_printf(
                    g_bio_err,
                    "LibOVSA: Error comparing strings failed in getting the size of the chunked "
                    "source buffer\n");
                return OVSA_INVALID_FILE_PATH;
            }

            if (buff_len < RSIZE_MAX_STR) {
                if (buff_len != 0) {
                    if (strcmp_s(src_buff_ptr, buff_len, dest_buff_ptr, indicator) != EOK) {
                        BIO_printf(g_bio_err,
                                   "LibOVSA: Error comparing strings failed for end buffer\n");
                        return OVSA_CRYPTO_GENERIC_ERROR;
                    }
                }
                break;
            } else {
                if (strcmp_s(src_buff_ptr, RSIZE_MAX_STR, dest_buff_ptr, indicator) != EOK) {
                    BIO_printf(g_bio_err,
                               "LibOVSA: Error comparing strings failed for intermediate buffer\n");
                    return OVSA_CRYPTO_GENERIC_ERROR;
                }
                if (*indicator != 0) {
                    return ret;
                }
            }
        }
    }

    return ret;
}

ovsa_status_t ovsa_json_create_isv_keystore(const ovsa_isv_keystore_t keystore[], char* outputBuf,
                                            size_t outputLen) {
    ovsa_status_t ret   = OVSA_OK;
    cJSON* isv_keystore = NULL;
    char* str_print     = NULL;
    size_t str_len      = 0;

    OVSA_DBG(DBG_D, "\ncreate_ISV_keystore_json_blob : entry\n");

    if (outputBuf == NULL || outputLen == 0) {
        ret = OVSA_JSON_INVALID_INPUT;
        OVSA_DBG(DBG_E, "LibOVSA: Error input is null %d\n", ret);
        goto end;
    }

    /* Create json object */
    isv_keystore = cJSON_CreateObject();
    if (isv_keystore == NULL) {
        ret = OVSA_JSON_ERROR_CREATE_OBJECT;
        OVSA_DBG(DBG_E, "LibOVSA: Error isv_keystore is null%d\n", ret);
        goto end;
    }

    /* Populate the json structure */
    if (cJSON_AddStringToObject(isv_keystore, "name", keystore[0].isv_name) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "LibOVSA: Error could not add name string object %d\n", ret);
        goto end;
    }

    if (cJSON_AddStringToObject(isv_keystore, "key_guid", keystore[0].key_guid) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "LibOVSA: Error could not add key_guid string object %d\n", ret);
        goto end;
    }

    if (cJSON_AddStringToObject(isv_keystore, "public_key", keystore[0].public_key) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "LibOVSA: Error could not add public_key string object %d\n", ret);
        goto end;
    }

    if (cJSON_AddStringToObject(isv_keystore, "private_key", keystore[0].private_key) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "LibOVSA: Error could not add private_key string object %d\n", ret);
        goto end;
    }

    if (keystore[0].isv_certificate == NULL) {
        if (cJSON_AddStringToObject(isv_keystore, "certificate", "") == NULL) {
            ret = OVSA_JSON_ERROR_ADD_ELEMENT;
            OVSA_DBG(DBG_E, "LibOVSA: Error could not add certificate string object %d\n", ret);
            goto end;
        }
    } else {
        if (cJSON_AddStringToObject(isv_keystore, "certificate", keystore[0].isv_certificate) ==
            NULL) {
            ret = OVSA_JSON_ERROR_ADD_ELEMENT;
            OVSA_DBG(DBG_E, "LibOVSA: Error could not add certificate string object %d\n", ret);
            goto end;
        }
    }

    if (cJSON_AddStringToObject(isv_keystore, "public_key_2", keystore[1].public_key) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "LibOVSA: Error could not add public_key string object %d\n", ret);
        goto end;
    }

    if (cJSON_AddStringToObject(isv_keystore, "private_key_2", keystore[1].private_key) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "LibOVSA: Error could not add private_key string object %d\n", ret);
        goto end;
    }

    if (keystore[1].isv_certificate == NULL) {
        if (cJSON_AddStringToObject(isv_keystore, "certificate_2", "") == NULL) {
            ret = OVSA_JSON_ERROR_ADD_ELEMENT;
            OVSA_DBG(DBG_E, "LibOVSA: Error could not add certificate2 string object %d\n", ret);
            goto end;
        }
    } else {
        if (cJSON_AddStringToObject(isv_keystore, "certificate_2", keystore[1].isv_certificate) ==
            NULL) {
            ret = OVSA_JSON_ERROR_ADD_ELEMENT;
            OVSA_DBG(DBG_E, "LibOVSA: Error could not add certificate2 string object %d\n", ret);
            goto end;
        }
    }
    str_print = cJSON_Print(isv_keystore);
    if (str_print == NULL) {
        ret = OVSA_JSON_PRINT_FAIL;
        OVSA_DBG(DBG_E, "LibOVSA: Error could not print json string %d\n", ret);
        goto end;
    }

    ret = ovsa_get_string_length(str_print, &str_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "LibOVSA: Error could not get length of json string %d\n", ret);
        goto end;
    }
    memcpy_s(outputBuf, outputLen, str_print, str_len);

end:
    cJSON_Delete(isv_keystore);
    if (str_print) {
        ovsa_crypto_openssl_free(&str_print);
    }
    OVSA_DBG(DBG_D, "create_ISV_keystore_json_blob : exit\n");
    return ret;
}

ovsa_status_t ovsa_json_extract_keystore_info(const char* inputBuf,
                                              ovsa_isv_keystore_t keystore[]) {
    ovsa_status_t ret  = OVSA_OK;
    cJSON* parse_json  = NULL;
    cJSON* name        = NULL;
    cJSON* key_guid    = NULL;
    cJSON* public_key  = NULL;
    cJSON* private_key = NULL;
    cJSON* certificate = NULL;

    OVSA_DBG(DBG_D, "\nextract_keystore_info entry\n");

    if (inputBuf == NULL) {
        ret = OVSA_JSON_INVALID_INPUT;
        OVSA_DBG(DBG_E, "LibOVSA: Error input is null %d\n", ret);
        goto end;
    }

    parse_json = cJSON_Parse(inputBuf);
    if (parse_json == NULL) {
        ret = OVSA_JSON_PARSE_FAIL;
        OVSA_DBG(DBG_E, "LibOVSA: Error could not parse %d\n", ret);
        goto end;
    }

    name = cJSON_GetObjectItemCaseSensitive(parse_json, "name");
    if (cJSON_IsString(name) && (name->valuestring != NULL)) {
        memcpy_s(keystore[0].isv_name, MAX_NAME_SIZE, name->valuestring,
                 strnlen_s(name->valuestring, MAX_NAME_SIZE));
        OVSA_DBG(DBG_D, "name %s\n", keystore[0].isv_name);
    }

    key_guid = cJSON_GetObjectItemCaseSensitive(parse_json, "key_guid");
    if (cJSON_IsString(key_guid) && (key_guid->valuestring != NULL)) {
        memcpy_s(keystore[0].key_guid, GUID_SIZE, key_guid->valuestring,
                 strnlen_s(key_guid->valuestring, GUID_SIZE));
    }

    public_key = cJSON_GetObjectItemCaseSensitive(parse_json, "public_key");
    if (cJSON_IsString(public_key) && (public_key->valuestring != NULL)) {
        memcpy_s(keystore[0].public_key, MAX_KEY_SIZE, public_key->valuestring,
                 strnlen_s(public_key->valuestring, MAX_KEY_SIZE));
    }

    private_key = cJSON_GetObjectItemCaseSensitive(parse_json, "private_key");
    if (cJSON_IsString(private_key) && (private_key->valuestring != NULL)) {
        memcpy_s(keystore[0].private_key, MAX_KEY_SIZE, private_key->valuestring,
                 strnlen_s(private_key->valuestring, MAX_KEY_SIZE));
    }

    certificate = cJSON_GetObjectItemCaseSensitive(parse_json, "certificate");
    if (cJSON_IsString(certificate) && (certificate->valuestring != NULL)) {
        size_t str_len = 0;
        ret            = ovsa_get_string_length(certificate->valuestring, &str_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "LibOVSA: Error could not get length of certificate string %d\n", ret);
            goto end;
        }
        memcpy_s(keystore[0].isv_certificate, str_len, certificate->valuestring, str_len);
        OVSA_DBG(DBG_D, "certificate %s\n", keystore[0].isv_certificate);
    }

    cJSON* public_key_2 = cJSON_GetObjectItemCaseSensitive(parse_json, "public_key_2");
    if (cJSON_IsString(public_key_2) && (public_key_2->valuestring != NULL)) {
        memcpy_s(keystore[1].public_key, MAX_KEY_SIZE, public_key_2->valuestring,
                 strnlen_s(public_key_2->valuestring, MAX_KEY_SIZE));
    }

    cJSON* private_key_2 = cJSON_GetObjectItemCaseSensitive(parse_json, "private_key_2");
    if (cJSON_IsString(private_key_2) && (private_key_2->valuestring != NULL)) {
        memcpy_s(keystore[1].private_key, MAX_KEY_SIZE, private_key_2->valuestring,
                 strnlen_s(private_key_2->valuestring, MAX_KEY_SIZE));
    }

    cJSON* certificate_2 = cJSON_GetObjectItemCaseSensitive(parse_json, "certificate_2");
    if (cJSON_IsString(certificate_2) && (certificate_2->valuestring != NULL)) {
        size_t str_len = 0;
        ret            = ovsa_get_string_length(certificate_2->valuestring, &str_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "LibOVSA: Error could not get length of certificate string %d\n", ret);
            goto end;
        }
        memcpy_s(keystore[1].isv_certificate, str_len, certificate_2->valuestring, str_len);
        OVSA_DBG(DBG_D, "certificate_2 %s\n", keystore[1].isv_certificate);
    }

end:
    cJSON_Delete(parse_json);
    OVSA_DBG(DBG_D, "extract_keystore_info exit\n");
    return ret;
}

ovsa_status_t ovsa_json_create_encrypted_keystore(const char* keystoreBuf, char* outputBuf,
                                                  size_t outLen) {
    ovsa_status_t ret  = OVSA_OK;
    cJSON* en_keystore = NULL;
    char* str_print    = NULL;
    size_t str_len     = 0;

    OVSA_DBG(DBG_D, "\novsa_json_create_encrypted_keystore : entry\n");

    if (keystoreBuf == NULL || outputBuf == NULL || outLen == 0) {
        ret = OVSA_JSON_INVALID_INPUT;
        OVSA_DBG(DBG_E, "LibOVSA: Error input is null %d\n", ret);
        goto end;
    }

    /* Create json object */
    en_keystore = cJSON_CreateObject();
    if (en_keystore == NULL) {
        ret = OVSA_JSON_ERROR_CREATE_OBJECT;
        OVSA_DBG(DBG_E, "LibOVSA: Error en_keystore is null%d\n", ret);
        goto end;
    }

    /* Populate the json structure */
    if (cJSON_AddStringToObject(en_keystore, "keystore", keystoreBuf) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "LibOVSA: Error could not add keystore string object %d\n", ret);
        goto end;
    }

    str_print = cJSON_Print(en_keystore);
    if (str_print == NULL) {
        ret = OVSA_JSON_PRINT_FAIL;
        OVSA_DBG(DBG_E, "LibOVSA: Error could not print json string %d\n", ret);
        goto end;
    }

    ret = ovsa_get_string_length(str_print, &str_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "LibOVSA: Error could not get length of json string %d\n", ret);
        goto end;
    }
    memcpy_s(outputBuf, outLen, str_print, str_len);

end:
    cJSON_Delete(en_keystore);
    if (str_print) {
        ovsa_crypto_openssl_free(&str_print);
    }
    OVSA_DBG(DBG_D, "ovsa_json_create_encrypted_keystore : exit\n");
    return ret;
}

ovsa_status_t ovsa_json_extract_encrypted_keystore(const char* inputBuf,
                                                   ovsa_enc_keystore_t* en_keystore,
                                                   size_t enkeyLen) {
    ovsa_status_t ret   = OVSA_OK;
    cJSON* parse_json   = NULL;
    cJSON* enc_keystore = NULL;
    size_t str_len      = 0;

    OVSA_DBG(DBG_D, "\novsa_json_extract_encrypted_keystore entry\n");

    if (inputBuf == NULL || enkeyLen == 0) {
        ret = OVSA_JSON_INVALID_INPUT;
        OVSA_DBG(DBG_E, "LibOVSA: Error input is null %d\n", ret);
        goto end;
    }

    parse_json = cJSON_Parse(inputBuf);
    if (parse_json == NULL) {
        ret = OVSA_JSON_PARSE_FAIL;
        OVSA_DBG(DBG_E, "LibOVSA: Error could not parse %d\n", ret);
        goto end;
    }

    enc_keystore = cJSON_GetObjectItemCaseSensitive(parse_json, "keystore");
    if (cJSON_IsString(enc_keystore) && (enc_keystore->valuestring != NULL)) {
        ret = ovsa_get_string_length(enc_keystore->valuestring, &str_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "LibOVSA: Error could not get length of enc_keystore string %d\n", ret);
            goto end;
        }
        memcpy_s(en_keystore->keystore, str_len, enc_keystore->valuestring, str_len);
    }

end:
    cJSON_Delete(parse_json);
    OVSA_DBG(DBG_D, "ovsa_json_extract_encrypted_keystore exit\n");
    return ret;
}

ovsa_status_t ovsa_json_apend_signature(const char* inputBuf, const char* sigBuf, char* outBuf,
                                        size_t buff_len) {
    ovsa_status_t ret = OVSA_OK;
    cJSON* input_json = NULL;
    char* str_print   = NULL;
    size_t str_len    = 0;

    OVSA_DBG(DBG_D, "\novsa_apend_signature entry\n");

    if (inputBuf == NULL || sigBuf == NULL || buff_len == 0 || outBuf == NULL) {
        ret = OVSA_JSON_INVALID_INPUT;
        OVSA_DBG(DBG_E, "LibOVSA: Error input is null %d\n", ret);
        goto end;
    }

    OVSA_DBG(DBG_D, "sigBuf: %s\n", sigBuf);
    input_json = cJSON_Parse(inputBuf);
    if (input_json == NULL) {
        ret = OVSA_JSON_PARSE_FAIL;
        OVSA_DBG(DBG_E, "LibOVSA: Error could not parse inputBuf %d\n", ret);
        goto end;
    }

    if (cJSON_AddStringToObject(input_json, "signature", sigBuf) == NULL) {
        ret = OVSA_JSON_ERROR_ADD_ELEMENT;
        OVSA_DBG(DBG_E, "LibOVSA: Error could not add sigBuf string object %d\n", ret);
        goto end;
    }

    str_print = cJSON_Print(input_json);
    if (str_print == NULL) {
        OVSA_DBG(DBG_E, "LibOVSA: Error could not print json string\n");
        ret = OVSA_JSON_PRINT_FAIL;
        goto end;
    }

    ret = ovsa_get_string_length(str_print, &str_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "LibOVSA: Error could not get length of string %d\n", ret);
        goto end;
    }
    memcpy_s(outBuf, buff_len, str_print, str_len);

end:
    cJSON_Delete(input_json);
    if (str_print) {
        ovsa_crypto_openssl_free(&str_print);
    }
    OVSA_DBG(DBG_D, "ovsa_apend_signature exit\n");
    return ret;
}

ovsa_status_t ovsa_json_extract_and_strip_signature(const char* inputBuf, char* sigBuf,
                                                    size_t sigLen, char* outBuf, size_t outLen) {
    ovsa_status_t ret = OVSA_OK;
    cJSON* input_json = NULL;
    cJSON* sig_json   = NULL;
    cJSON* signature  = NULL;
    char* input       = NULL;
    size_t str_len    = 0;

    OVSA_DBG(DBG_D, "\novsa_extract_and_strip_signature entry\n");

    if (inputBuf == NULL || sigBuf == NULL || outLen == 0 || outBuf == NULL) {
        ret = OVSA_JSON_INVALID_INPUT;
        OVSA_DBG(DBG_E, "LibOVSA: Error input is null %d\n", ret);

        goto end;
    }

    input_json = cJSON_Parse(inputBuf);
    if (input_json == NULL) {
        ret = OVSA_JSON_PARSE_FAIL;
        OVSA_DBG(DBG_E, "LibOVSA: Error could not parse inputBuf %d\n", ret);
        goto end;
    }

    sig_json = cJSON_GetObjectItemCaseSensitive(input_json, "signature");
    if (cJSON_IsString(sig_json) && (sig_json->valuestring != NULL)) {
        memcpy_s(sigBuf, sigLen, sig_json->valuestring, strnlen_s(sig_json->valuestring, sigLen));
        OVSA_DBG(DBG_D, "signature: %s\n", sigBuf);
    } else {
        ret = OVSA_JSON_PARSE_FAIL;
        OVSA_DBG(DBG_E, "LibOVSA: Error Signature is null %d\n", ret);
        goto end;
    }

    signature = cJSON_DetachItemFromObjectCaseSensitive(input_json, "signature");
    if (signature == NULL) {
        OVSA_DBG(DBG_E, "LibOVSA: Error could not extract signature\n");
        ret = OVSA_JSON_PARSE_FAIL;
        goto end;
    }

    input = cJSON_Print(input_json);
    if (input == NULL) {
        OVSA_DBG(DBG_E, "LibOVSA: Error could not print json input string\n");
        ret = OVSA_JSON_PRINT_FAIL;
        goto end;
    }

    ret = ovsa_get_string_length(input, &str_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "LibOVSA: Error could not get length of string %d\n", ret);
        goto end;
    }
    memcpy_s(outBuf, outLen, input, str_len);

end:
    cJSON_Delete(input_json);
    cJSON_Delete(signature);
    if (input) {
        ovsa_crypto_openssl_free(&input);
    }
    OVSA_DBG(DBG_D, "ovsa_extract_and_strip_signature exit\n");
    return ret;
}

ovsa_status_t ovsa_json_getitem_size(const char* keyName, const char* inBuf, size_t* len) {
    ovsa_status_t ret = OVSA_OK;
    cJSON* parse_json = NULL;
    cJSON* key        = NULL;

    OVSA_DBG(DBG_D, "\novsa_getjsonitem_size: entry\n");

    if (inBuf == NULL || keyName == NULL || len == NULL) {
        ret = OVSA_JSON_INVALID_INPUT;
        OVSA_DBG(DBG_E, "LibOVSA: Error input parameters invalid %d\n", ret);
        goto end;
    }

    parse_json = cJSON_Parse(inBuf);
    if (parse_json == NULL) {
        ret = OVSA_JSON_PARSE_FAIL;
        OVSA_DBG(DBG_E, "LibOVSA: Error json parse failed %d\n", ret);
        goto end;
    }

    key = cJSON_GetObjectItemCaseSensitive(parse_json, keyName);
    if (cJSON_IsString(key) && (key->valuestring != NULL)) {
        ret = ovsa_get_string_length(key->valuestring, len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "LibOVSA: Error ovsa crypto get length failed with code %d\n", ret);
            goto end;
        }
    }
    OVSA_DBG(DBG_D, "len of %s is %d\n", keyName, (int)*len);

end:
    cJSON_Delete(parse_json);
    OVSA_DBG(DBG_D, "ovsa_getjsonitem_size: exit\n");
    return ret;
}
