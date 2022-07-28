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

#include <assert.h>
#include <errno.h>
#include <openssl/bio.h>
#include <openssl/bioerr.h>
#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "license_service.h"
#include "safe_str_lib.h"
#include "utils.h"

ovsa_status_t ovsa_license_service_generate_randnum(int size, bool b64_format, int out_len,
                                                    char* nonce_buf);
void ovsa_license_service_crypto_openssl_free(char** buff) {
    size_t buff_len = 0;

    if (*buff != NULL) {
        ovsa_license_service_get_string_length(*buff, &buff_len);
        OPENSSL_clear_free(*buff, buff_len);
        *buff = NULL;
    }

    return;
}

EVP_PKEY* ovsa_license_service_crypto_load_key(const char* p_Key, const char* key_descrip) {
    BIO* key       = NULL;
    EVP_PKEY* pkey = NULL;

    if ((p_Key == NULL) || (key_descrip == NULL)) {
        OVSA_DBG(DBG_E, "OVSA: Error loading the key failed with invalid parameter\n");
        return NULL;
    }

    key = BIO_new(BIO_s_mem());
    if (key == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error loading the key failed in getting the new BIO\n");
        goto end;
    }

    if (BIO_puts(key, p_Key) <= 0) {
        OVSA_DBG(DBG_E, "OVSA: Error loading the key failed in writing to key BIO\n");
        goto end;
    }

    if (strcmp(key_descrip, "private key") == 0) {
        pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);
    } else {
        pkey = PEM_read_bio_PUBKEY(key, NULL, NULL, NULL);
    }

end:
    BIO_free_all(key);
    if (pkey == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error loading the key failed in loading the %s into memory\n",
                 key_descrip);
        ERR_print_errors(g_bio_err);
    }
    return pkey;
}

ovsa_status_t ovsa_license_service_crypto_do_sign_verify_hash(unsigned char* buf, BIO* inp,
                                                              const EVP_PKEY* key,
                                                              const unsigned char* sigin,
                                                              int siglen, const char* file,
                                                              BIO* out) {
    int read = 0, verify = 0, count = 0;
    unsigned char* sigbuf = NULL;
    ovsa_status_t ret     = OVSA_OK;
    size_t len            = BUFSIZE;

    while (BIO_pending(inp) || !BIO_eof(inp)) {
        read = BIO_read(inp, (char*)buf, BUFSIZE);
        if (read < 0) {
            OVSA_DBG(DBG_E,
                     "OVSA: Error signing/verifying/hashing failed in reading the "
                     "input file\n");
            ret = -1;
            OVSA_DBG(DBG_E,
                     "OVSA: Error signing/verifying/hashing failed in reading the "
                     "input file\n");
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
            OVSA_DBG(DBG_I, "Verified OK\n");
        } else if (verify == 0) {
            OVSA_DBG(DBG_E, "OVSA: Error verification Failure\n");
            ret = -1;
            goto end;
        } else {
            OVSA_DBG(DBG_E, "OVSA: Error verifying Data\n");
            ret = -1;
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
            len = pkey_len;
            ret = ovsa_license_service_safe_malloc(len, (char**)&sigbuf);
            if (ret < OVSA_OK) {
                ret = OVSA_MEMORY_ALLOC_FAIL;
                OVSA_DBG(DBG_E, "OVSA: Error init memory failed with code %d\n", ret);
                goto end;
            }
            buf = sigbuf;
        }

        if (!EVP_DigestSignFinal(ctx, buf, &len)) {
            OVSA_DBG(DBG_E, "OVSA: Error signing failed to sign the data\n");
            ret = -1;
            goto end;
        }

        if (!BIO_write(out, buf, len)) {
            OVSA_DBG(DBG_E, "OVSA: Error signing failed in writing the signature\n");
            ret = -1;
            goto end;
        }
    } else {
        len = BIO_gets(inp, (char*)buf, BUFSIZE);
        if ((int)len <= 0) {
            OVSA_DBG(DBG_E, "OVSA: Error hashing failed with invalid input file length\n");
            ret = -1;
            goto end;
        }
        for (count = 0; count < (int)len; count++) {
            BIO_printf(out, "%02x", buf[count]);
        }
    }

    if (!BIO_flush(out)) {
        OVSA_DBG(DBG_E, "OVSA: Error signing failed in flushing the signature\n");
        ret = -1;
        goto end;
    }

    if (key != NULL) {
        OVSA_DBG(DBG_E, "Signing Done\n");
    }

end:
    if (sigbuf != NULL) {
        OPENSSL_clear_free(sigbuf, len);
    }
    return ret;
}

X509* ovsa_license_service_crypto_load_cert(const char* cert, const char* cert_descrip) {
    BIO* cert_mem = NULL;
    X509* xcert   = NULL;

    if ((cert == NULL) || (cert_descrip == NULL)) {
        OVSA_DBG(DBG_E, "OVSA: Error loading the certificate failed with invalid parameter\n");
        return NULL;
    }

    cert_mem = BIO_new(BIO_s_mem());
    if (cert_mem == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error loading the certificate failed in getting the new BIO\n");
        goto end;
    }

    if (BIO_puts(cert_mem, cert) <= 0) {
        OVSA_DBG(DBG_E,
                 "OVSA: Error loading the certificate failed in writing to "
                 "certificate BIO\n");
        goto end;
    }

    xcert = PEM_read_bio_X509_AUX(cert_mem, NULL, NULL, NULL);

end:
    if (xcert == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error in loading the %s into memory\n", cert_descrip);
        ERR_print_errors(g_bio_err);
    }

    BIO_free_all(cert_mem);
    return xcert;
}

ovsa_status_t ovsa_license_service_crypto_extract_pubkey_certificate(const char* cert,
                                                                     char* public_key) {
    ovsa_status_t ret   = OVSA_OK;
    BUF_MEM* pubkey_ptr = NULL;
    BIO* pubkey_mem     = NULL;
    EVP_PKEY* pkey      = NULL;
    X509* xcert         = NULL;

    if ((cert == NULL) || (public_key == NULL)) {
        OVSA_DBG(DBG_E,
                 "OVSA: Error extracting public key from certificate failed with invalid "
                 "parameter\n");
        return -1;
    }

    pubkey_mem = BIO_new(BIO_s_mem());
    if (pubkey_mem == NULL) {
        OVSA_DBG(DBG_E,
                 "OVSA: Error extracting public key from certificate failed in "
                 "getting new BIO\n");
        ret = -1;
        goto end;
    }

    xcert = ovsa_license_service_crypto_load_cert(cert, "certificate");
    if (xcert == NULL) {
        OVSA_DBG(DBG_E,
                 "OVSA: Error extracting public key from certificate failed to "
                 "read certificate\n");
        ret = -1;
        goto end;
    }

    /* Extract public key from certificate */
    pkey = X509_get0_pubkey(xcert);
    if (pkey == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error in extracting the public key from certificate\n");
        ret = -1;
        goto end;
    }

    if (!PEM_write_bio_PUBKEY(pubkey_mem, pkey)) {
        OVSA_DBG(DBG_E,
                 "OVSA: Error extracting public key from certificate failed in writing the "
                 "public key\n");
        ret = -1;
        goto end;
    }

    BIO_get_mem_ptr(pubkey_mem, &pubkey_ptr);
    if (pubkey_ptr == NULL) {
        OVSA_DBG(DBG_E,
                 "OVSA: Error extracting public key from certificate failed to extract the "
                 "public key\n");
        ret = -1;
        goto end;
    }

    if (memcpy_s(public_key, MAX_KEY_SIZE, pubkey_ptr->data, pubkey_ptr->length) != EOK) {
        OVSA_DBG(DBG_E,
                 "OVSA: Error extracting public key from certificate failed in getting the "
                 "public key\n");
        ret = -1;
        goto end;
    }

end:
    X509_free(xcert);
    BIO_free_all(pubkey_mem);
    if (ret < 0) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_license_service_crypto_verify_mem(const char* cert, const char* in_buff,
                                                     size_t in_buff_len, char* signature) {
    ovsa_status_t ret              = OVSA_OK;
    unsigned char* verify_mem_buff = NULL;
    unsigned char* sigbuff         = NULL;
    const EVP_MD* md               = NULL;
    BIO* input_bio                 = NULL;
    BIO* write_bio                 = NULL;
    EVP_PKEY* pkey                 = NULL;
    BIO* read_bio                  = NULL;
    BIO* sigbio                    = NULL;
    BIO* bmd                       = NULL;
    BIO* b64                       = NULL;
    int siglen = 0, verify = 0;
    char public_key[MAX_KEY_SIZE];

    g_bio_err = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (g_bio_err == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error crypto Initialization failed in creating a file BIO\n");
        return -1;
    }

    if ((cert == NULL) || (in_buff == NULL) || (in_buff_len == 0) || (signature == NULL)) {
        OVSA_DBG(DBG_E, "OVSA: Error verifying the memory buffer failed with invalid parameter\n");
        return -1;
    }

    memset_s(public_key, MAX_KEY_SIZE, 0);
    ret = ovsa_license_service_crypto_extract_pubkey_certificate(cert, public_key);
    if (ret < 0) {
        OVSA_DBG(DBG_E,
                 "OVSA: Error verifying the memory buffer failed in extracting "
                 "the public key\n");
        goto end;
    }

    read_bio = BIO_new(BIO_s_mem());
    if (read_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying the memory buffer failed in "
                   "getting new BIO for the "
                   "input buffer\n");
        ret = -1;
        goto end;
    }

    bmd = BIO_new(BIO_f_md());
    if (bmd == NULL) {
        OVSA_DBG(DBG_E,
                 "OVSA: Error verifying the memory buffer failed in getting the "
                 "message digest\n");
        ret = -1;
        goto end;
    }

    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        OVSA_DBG(DBG_E,
                 "OVSA: Error verifying the memory buffer failed in getting the "
                 "b64 encode method\n");
        ret = -1;
        goto end;
    }

    input_bio = BIO_push(bmd, read_bio);
    if (BIO_puts(read_bio, in_buff) <= 0) {
        OVSA_DBG(DBG_E,
                 "OVSA: Error verifying the memory buffer failed in writing to "
                 "input buffer BIO\n");
        ret = -1;
        goto end;
    }

    pkey = ovsa_license_service_crypto_load_key(public_key, "public key");
    if (pkey != NULL) {
        EVP_MD_CTX* mctx   = NULL;
        EVP_PKEY_CTX* pctx = NULL;
        md                 = EVP_sha512();

        if (!BIO_get_md_ctx(bmd, &mctx)) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error verifying the memory buffer failed "
                       "in getting the context "
                       "for digest\n");
            ret = -1;
            goto end;
        }

        verify = EVP_DigestVerifyInit(mctx, &pctx, md, NULL, pkey);
        if (!verify) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error verifying the memory buffer failed in setting up the "
                       "verifying context\n");
            ret = -1;
            goto end;
        }

        write_bio = BIO_new(BIO_s_mem());
        if (write_bio == NULL) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error verifying the memory buffer failed "
                       "in getting new BIO for the "
                       "signature buffer\n");
            ret = -1;
            goto end;
        }

        sigbio = write_bio;
        if (BIO_puts(sigbio, signature) <= 0) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error verifying the memory buffer failed "
                       "in writing to signature BIO\n");
            ret = -1;
            goto end;
        }

        sigbio = BIO_push(b64, sigbio);
        siglen = EVP_PKEY_size(pkey);

        ret = ovsa_license_service_safe_malloc(siglen, (char**)&sigbuff);
        if (ret < OVSA_OK) {
            ret = OVSA_MEMORY_ALLOC_FAIL;
            OVSA_DBG(DBG_E, "OVSA: Error init memory failed with code %d\n", ret);
            goto end;
        }

        siglen = BIO_read(sigbio, sigbuff, siglen);
        if (siglen <= 0) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error verifying the memory buffer failed "
                       "in reading to signature BIO\n");
            ret = -1;
            goto end;
        }
    } else {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error verifying the memory buffer failed in "
                   "loading the public key "
                   "into memory\n");
        ret = -1;
        goto end;
    }

    ret = ovsa_license_service_safe_malloc(EVP_ENCODE_LENGTH(BUFSIZE), (char**)&verify_mem_buff);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error init memory failed with code %d\n", ret);
        goto end;
    }

    ret = ovsa_license_service_crypto_do_sign_verify_hash(verify_mem_buff, input_bio, pkey, sigbuff,
                                                          siglen, in_buff, NULL);
    if (ret < 0) {
        OVSA_DBG(DBG_E,
                 "OVSA: Error verifying the memory buffer failed in verifying "
                 "the signature\n");
        goto end;
    }

    (void)BIO_reset(bmd);
end:
    OPENSSL_cleanse(public_key, MAX_KEY_SIZE);
    EVP_PKEY_free(pkey);
    OPENSSL_free(sigbuff);
    OPENSSL_free(verify_mem_buff);
    BIO_free(b64);
    BIO_free_all(write_bio);
    BIO_free(bmd);
    BIO_free_all(read_bio);
    if (ret < 0) {
        ERR_print_errors(g_bio_err);
    }
    if (g_bio_err != NULL) {
        BIO_free_all(g_bio_err);
        g_bio_err = NULL;
    }
    return ret;
}

ovsa_status_t ovsa_license_service_crypto_convert_bin_to_base64(const char* in_buff,
                                                                size_t in_buff_len,
                                                                char** out_buff) {
    ovsa_status_t ret      = OVSA_OK;
    BIO* pem_bio           = NULL;
    BIO* write_bio         = NULL;
    BIO* b64               = NULL;
    BUF_MEM* pem_write_ptr = NULL;

    if ((in_buff == NULL) || (in_buff_len == 0)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting bin to pem failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting bin to pem failed in getting the b64 encode "
                   "method\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    pem_bio = BIO_new(BIO_s_mem());
    if (pem_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting bin to pem failed in "
                   "getting new BIO for the pem\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    write_bio = pem_bio;
    write_bio = BIO_push(b64, write_bio);

    if (!BIO_write(write_bio, in_buff, in_buff_len)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting bin to pem failed in writing to pem BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (!BIO_flush(write_bio)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting bin to pem failed in "
                   "flushing the pem BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    BIO_get_mem_ptr(write_bio, &pem_write_ptr);
    if (pem_write_ptr == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting bin to pem failed to extract the pem BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    /* App needs to free this memory */
    ret = ovsa_license_service_safe_malloc(pem_write_ptr->length + NULL_TERMINATOR, out_buff);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting bin to pem failed in allocating memory for "
                   "pem buffer\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    if (memcpy_s(*out_buff, pem_write_ptr->length, pem_write_ptr->data, pem_write_ptr->length) !=
        EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting bin to pem failed in "
                   "getting the output buffer\n");
        ret = OVSA_MEMIO_ERROR;
        ovsa_license_service_safe_free(out_buff);
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

ovsa_status_t ovsa_license_service_crypto_convert_base64_to_bin(const char* in_buff,
                                                                size_t in_buff_len, char* out_buff,
                                                                size_t* out_buff_len) {
    ovsa_status_t ret = OVSA_OK;
    BIO* bin_bio      = NULL;
    BIO* write_bio    = NULL;
    BIO* b64          = NULL;
    size_t bin_len    = 0;

    if ((in_buff == NULL) || (in_buff_len == 0) || (out_buff == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting pem to bin failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting pem to bin failed in getting the b64 encode "
                   "method\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    bin_bio = BIO_new_mem_buf(in_buff, in_buff_len);
    if (bin_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error converting pem to bin failed in writing to bin BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    write_bio = bin_bio;
    write_bio = BIO_push(b64, write_bio);
    bin_len   = BIO_read(write_bio, out_buff, in_buff_len);
    if (bin_len <= 0) {
        BIO_printf(g_bio_err, "LibOVSA: Error converting pem to bin failed in reading the bin\n");
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

ovsa_status_t ovsa_license_service_generate_nonce_payload(char** nonce_buf, char** json_payload) {
    ovsa_status_t ret        = OVSA_OK;
    char* nonce_json_buf     = NULL;
    bool is_b64_format       = true;
    size_t nonce_payload_len = 0;
    size_t length            = 0;
    unsigned char nonce[NONCE_SIZE];

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    size_t nonce_len = (sizeof(char) * SECRET_NONCE_SIZE * 2) + 1;
    ret              = ovsa_license_service_safe_malloc(nonce_len, nonce_buf);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error memory init failed\n");
        goto out;
    }

    /* Generate nonce */
    ret = ovsa_license_service_generate_randnum(SECRET_NONCE_SIZE, is_b64_format, nonce_len, *nonce_buf);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error create nonce failed with code %d\n", ret);
        goto out;
    }
    /* created json message blob for nonce */
    ret = ovsa_license_service_json_create_message_blob(OVSA_SEND_NONCE, *nonce_buf,
                                                        &nonce_json_buf, &length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error create message blob failed with error code %d\n", ret);
        goto out;
    }
    /* Append payload length to json blob */
    nonce_payload_len = length + PAYLOAD_LENGTH + 1;
    ret = ovsa_license_service_safe_malloc((sizeof(char) * nonce_payload_len), json_payload);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error memory init failed\n");
        goto out;
    }
    ret = ovsa_license_service_append_payload_len_to_blob(nonce_json_buf, json_payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error json blob creation failed with %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_D, "OVSA:json payload %s\n", *json_payload);
out:
    ovsa_license_service_safe_free(&nonce_json_buf);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_license_service_crypto_compute_hash(const char* in_buff, int hash_alg,
                                                       char* out_buff, bool b64_format) {
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
        OVSA_DBG(DBG_E, "OVSA: Error computing hash failed with invalid parameter\n");
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
        OVSA_DBG(DBG_E, "OVSA: Error computing hash failed in getting new BIO");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    bmd = BIO_new(BIO_f_md());
    if (bmd == NULL) {
        OVSA_DBG(DBG_E, "OVSA: Error computing hash failed in getting the message digest\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (b64_format == true) {
        if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
            OVSA_DBG(DBG_E, "OVSA: Error computing hash failed in getting the b64 encode method\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }
    }

    write_bio = BIO_new(BIO_s_mem());
    if (write_bio == NULL) {
        OVSA_DBG(DBG_E,
                 "OVSA: Error computing hash failed in getting new BIO for the output buffer\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    out_bio = write_bio;
    if (b64_format == true)
        out_bio = BIO_push(b64, out_bio);
    input_bio = BIO_push(bmd, read_bio);
    if (BIO_puts(read_bio, in_buff) <= 0) {
        OVSA_DBG(DBG_E, "OVSA: Error computing hash failed in writing to input buffer BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (!BIO_get_md_ctx(bmd, &mctx)) {
        OVSA_DBG(DBG_E, "OVSA: Error computing hash failed in getting the context for digest\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (!EVP_DigestInit_ex(mctx, md, NULL)) {
        OVSA_DBG(DBG_E, "OVSA: Error computing hash failed in setting up the digest context\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }
    ret = ovsa_license_service_safe_malloc(EVP_ENCODE_LENGTH(BUFSIZE), (char**)&compute_hash_buff);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "OVSA: Error init memory failed with code %d\n", ret);
        goto end;
    }
    ret = ovsa_license_service_crypto_do_sign_verify_hash(compute_hash_buff, input_bio, NULL, NULL,
                                                          0, in_buff, out_bio);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OVSA: Error computing hash failed in generating the hash\n");
        goto end;
    }

    if (b64_format == true) {
        BIO_get_mem_ptr(out_bio, &compute_hash_ptr);
        if (compute_hash_ptr == NULL) {
            OVSA_DBG(DBG_E, "OVSA: Error computing hash failed to extract the computed hash\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }
        if (memcpy_s(out_buff, HASH_B64_SIZE, compute_hash_ptr->data, compute_hash_ptr->length) !=
            EOK) {
            OVSA_DBG(DBG_E, "OVSA: Error computing hash failed in getting the output buffer\n");
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
    ovsa_license_service_crypto_openssl_free((char**)&compute_hash_buff);
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
