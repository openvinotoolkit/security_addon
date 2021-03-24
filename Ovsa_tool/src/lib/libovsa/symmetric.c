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

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string.h>

#include "tpm.h"
#include "utils.h"
/* Include at last due to dependency */
#include "symmetric.h"

static ovsa_status_t ovsa_crypto_RNG(int key_size, char* symmetric_key);

static EVP_PKEY_CTX* ovsa_crypto_init_ctx(EVP_PKEY* pkey);

static int ovsa_crypto_setup_peer(EVP_PKEY_CTX* ctx, EVP_PKEY* pkey);

static ovsa_status_t ovsa_crypto_RNG(int key_size, char* symmetric_key) {
    ovsa_status_t ret   = OVSA_OK;
    BUF_MEM* symkey_ptr = NULL;
    BIO* sym_key_mem    = NULL;
    int count = 0, rng = 0;

    if ((key_size == 0) || (symmetric_key == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error RNG failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    sym_key_mem = BIO_new(BIO_s_mem());
    if (sym_key_mem == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error RNG failed in getting new BIO for symmetric key\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    while (key_size > 0) {
        unsigned char buff[MAX_SYM_KEY_SIZE];
        int chunk = 0;

        chunk = key_size;
        if (chunk > (int)sizeof(buff)) {
            chunk = sizeof(buff);
        }

        rng = RAND_bytes(buff, chunk);
        if (rng <= 0) {
            ret = OVSA_CRYPTO_GENERIC_ERROR;
            goto end;
        }

        for (count = 0; count < chunk; count++) {
            if (BIO_printf(sym_key_mem, "%02x", buff[count]) != 2) {
                ret = OVSA_CRYPTO_GENERIC_ERROR;
                goto end;
            }
        }
        key_size -= chunk;
        /* Clear symmetric key buffer */
        OPENSSL_cleanse(buff, sizeof(buff));
    }

    BIO_puts(sym_key_mem, "\n");
    if (!BIO_flush(sym_key_mem)) {
        BIO_printf(g_bio_err, "LibOVSA: Error RNG failed in flushing the symmetric key\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    BIO_get_mem_ptr(sym_key_mem, &symkey_ptr);
    if (symkey_ptr == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error RNG failed to extract the symmetric key\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (memcpy_s(symmetric_key, MAX_EKEY_SIZE, symkey_ptr->data, symkey_ptr->length) != EOK) {
        BIO_printf(g_bio_err, "LibOVSA: Error RNG failed in getting the symmetric key\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

end:
    BIO_free_all(sym_key_mem);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

static EVP_PKEY_CTX* ovsa_crypto_init_ctx(EVP_PKEY* pkey) {
    EVP_PKEY_CTX* ctx = NULL;
    int status        = -1;

    if (pkey == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error initializing context failed in getting the key\n");
        return ctx;
    }

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error initializing context failed in allocating the context for key\n");
        goto end;
    }

    status = EVP_PKEY_derive_init(ctx);
    if (status <= 0) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error initializing context failed to initialize the context for key\n");
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
    }

end:
    EVP_PKEY_free(pkey);
    return ctx;
}

static int ovsa_crypto_setup_peer(EVP_PKEY_CTX* ctx, EVP_PKEY* pkey) {
    int status = -1;

    if ((ctx == NULL) || (pkey == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error setting up peer key failed with invalid parameter\n");
        return status;
    }

    status = EVP_PKEY_derive_set_peer(ctx, pkey);
    if (status <= 0) {
        BIO_printf(g_bio_err, "LibOVSA: Error in setting up the peer key\n");
    }

    EVP_PKEY_free(pkey);
    return status;
}

ovsa_status_t ovsa_crypto_create_ecdh_key(int asym_key_slot, int peer_key_slot, int* sym_key_slot) {
    ovsa_status_t ret       = OVSA_OK;
    BUF_MEM* shared_key_ptr = NULL;
    BIO* shared_key_mem     = NULL;
    BIO* shared_key_bio     = NULL;
    unsigned char* buff     = NULL;
    EVP_PKEY* peerkey       = NULL;
    EVP_PKEY_CTX* ctx       = NULL;
    EVP_PKEY* pkey          = NULL;
    size_t buff_len         = 0;
    char* cert              = NULL;
    BIO* b64                = NULL;
    int status              = -1;
    size_t private_key_len = 0, public_key_len = 0;
    char peer_key[MAX_KEY_SIZE];
    char private_key[MAX_KEY_SIZE];
    char shared_key[MAX_EKEY_SIZE];
    unsigned char sha512[SHA512_DIGEST_LENGTH];

    if ((asym_key_slot < MIN_KEY_SLOT) || (asym_key_slot >= MAX_KEY_SLOT) ||
        (peer_key_slot < MIN_KEY_SLOT) || (peer_key_slot >= MAX_KEY_SLOT) ||
        (sym_key_slot == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error creating ecdh key failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    private_key_len = strnlen_s(g_key_store[asym_key_slot].private_key, MAX_KEY_SIZE);
    if (private_key_len == EOK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error creating ecdh key failed in getting the size of the private key\n");
        return OVSA_CRYPTO_GENERIC_ERROR;
    }

    memset_s(private_key, MAX_KEY_SIZE, 0);

    if (memcpy_s(private_key, MAX_KEY_SIZE, g_key_store[asym_key_slot].private_key,
                 private_key_len) != EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error creating ecdh key failed in getting the private key\n");
        return OVSA_MEMIO_ERROR;
    }

    memset_s(peer_key, MAX_KEY_SIZE, 0);

    public_key_len = strnlen_s(g_key_store[peer_key_slot].public_key, MAX_KEY_SIZE);
    if (public_key_len == EOK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error creating ecdh key failed in getting the size of the public key\n");
        return OVSA_CRYPTO_GENERIC_ERROR;
    }

    if (memcpy_s(peer_key, MAX_KEY_SIZE, g_key_store[peer_key_slot].public_key, public_key_len) !=
        EOK) {
        BIO_printf(g_bio_err, "LibOVSA: Error creating ecdh key failed in getting the peer key\n");
        return OVSA_MEMIO_ERROR;
    }

    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error creating ecdh key failed in getting the b64 encode method\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    shared_key_bio = BIO_new(BIO_s_mem());
    if (shared_key_bio == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error creating ecdh key failed in getting new BIO for the shared key\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    pkey = ovsa_crypto_load_key(private_key, "private key");
    if (pkey == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error creating ecdh key failed in loading private key into memory\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }

    ctx = ovsa_crypto_init_ctx(pkey);
    if (ctx == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error creating ecdh key failed in initializing context\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }

    peerkey = ovsa_crypto_load_key(peer_key, "peer key");
    if (peerkey == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error creating ecdh key failed in loading peer key into memory\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }

    if (ovsa_crypto_setup_peer(ctx, peerkey) <= 0) {
        BIO_printf(g_bio_err, "LibOVSA: Error creating ecdh key failed in setting up peer key\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }

    status = EVP_PKEY_derive(ctx, NULL, (size_t*)&buff_len);
    if (status > 0 && buff_len != 0) {
        buff =
            (unsigned char*)ovsa_crypto_app_malloc(buff_len + NULL_TERMINATOR, "shared_key buffer");
        if (buff == NULL) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error creating ecdh key failed in allocating memory for shared "
                       "key buffer\n");
            ret = OVSA_MEMORY_ALLOC_FAIL;
            goto end;
        }
        status = EVP_PKEY_derive(ctx, buff, (size_t*)&buff_len);
    }
    if (status <= 0) {
        BIO_puts(g_bio_err, "LibOVSA: Error creating ecdh key failed in deriving the key\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }

    shared_key_mem = shared_key_bio;
    shared_key_mem = BIO_push(b64, shared_key_mem);
    if (SHA512(buff, (size_t)buff_len, sha512) == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error creating ecdh key failed in computing the digest for shared key\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    if (!BIO_write(shared_key_mem, buff, buff_len)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error creating ecdh key failed in generating the shared key\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (!BIO_flush(shared_key_mem)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error creating ecdh key failed in flushing the shared key\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    BIO_get_mem_ptr(shared_key_mem, &shared_key_ptr);
    if (shared_key_ptr == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error creating ecdh key failed to extract the shared key\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    memset_s(shared_key, MAX_EKEY_SIZE, 0);

    if (memcpy_s(shared_key, MAX_EKEY_SIZE, shared_key_ptr->data, shared_key_ptr->length) != EOK) {
        BIO_printf(g_bio_err, "LibOVSA: Error creating ecdh key failed in getting shared key\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

    ret = ovsa_crypto_add_symmetric_keystore_array(shared_key, sym_key_slot);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error creating ecdh key failed in adding to symmetric keystore array\n");
    }

end:
    OPENSSL_cleanse(shared_key, MAX_EKEY_SIZE);
    OPENSSL_cleanse(peer_key, MAX_KEY_SIZE);
    OPENSSL_cleanse(private_key, MAX_KEY_SIZE);
    ovsa_crypto_openssl_free((char**)&buff);
    ovsa_crypto_openssl_free(&cert);
    EVP_PKEY_CTX_free(ctx);
    BIO_free(b64);
    BIO_free_all(shared_key_bio);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_add_symmetric_keystore_array(const char* symmetric_key,
                                                       int* sym_key_slot) {
    ovsa_status_t ret        = OVSA_OK;
    int symmetric_index      = 0;
    size_t symmetric_key_len = 0, sym_key_len = 0;

    if ((symmetric_key == NULL) || (sym_key_slot == NULL)) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error adding to symmetric keystore array failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    if (pthread_mutex_lock(&g_symmetric_index_lock) != 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error adding to symmetric keystore array failed in acquiring the "
                   "mutex with error code = %s\n",
                   strerror(errno));
        return OVSA_MUTEX_LOCK_FAIL;
    }

    symmetric_key_len = strnlen_s(symmetric_key, MAX_EKEY_SIZE);
    if (symmetric_key_len == EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error adding to symmetric keystore array failed in getting the size "
                   "of the symmetric key\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    for (symmetric_index = 0; symmetric_index < MAX_KEY_SLOT; symmetric_index++) {
        sym_key_len = strnlen_s(g_sym_key[symmetric_index], MAX_EKEY_SIZE);
        if (sym_key_len == 0) {
            if (memcpy_s(g_sym_key[symmetric_index], MAX_EKEY_SIZE, symmetric_key,
                         symmetric_key_len) != EOK) {
                BIO_printf(
                    g_bio_err,
                    "LibOVSA: Error adding to symmetric keystore array failed in getting the "
                    "symmetric key\n");
                ret = OVSA_MEMIO_ERROR;
                goto end;
            }

            *sym_key_slot = symmetric_index;
            break;
        } else {
            continue;
        }
    }

    if (symmetric_index == MAX_KEY_SLOT) {
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        BIO_printf(g_bio_err,
                   "LibOVSA: Error adding to symmetric keystore array failed since not able to "
                   "store the symmetric key\n");
        goto end;
    }

end:
    if (pthread_mutex_unlock(&g_symmetric_index_lock) != 0) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error adding to symmetric keystore array failed in releasing the "
                   "mutex with error code = %s\n",
                   strerror(errno));
        return OVSA_MUTEX_UNLOCK_FAIL;
    }

    return ret;
}

ovsa_status_t ovsa_crypto_generate_symmetric_key(int key_size, int* sym_key_slot) {
    ovsa_status_t ret = OVSA_OK;
    char symmetric_key[MAX_EKEY_SIZE];

    if ((key_size == 0) || (sym_key_slot == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating symmetric key failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    memset_s(symmetric_key, MAX_EKEY_SIZE, 0);

    ret = ovsa_crypto_RNG(key_size, symmetric_key);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error generating symmetric key failed in generating the symmetric key\n");
        return ret;
    }

    ret = ovsa_crypto_add_symmetric_keystore_array(symmetric_key, sym_key_slot);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating symmetric key failed in adding to symmetric keystore "
                   "array\n");
    }

    OPENSSL_cleanse(symmetric_key, MAX_EKEY_SIZE);
    return ret;
}

ovsa_status_t ovsa_crypto_derive_keyiv_hmac(int sym_key_slot, const char* in_buff,
                                            size_t in_buff_len, int* keyiv_hmac_slot) {
    int iklen = 0, ivlen = 0, hmaclen = 0, islen = 0;
    unsigned char tmpkeyiv_hmac[MAX_KEYIV_HMAC_LENGTH];
    static const char magic[] = "Salted__";
    ovsa_status_t ret         = OVSA_OK;
    const EVP_CIPHER* cipher  = NULL;
    BIO* read_mem             = NULL;
    BIO* read_bio             = NULL;
    BIO* keyiv_hmac_bio       = NULL;
    BIO* keyiv_hmac_write_bio = NULL;
    BIO* b64                  = NULL;
    BIO* keyiv_hmac_b64       = NULL;
    BUF_MEM* keyiv_hmac_ptr   = NULL;
    size_t secret_len         = 0;
    unsigned char salt[PKCS5_SALT_LEN];
    char mbuff[sizeof(magic) - 1];
    char secret[MAX_EKEY_SIZE];
    char keyiv_hmac[MAX_KEYIV_HMAC_LENGTH];

    if ((sym_key_slot < MIN_KEY_SLOT) || (sym_key_slot >= MAX_KEY_SLOT) || (in_buff == NULL) ||
        (in_buff_len == 0) || (keyiv_hmac_slot == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating key/IV/HMAC failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating key/IV/HMAC failed in getting the b64 encode "
                   "method\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    read_mem = BIO_new_mem_buf(in_buff, in_buff_len);
    if (read_mem == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating key/IV/HMAC failed in creating new BIO for the "
                   "input buffer\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    memset_s(salt, sizeof(salt), 0);
    memset_s(mbuff, sizeof(mbuff), 0);

    read_bio = read_mem;
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    read_bio = BIO_push(b64, read_bio);
    if (BIO_read(read_bio, mbuff, sizeof(mbuff)) != sizeof(mbuff) ||
        BIO_read(read_bio, (unsigned char*)salt, sizeof(salt)) != sizeof(salt)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating key/IV/HMAC failed in reading the input buffer\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    secret_len = strnlen_s(g_sym_key[sym_key_slot], MAX_EKEY_SIZE);
    if (secret_len == EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating key/IV/HMAC failed in getting the size of secret\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    memset_s(secret, MAX_EKEY_SIZE, 0);

    if (memcpy_s(secret, MAX_EKEY_SIZE, g_sym_key[sym_key_slot], secret_len) != EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating key/IV/HMAC failed in getting the secret\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

    memset_s(tmpkeyiv_hmac, MAX_KEYIV_HMAC_LENGTH, 0);

    cipher  = EVP_aes_256_ctr();
    iklen   = EVP_CIPHER_key_length(cipher);
    ivlen   = EVP_CIPHER_iv_length(cipher);
    hmaclen = EVP_CIPHER_key_length(cipher);
    islen   = (salt != NULL ? sizeof(salt) : 0);
    if (!PKCS5_PBKDF2_HMAC(secret, secret_len, salt, islen, PBKDF2_ITERATION_COUNT, EVP_sha384(),
                           iklen + ivlen + hmaclen, tmpkeyiv_hmac)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating key/IV/HMAC failed in deriving the key/iv\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    OPENSSL_cleanse(secret, secret_len);

    keyiv_hmac_write_bio = BIO_new(BIO_s_mem());
    if (keyiv_hmac_write_bio == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error generating key/IV/HMAC failed in getting new BIO for the keyiv_hmac\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if ((keyiv_hmac_b64 = BIO_new(BIO_f_base64())) == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating key/IV/HMAC failed in getting the b64 encode "
                   "method for keyiv_hmac\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    keyiv_hmac_bio = keyiv_hmac_write_bio;
    keyiv_hmac_bio = BIO_push(keyiv_hmac_b64, keyiv_hmac_bio);

    if (!BIO_write(keyiv_hmac_bio, tmpkeyiv_hmac, iklen + ivlen + hmaclen)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating key/IV/HMAC failed in writing to keyiv_hmac BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (!BIO_flush(keyiv_hmac_bio)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating key/IV/HMAC failed in flushing the keyiv_hmac BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    BIO_get_mem_ptr(keyiv_hmac_bio, &keyiv_hmac_ptr);
    if (keyiv_hmac_ptr == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating key/IV/HMAC failed to extract the keyiv_hmac BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    memset_s(keyiv_hmac, MAX_KEYIV_HMAC_LENGTH, 0);

    if (memcpy_s(keyiv_hmac, MAX_KEYIV_HMAC_LENGTH, keyiv_hmac_ptr->data, keyiv_hmac_ptr->length) !=
        EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating key/IV/HMAC failed in getting the key/IV/HMAC\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

    ret = ovsa_crypto_add_symmetric_keystore_array(keyiv_hmac, keyiv_hmac_slot);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating key/IV/HMAC failed in adding to symmetric keystore "
                   "array\n");
        goto end;
    }

end:
    OPENSSL_cleanse(keyiv_hmac, MAX_KEYIV_HMAC_LENGTH);
    OPENSSL_cleanse(tmpkeyiv_hmac, MAX_KEYIV_HMAC_LENGTH);
    OPENSSL_cleanse(salt, sizeof(salt));
    BIO_free(b64);
    BIO_free(keyiv_hmac_b64);
    BIO_free_all(read_mem);
    BIO_free_all(keyiv_hmac_write_bio);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_generate_salt(char* salt_buff, char* magic_salt_buff) {
    ovsa_status_t ret         = OVSA_OK;
    static const char magic[] = "Salted__";
    BUF_MEM* magic_salt_ptr   = NULL;
    BIO* magic_salt_bio       = NULL;
    BIO* write_bio            = NULL;
    BIO* b64                  = NULL;
    unsigned char salt[PKCS5_SALT_LEN];

    if (magic_salt_buff == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error generating salt failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    memset_s(salt, sizeof(salt), 0);

    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating salt failed in getting the b64 encode method\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    memset_s(salt, sizeof(salt), 0);
    if (salt_buff == NULL) {
        if (RAND_bytes(salt, sizeof(salt)) <= 0) {
            BIO_printf(g_bio_err, "LibOVSA: Error generating salt failed in generating the salt\n");
            ret = OVSA_CRYPTO_GENERIC_ERROR;
            goto end;
        }
    } else {
        if (memcpy_s(salt, PKCS5_SALT_LEN, salt_buff, sizeof(salt_buff)) != EOK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error generating salt failed in getting the salt buffer\n");
            ret = OVSA_MEMIO_ERROR;
            goto end;
        }
    }

    magic_salt_bio = BIO_new(BIO_s_mem());
    if (magic_salt_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating salt failed in getting new BIO for output buffer\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    write_bio = magic_salt_bio;
    write_bio = BIO_push(b64, write_bio);
    if (BIO_write(write_bio, magic, sizeof(magic) - 1) != sizeof(magic) - 1 ||
        BIO_write(write_bio, (char*)salt, sizeof(salt)) != sizeof(salt)) {
        BIO_printf(g_bio_err, "LibOVSA: Error generating salt failed in writing to write BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (!BIO_flush(write_bio)) {
        BIO_printf(g_bio_err, "LibOVSA: Error generating salt failed in flushing the write BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    BIO_get_mem_ptr(write_bio, &magic_salt_ptr);
    if (magic_salt_ptr == NULL) {
        BIO_printf(g_bio_err, "LibOVSA: Error generating salt failed to extract the magic/salt\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (memcpy_s(magic_salt_buff, MAX_MAGIC_SALT_LENGTH, magic_salt_ptr->data,
                 magic_salt_ptr->length) != EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error generating salt failed in getting the magic/salt buffer\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

end:
    OPENSSL_cleanse(salt, sizeof(salt));
    BIO_free(b64);
    BIO_free_all(magic_salt_bio);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_encrypt_mem(int sym_key_slot, const char* in_buff, size_t in_buff_len,
                                      char* magic_salt_buff_ptr, char** out_buff,
                                      size_t* out_buff_len, int* keyiv_hmac_slot) {
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    unsigned char tmpkeyiv_hmac[MAX_KEYIV_HMAC_LENGTH];
    int read_len = 0, iklen = 0, ivlen = 0;
    static const char magic[] = "Salted__";
    ovsa_status_t ret         = OVSA_OK;
    const EVP_CIPHER* cipher  = NULL;
    BUF_MEM* encrypt_ptr      = NULL;
    unsigned char* buff       = NULL;
    EVP_CIPHER_CTX* ctx       = NULL;
    BIO* cipher_bio           = NULL;
    BIO* write_bio            = NULL;
    BIO* read_bio             = NULL;
    BIO* keyiv_hmac_bio       = NULL;
    BIO* keyiv_hmac_read_bio  = NULL;
    BIO* benc                 = NULL;
    BIO* b64                  = NULL;
    BIO* keyiv_hmac_b64       = NULL;
    BIO* magic_salt_bio       = NULL;
    BIO* magic_salt_read_bio  = NULL;
    BIO* magic_salt_b64       = NULL;
    size_t keyiv_hmac_len = 0, magic_salt_len = 0;
    size_t magic_salt_buff_len = 0, magic_salt_buff_ptr_len = 0;
    char magic_salt[MAX_MAGIC_SALT_LENGTH];
    char magic_salt_buff[MAX_MAGIC_SALT_LENGTH];

    if ((sym_key_slot < MIN_KEY_SLOT) || (sym_key_slot >= MAX_KEY_SLOT) || (in_buff == NULL) ||
        (in_buff_len == 0) || (out_buff == NULL) || (out_buff_len == NULL) ||
        (keyiv_hmac_slot == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting the memory buffer failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting the memory buffer failed in getting the b64 encode "
                   "method\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    read_bio = BIO_new_mem_buf(in_buff, in_buff_len);
    if (read_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting the memory buffer failed in creating new BIO for the "
                   "input buffer\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    memset_s(magic_salt, sizeof(magic_salt), 0);
    memset_s(magic_salt_buff, sizeof(magic_salt_buff), 0);
    if (magic_salt_buff_ptr == NULL) {
        ret = ovsa_crypto_generate_salt(NULL, magic_salt_buff);
        if (ret < OVSA_OK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error encrypting the memory buffer failed in generating salt\n");
            goto end;
        }
    } else {
        magic_salt_buff_ptr_len = strnlen_s(magic_salt_buff_ptr, MAX_MAGIC_SALT_LENGTH);
        if (magic_salt_buff_ptr_len == EOK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error encrypting the memory buffer failed in getting the size of "
                       "the magic_salt buffer\n");
            ret = OVSA_CRYPTO_GENERIC_ERROR;
            goto end;
        }

        if (memcpy_s(magic_salt_buff, MAX_MAGIC_SALT_LENGTH, magic_salt_buff_ptr,
                     magic_salt_buff_ptr_len) != EOK) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error encrypting the memory buffer failed to get the magic_salt "
                       "buffer\n");
            ret = OVSA_MEMIO_ERROR;
            goto end;
        }
    }

    magic_salt_read_bio = BIO_new(BIO_s_mem());
    if (magic_salt_read_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting the memory buffer failed in getting new BIO for the "
                   "magic_salt\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    magic_salt_bio = magic_salt_read_bio;
    if (BIO_puts(magic_salt_read_bio, magic_salt_buff) <= 0) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error encrypting the memory buffer failed in writing to magic_salt BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if ((magic_salt_b64 = BIO_new(BIO_f_base64())) == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting the memory buffer failed in getting the b64 encode "
                   "method for magic_salt\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    BIO_set_flags(magic_salt_b64, BIO_FLAGS_BASE64_NO_NL);
    magic_salt_bio      = BIO_push(magic_salt_b64, magic_salt_bio);
    magic_salt_buff_len = strnlen_s(magic_salt_buff, MAX_MAGIC_SALT_LENGTH);
    if (magic_salt_buff_len == EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting the memory buffer failed in getting the size for "
                   "magic_salt\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    magic_salt_len = BIO_read(magic_salt_bio, magic_salt, magic_salt_buff_len);
    if (magic_salt_len <= 0) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error encrypting the memory buffer failed in reading to magic_salt BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    write_bio = BIO_new(BIO_s_mem());
    if (write_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting the memory buffer failed in getting new BIO for "
                   "output buffer\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    cipher_bio = write_bio;
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    cipher_bio = BIO_push(b64, cipher_bio);

    /* Write magic and salt to the cipher BIO */
    if (BIO_write(cipher_bio, magic_salt, sizeof(magic) - 1) != sizeof(magic) - 1 ||
        BIO_write(cipher_bio, magic_salt + (sizeof(magic) - 1), PKCS5_SALT_LEN) != PKCS5_SALT_LEN) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting the memory buffer failed in writing to cipher BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    ret = ovsa_crypto_derive_keyiv_hmac(sym_key_slot, magic_salt_buff, magic_salt_buff_len,
                                        keyiv_hmac_slot);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error encrypting the memory buffer failed in deriving the key/IV/HMAC\n");
        goto end;
    }

    cipher = EVP_aes_256_ctr();
    iklen  = EVP_CIPHER_key_length(cipher);
    ivlen  = EVP_CIPHER_iv_length(cipher);

    memset_s(tmpkeyiv_hmac, MAX_KEYIV_HMAC_LENGTH, 0);
    memset_s(key, EVP_MAX_KEY_LENGTH, 0);
    memset_s(iv, EVP_MAX_IV_LENGTH, 0);

    keyiv_hmac_read_bio = BIO_new(BIO_s_mem());
    if (keyiv_hmac_read_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting the memory buffer failed in getting new BIO for the "
                   "keyiv_hmac buffer\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    keyiv_hmac_bio = keyiv_hmac_read_bio;
    if (BIO_puts(keyiv_hmac_read_bio, g_sym_key[*keyiv_hmac_slot]) <= 0) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error encrypting the memory buffer failed in writing to keyiv_hmac BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if ((keyiv_hmac_b64 = BIO_new(BIO_f_base64())) == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting the memory buffer failed in getting the b64 encode "
                   "method for keyiv_hmac\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    keyiv_hmac_bio = BIO_push(keyiv_hmac_b64, keyiv_hmac_bio);
    keyiv_hmac_len = strnlen_s(g_sym_key[*keyiv_hmac_slot], MAX_KEYIV_HMAC_LENGTH);
    if (keyiv_hmac_len == EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting the memory buffer failed in getting the size for "
                   "keyiv_hmac\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    keyiv_hmac_len = BIO_read(keyiv_hmac_bio, tmpkeyiv_hmac, keyiv_hmac_len);
    if (keyiv_hmac_len <= 0) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error encrypting the memory buffer failed in reading to keyiv_hmac BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    /* Split and move data back to buffer */
    if (memcpy_s(key, EVP_MAX_KEY_LENGTH, tmpkeyiv_hmac, iklen) != EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting the memory buffer failed in getting the key\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

    if (memcpy_s(iv, EVP_MAX_IV_LENGTH, tmpkeyiv_hmac + EVP_CIPHER_key_length(cipher), ivlen) !=
        EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting the memory buffer failed in getting the iv\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

    if ((benc = BIO_new(BIO_f_cipher())) == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error encrypting the memory buffer failed in getting the cipher BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    BIO_get_cipher_ctx(benc, &ctx);
    if (!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, 1)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting the memory buffer failed in setting the cipher\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }

    if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 1)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting the memory buffer failed in setting the key/iv\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }

    if (benc != NULL) {
        cipher_bio = BIO_push(benc, cipher_bio);
    }

    buff = ovsa_crypto_app_malloc(EVP_ENCODE_LENGTH(BUFSIZE), "evp encrypt_mem buffer");
    if (buff == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting the memory buffer failed in allocating memory for "
                   "evp encrypt buffer\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    while (BIO_pending(read_bio) || !BIO_eof(read_bio)) {
        read_len = BIO_read(read_bio, (char*)buff, BUFSIZE);
        if (read_len <= 0) {
            break;
        }
        if (BIO_write(cipher_bio, (char*)buff, read_len) != read_len) {
            BIO_printf(
                g_bio_err,
                "LibOVSA: Error encrypting the memory buffer failed in writing to cipher BIO\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }
    }

    if (!BIO_flush(cipher_bio)) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error encrypting the memory buffer failed in flushing the cipher BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    BIO_get_mem_ptr(cipher_bio, &encrypt_ptr);
    if (encrypt_ptr == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error encrypting the memory buffer failed to extract the cipher BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    /* App needs to free this memory */
    *out_buff = ovsa_crypto_app_malloc(encrypt_ptr->length + NULL_TERMINATOR, "encrypted buffer");
    if (*out_buff == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting the memory buffer failed in allocating memory for "
                   "encrypted buffer\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    *out_buff_len = encrypt_ptr->length;
    if (memcpy_s(*out_buff, encrypt_ptr->length, encrypt_ptr->data, encrypt_ptr->length) != EOK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error encrypting the memory buffer failed in getting the output buffer\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

end:
    OPENSSL_cleanse(tmpkeyiv_hmac, MAX_KEYIV_HMAC_LENGTH);
    OPENSSL_cleanse(key, EVP_MAX_KEY_LENGTH);
    OPENSSL_cleanse(iv, EVP_MAX_IV_LENGTH);
    OPENSSL_cleanse(magic_salt, sizeof(magic_salt));
    OPENSSL_cleanse(magic_salt_buff, sizeof(magic_salt_buff));
    if (magic_salt_buff_ptr != NULL) {
        OPENSSL_cleanse(magic_salt_buff_ptr, magic_salt_buff_ptr_len);
    }
    ovsa_crypto_openssl_free((char**)&buff);
    BIO_free(benc);
    BIO_free(b64);
    BIO_free(magic_salt_b64);
    BIO_free(keyiv_hmac_b64);
    BIO_free_all(write_bio);
    BIO_free_all(read_bio);
    BIO_free_all(keyiv_hmac_read_bio);
    BIO_free_all(magic_salt_read_bio);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_decrypt_mem(int sym_key_slot, const char* in_buff, size_t in_buff_len,
                                      char** out_buff, size_t* out_buff_len, int* keyiv_hmac_slot) {
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    unsigned char tmpkeyiv_hmac[MAX_KEYIV_HMAC_LENGTH];
    int read_len = 0, iklen = 0, ivlen = 0;
    static const char magic[] = "Salted__";
    ovsa_status_t ret         = OVSA_OK;
    const EVP_CIPHER* cipher  = NULL;
    BIO* keyiv_hmac_read_bio  = NULL;
    BUF_MEM* decrypt_ptr      = NULL;
    BIO* keyiv_hmac_bio       = NULL;
    unsigned char* buff       = NULL;
    EVP_CIPHER_CTX* ctx       = NULL;
    BIO* keyiv_hmac_b64       = NULL;
    BIO* decrypt_bio          = NULL;
    BIO* write_bio            = NULL;
    BIO* read_mem             = NULL;
    BIO* read_bio             = NULL;
    BIO* benc                 = NULL;
    BIO* b64                  = NULL;
    size_t keyiv_hmac_len     = 0;
    unsigned char salt[PKCS5_SALT_LEN];
    char mbuff[sizeof(magic) - 1];

    if ((sym_key_slot < 0) || (sym_key_slot >= MAX_KEY_SLOT) || (in_buff == NULL) ||
        (in_buff_len == 0) || (out_buff == NULL) || (out_buff_len == NULL) ||
        (keyiv_hmac_slot == NULL)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error decrypting the memory buffer failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error decrypting the memory buffer failed in getting the b64 encode "
                   "method\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    read_mem = BIO_new_mem_buf(in_buff, in_buff_len);
    if (read_mem == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error decrypting the memory buffer failed in creating new BIO for the "
                   "input buffer\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    memset_s(salt, sizeof(salt), 0);
    memset_s(mbuff, sizeof(mbuff), 0);

    read_bio = read_mem;
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    read_bio = BIO_push(b64, read_bio);
    if (BIO_read(read_bio, mbuff, sizeof(mbuff)) != sizeof(mbuff) ||
        BIO_read(read_bio, (unsigned char*)salt, sizeof(salt)) != sizeof(salt)) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error decrypting the memory buffer failed in reading the input file\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    ret = ovsa_crypto_derive_keyiv_hmac(sym_key_slot, in_buff, in_buff_len, keyiv_hmac_slot);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error decrypting the memory buffer failed in deriving the key/IV/HMAC\n");
        goto end;
    }

    cipher = EVP_aes_256_ctr();
    iklen  = EVP_CIPHER_key_length(cipher);
    ivlen  = EVP_CIPHER_iv_length(cipher);

    memset_s(tmpkeyiv_hmac, MAX_KEYIV_HMAC_LENGTH, 0);
    memset_s(key, EVP_MAX_KEY_LENGTH, 0);
    memset_s(iv, EVP_MAX_IV_LENGTH, 0);

    keyiv_hmac_read_bio = BIO_new(BIO_s_mem());
    if (keyiv_hmac_read_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error decrypting the memory buffer failed in getting new BIO for the "
                   "keyiv_hmac buffer\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    keyiv_hmac_bio = keyiv_hmac_read_bio;
    if (BIO_puts(keyiv_hmac_read_bio, g_sym_key[*keyiv_hmac_slot]) <= 0) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error decrypting the memory buffer failed in writing to keyiv_hmac BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if ((keyiv_hmac_b64 = BIO_new(BIO_f_base64())) == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error decrypting the memory buffer failed in getting the b64 encode "
                   "method for keyiv_hmac\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    keyiv_hmac_bio = BIO_push(keyiv_hmac_b64, keyiv_hmac_bio);
    keyiv_hmac_len = strnlen_s(g_sym_key[*keyiv_hmac_slot], MAX_KEYIV_HMAC_LENGTH);
    if (keyiv_hmac_len == EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error decrypting the memory buffer failed in getting the size for "
                   "keyiv_hmac\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    keyiv_hmac_len = BIO_read(keyiv_hmac_bio, tmpkeyiv_hmac, keyiv_hmac_len);
    if (keyiv_hmac_len <= 0) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error decrypting the memory buffer failed in reading to keyiv_hmac BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    /* Split and move data back to buffer */
    if (memcpy_s(key, EVP_MAX_KEY_LENGTH, tmpkeyiv_hmac, iklen) != EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error decrypting the memory buffer failed in getting the key\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

    if (memcpy_s(iv, EVP_MAX_IV_LENGTH, tmpkeyiv_hmac + EVP_CIPHER_key_length(cipher), ivlen) !=
        EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error decrypting the memory buffer failed in getting the iv\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

    write_bio = BIO_new(BIO_s_mem());
    if (write_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error decrypting the memory buffer failed in getting new BIO for "
                   "output buffer\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    decrypt_bio = write_bio;
    if ((benc = BIO_new(BIO_f_cipher())) == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error decrypting the memory buffer failed in getting the cipher BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    BIO_get_cipher_ctx(benc, &ctx);
    if (!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, 0)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error decrypting the memory buffer failed in setting the cipher\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }

    if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 0)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error decrypting the memory buffer failed in setting the key/iv\n");
        ret = OVSA_CRYPTO_EVP_ERROR;
        goto end;
    }

    if (benc != NULL) {
        decrypt_bio = BIO_push(benc, decrypt_bio);
    }

    buff = ovsa_crypto_app_malloc(EVP_ENCODE_LENGTH(BUFSIZE), "evp decrypt_mem buffer");
    if (buff == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error decrypting the memory buffer failed in allocating memory for "
                   "evp decrypt buffer\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    while (BIO_pending(read_bio) || !BIO_eof(read_bio)) {
        read_len = BIO_read(read_bio, (char*)buff, BUFSIZE);
        if (read_len <= 0) {
            break;
        }
        if (BIO_write(decrypt_bio, (char*)buff, read_len) != read_len) {
            BIO_printf(
                g_bio_err,
                "LibOVSA: Error decrypting the memory buffer failed in writing to decrypt BIO\n");
            ret = OVSA_CRYPTO_BIO_ERROR;
            goto end;
        }
    }

    if (!BIO_flush(decrypt_bio)) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error decrypting the memory buffer failed in flushing the decrypt BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    BIO_get_mem_ptr(decrypt_bio, &decrypt_ptr);
    if (decrypt_ptr == NULL) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error decrypting the memory buffer failed to extract the decrypt BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    /* App needs to free this memory */
    *out_buff = ovsa_crypto_app_malloc(decrypt_ptr->length + NULL_TERMINATOR, "decrypted buffer");
    if (*out_buff == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error decrypting the memory buffer failed in allocating memory for "
                   "decrypted buffer\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    *out_buff_len = decrypt_ptr->length;
    if (memcpy_s(*out_buff, decrypt_ptr->length, decrypt_ptr->data, decrypt_ptr->length) != EOK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error decrypting the memory buffer failed in getting the output buffer\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

end:
    OPENSSL_cleanse(tmpkeyiv_hmac, MAX_KEYIV_HMAC_LENGTH);
    OPENSSL_cleanse(key, EVP_MAX_KEY_LENGTH);
    OPENSSL_cleanse(iv, EVP_MAX_IV_LENGTH);
    OPENSSL_cleanse(salt, sizeof(salt));
    ovsa_crypto_openssl_free((char**)&buff);
    BIO_free_all(keyiv_hmac_read_bio);
    BIO_free(keyiv_hmac_b64);
    BIO_free(b64);
    BIO_free_all(read_mem);
    BIO_free(benc);
    BIO_free_all(write_bio);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_derive_unsealing_key(char* magic_salt_buff, int* sym_key_slot) {
    ovsa_status_t ret         = OVSA_OK;
    size_t encryption_key_len = 0, encryption_key_b64_len = 0;
    char salt[PKCS5_SALT_LEN];
    char password[SYMMETRIC_KEY_SIZE];
    char encryption_key[MAX_EKEY_SIZE];
    char encryption_key_b64[MAX_EKEY_SIZE];

    if ((magic_salt_buff == NULL) || (sym_key_slot == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error unsealing key failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    memset_s(encryption_key_b64, sizeof(encryption_key_b64), 0);
    memset_s(encryption_key, sizeof(encryption_key), 0);

    ret = ovsa_tpm2_unsealkey(encryption_key_b64);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error unsealing key failed in unsealing the encryption key\n");
        goto end;
    }

    encryption_key_b64_len = strnlen_s(encryption_key_b64, MAX_EKEY_SIZE);
    if (encryption_key_b64_len == EOK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error unsealing key failed in getting the size of the encryption key\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    ret = ovsa_crypto_convert_base64_to_bin(encryption_key_b64, encryption_key_b64_len,
                                            encryption_key, &encryption_key_len);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error unsealing key failed in converting from base64 to bin\n");
        goto end;
    }

    memset_s(salt, sizeof(salt), 0);
    if (memcpy_s(salt, PKCS5_SALT_LEN, encryption_key, PKCS5_SALT_LEN) != EOK) {
        BIO_printf(g_bio_err, "LibOVSA: Error unsealing key failed in getting the salt\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

    memset_s(password, SYMMETRIC_KEY_SIZE, 0);
    if (memcpy_s(password, SYMMETRIC_KEY_SIZE, encryption_key + PKCS5_SALT_LEN,
                 SYMMETRIC_KEY_SIZE) != EOK) {
        BIO_printf(g_bio_err, "LibOVSA: Error unsealing key failed in getting the password\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

    ret = ovsa_crypto_add_symmetric_keystore_array(password, sym_key_slot);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error unsealing key failed in adding to symmetric keystore "
                   "array\n");
        goto end;
    }

    ret = ovsa_crypto_generate_salt(salt, magic_salt_buff);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err, "LibOVSA: unsealing key failed in getting the magic_salt buffer\n");
        goto end;
    }

end:
    OPENSSL_cleanse(password, SYMMETRIC_KEY_SIZE);
    OPENSSL_cleanse(salt, sizeof(salt));
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }

    return ret;
}

ovsa_status_t ovsa_crypto_encrypt_keystore(int sym_key_slot, const char* enc_keystore_name,
                                           const char* in_buff, size_t in_buff_len,
                                           char* magic_salt_buff) {
    char* enc_keystore_hmac_buff  = NULL;
    char* enc_keystore_buff       = NULL;
    BIO* enc_keystore_bio         = NULL;
    char* encrypt_buff            = NULL;
    ovsa_status_t ret             = OVSA_OK;
    int keyiv_hmac_slot           = -1;
    size_t enc_keystore_hmac_size = 0, enc_keystore_buff_len = 0;
    size_t enc_keystore_size = 0, encrypt_buff_len = 0, cert_len = 0;

    if ((sym_key_slot < MIN_KEY_SLOT) || (sym_key_slot >= MAX_KEY_SLOT) ||
        (enc_keystore_name == NULL) || (in_buff == NULL) || (in_buff_len == 0) ||
        (magic_salt_buff == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error encrypting keystore failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    ret = ovsa_crypto_encrypt_mem(sym_key_slot, in_buff, in_buff_len, magic_salt_buff,
                                  &encrypt_buff, &encrypt_buff_len, &keyiv_hmac_slot);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting keystore failed in encrypting the memory buffer\n");
        goto end;
    }

    enc_keystore_size = encrypt_buff_len + ENC_KEYSTORE_BLOB_TEXT_SIZE;
    enc_keystore_buff =
        (char*)ovsa_crypto_app_malloc(enc_keystore_size, "encrypted keystore buffer");
    if (enc_keystore_buff == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting keystore failed in allocating memory for "
                   "encrypted keysore buffer\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    ret = ovsa_json_create_encrypted_keystore(encrypt_buff, enc_keystore_buff);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting keystore failed in creating the encrypted keystore "
                   "json blob\n");
        goto end;
    }

    enc_keystore_hmac_size =
        encrypt_buff_len + ENC_KEYSTORE_BLOB_TEXT_SIZE + MAX_MAC_SIZE + SIGNATURE_BLOB_TEXT_SIZE;
    enc_keystore_hmac_buff =
        (char*)ovsa_crypto_app_malloc(enc_keystore_hmac_size, "encrypted keystore_hmac buffer");
    if (enc_keystore_hmac_buff == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting keystore failed in allocating memory for "
                   "encrypted keysore_hmac buffer\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    ret = ovsa_crypto_hmac_json_blob(keyiv_hmac_slot, enc_keystore_buff, enc_keystore_size,
                                     enc_keystore_hmac_buff);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error encrypting keystore failed in computing the hmac for json blob\n");
        goto end;
    }

    ret = ovsa_get_string_length(enc_keystore_hmac_buff, &enc_keystore_buff_len);
    if ((ret < OVSA_OK) || (enc_keystore_buff_len == EOK)) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting keystore failed in getting the size of "
                   "the encrypted keystore buffer\n");
        ret = OVSA_CRYPTO_GENERIC_ERROR;
        goto end;
    }

    ret = ovsa_json_getitem_size("certificate", in_buff, &cert_len);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error loading asymmetric key failed in getting the certificate size\n");
        goto end;
    }

    /*
     * Create keystore in protected write mode, so that existing keystore will not be over
     * written. Open the existing keystore in write mode for writing the certificate.
     */
    if (cert_len != 0) {
        enc_keystore_bio = BIO_new_file(enc_keystore_name, "w");
    } else {
        enc_keystore_bio = BIO_new_file(enc_keystore_name, "wx");
    }
    if (enc_keystore_bio == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error encrypting keystore failed in creating the encrypted keystore "
                   "file\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    /* Write encrypted keystore file on to disk */
    if (!BIO_write(enc_keystore_bio, enc_keystore_hmac_buff, enc_keystore_buff_len)) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error encrypting keystore failed in writing to encrypted keystore file\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

end:
    /* Clear key/IV/HMAC from the key slot */
    ovsa_crypto_clear_symmetric_key_slot(keyiv_hmac_slot);
    /* Clear symmetric key from the key slot */
    ovsa_crypto_clear_symmetric_key_slot(sym_key_slot);
    ovsa_crypto_openssl_free(&enc_keystore_hmac_buff);
    ovsa_crypto_openssl_free(&enc_keystore_buff);
    ovsa_crypto_openssl_free(&encrypt_buff);
    BIO_free_all(enc_keystore_bio);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}

ovsa_status_t ovsa_crypto_decrypt_keystore(int sym_key_slot, const char* in_buff,
                                           size_t in_buff_len, const char* magic_salt_buff,
                                           char** out_buff, size_t* out_buff_len) {
    char* enc_keystore_buff    = NULL;
    ovsa_status_t ret          = OVSA_OK;
    int keyiv_hmac_slot        = -1;
    size_t magic_salt_buff_len = 0, encrypted_buff_len = 0;
    ovsa_enc_keystore_t enc_keystore;

    if ((sym_key_slot < MIN_KEY_SLOT) || (sym_key_slot >= MAX_KEY_SLOT) || (in_buff == NULL) ||
        (in_buff_len == 0) || (magic_salt_buff == NULL) || (out_buff == NULL) ||
        (out_buff_len == NULL)) {
        BIO_printf(g_bio_err, "LibOVSA: Error decrypting keystore failed with invalid parameter\n");
        return OVSA_INVALID_PARAMETER;
    }

    memset_s(&enc_keystore, sizeof(ovsa_enc_keystore_t), 0);
    magic_salt_buff_len = strnlen_s(magic_salt_buff, MAX_MAGIC_SALT_LENGTH);
    if (magic_salt_buff_len == EOK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error decrypting keystore failed in getting the size of the "
                   "magic/salt buffer\n");
        return OVSA_CRYPTO_GENERIC_ERROR;
    }

    /* Extract salt from magic_salt buffer and derive key/IV/HMAC for the encrypted keystore */
    ret = ovsa_crypto_derive_keyiv_hmac(sym_key_slot, magic_salt_buff, magic_salt_buff_len,
                                        &keyiv_hmac_slot);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error decrypting keystore failed in deriving key/IV/HMAC\n");
        goto end;
    }

    enc_keystore_buff = (char*)ovsa_crypto_app_malloc(in_buff_len, "encrypted keystore buffer");
    if (enc_keystore_buff == NULL) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error decrypting keystore failed in allocating memory for "
                   "encrypted keysore buffer with hmac element\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    ret =
        ovsa_crypto_verify_hmac_json_blob(keyiv_hmac_slot, in_buff, in_buff_len, enc_keystore_buff);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error decrypting keystore failed in verifying the hmac json blob\n");
        goto end;
    }

    /* Clear key/IV/HMAC from the keyslot */
    ovsa_crypto_clear_symmetric_key_slot(keyiv_hmac_slot);

    ret = ovsa_json_getitem_size("keystore", enc_keystore_buff, &encrypted_buff_len);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error decrypting keystore failed in getting the encrypted keystore size\n");
        goto end;
    }

    if (encrypted_buff_len != 0) {
        enc_keystore.keystore = (char*)ovsa_crypto_app_malloc(encrypted_buff_len + NULL_TERMINATOR,
                                                              "encrypted keystore");
        if (enc_keystore.keystore == NULL) {
            BIO_printf(g_bio_err,
                       "LibOVSA: Error decrypting keystore failed in allocating memory for "
                       "encrypted keystore\n");
            ret = OVSA_MEMORY_ALLOC_FAIL;
            goto end;
        }
    }

    ret = ovsa_json_extract_encrypted_keystore(enc_keystore_buff, &enc_keystore);
    if (ret < OVSA_OK) {
        BIO_printf(
            g_bio_err,
            "LibOVSA: Error decrypting keystore failed in extracting the encrypted keystore\n");
        goto end;
    }

    ret = ovsa_crypto_decrypt_mem(sym_key_slot, enc_keystore.keystore, encrypted_buff_len, out_buff,
                                  out_buff_len, &keyiv_hmac_slot);
    if (ret < OVSA_OK) {
        BIO_printf(g_bio_err,
                   "LibOVSA: Error decrypting keystore failed in decrypting the memory buffer\n");
        goto end;
    }

end:
    /* Clear key/IV/HMAC from the keyslot */
    ovsa_crypto_clear_symmetric_key_slot(keyiv_hmac_slot);
    /* Clear symmetric key from the keyslot */
    ovsa_crypto_clear_symmetric_key_slot(sym_key_slot);
    ovsa_crypto_openssl_free(&enc_keystore_buff);
    ovsa_crypto_openssl_free(&enc_keystore.keystore);
    if (ret < OVSA_OK) {
        ERR_print_errors(g_bio_err);
    }
    return ret;
}
