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

#include <dirent.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "cJSON.h"
#include "json.h"
#include "ovsa.h"
#include "safe_mem_lib.h"
#include "safe_str_lib.h"

ovsa_status_t ovsa_get_string_length(const char* in_buff, size_t* in_buff_len) {
    ovsa_status_t ret = OVSA_OK;
    size_t total_len = 0, buff_len = 0;

    if (in_buff == NULL) {
        OVSA_DBG(DBG_E, "Error: Getting string length failed with invalid parameter\n");
        ret = OVSA_INVALID_PARAMETER;
        return ret;
    }

    buff_len = strnlen_s(in_buff, RSIZE_MAX_STR);
    if (buff_len < RSIZE_MAX_STR) {
        *in_buff_len = buff_len;
    } else {
        while (buff_len == RSIZE_MAX_STR) {
            total_len += RSIZE_MAX_STR;

            buff_len = strnlen_s((in_buff + total_len), RSIZE_MAX_STR);
            if (buff_len < RSIZE_MAX_STR) {
                total_len += buff_len;
                break;
            }
        }
        *in_buff_len = total_len;
    }

    return ret;
}

ovsa_host_cmd_t ovsa_get_command_type(const char* command) {
    size_t len          = 0;
    int ind             = 0;
    ovsa_host_cmd_t cmd = OVSA_INVALID_CMD;

    len = ovsa_get_string_length(command, &len);

    strcmp_s(command, len, "OVSA_SEND_HW_QUOTE", &ind);
    if (ind == 0)
        cmd = OVSA_SEND_HW_QUOTE;

    return cmd;
}

void ovsa_safe_free(char** ptr) {
    size_t ptr_len = 0;

    if (*ptr != NULL) {
        ovsa_get_string_length(*ptr, &ptr_len);
        memset_s(*ptr, ptr_len, 0);
        free(*ptr);
        *ptr = NULL;
    }

    return;
}

ovsa_status_t ovsa_safe_malloc(size_t size, char** aloc_buf) {
    ovsa_status_t ret = OVSA_OK;

    *aloc_buf = (char*)malloc(size * sizeof(char));
    if (*aloc_buf == NULL) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "Error: Buffer allocation failed with code %d\n", ret);
        goto out;
    }
    memset_s(*aloc_buf, (size) * sizeof(char), 0);
out:
    return ret;
}

ovsa_status_t ovsa_socket_read(int sockfd, char* buf, size_t len) {
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

void ovsa_safe_free_hw_quote_info(ovsa_hw_quote_info_t** hw_quote_info) {
    ovsa_hw_quote_info_t* quote_info;

    quote_info = *hw_quote_info;

    ovsa_safe_free(&quote_info->hw_quote_message);
    ovsa_safe_free(&quote_info->hw_quote_sig);
    ovsa_safe_free(&quote_info->hw_quote_pcr);
    ovsa_safe_free(&quote_info->hw_ak_pub_key);
    ovsa_safe_free(&quote_info->hw_ek_pub_key);
    ovsa_safe_free(&quote_info->hw_ek_cert);
    ovsa_safe_free((char**)&quote_info);
}

ovsa_status_t ovsa_socket_write(int sockfd, const char* buf, size_t len) {
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
            OVSA_DBG(DBG_E, "Write failure over socket with error %s\n", strerror(errno));
            ret = OVSA_SOCKET_WRITE_FAIL;
        }
    }
    return ret;
}

static bool ovsa_check_if_file_exists(const char* filename) {
    if (access(filename, F_OK) != -1)
        return true;
    else
        return false;
}

int ovsa_get_file_size(FILE* fp) {
    size_t file_size = 0;
    int ret          = 0;

    if (!(fseek(fp, 0L, SEEK_END) == 0)) {
        OVSA_DBG(DBG_E, "Error: Getting file size failed with error %s\n", strerror(errno));
        goto end;
    }

    file_size = ftell(fp);
    if (file_size == 0) {
        OVSA_DBG(DBG_E, "Error: Getting file size failed with error %s\n", strerror(errno));
        goto end;
    }

    if (fseek(fp, 0L, SEEK_SET) != 0) {
        OVSA_DBG(DBG_E,
                 "Error: Getting file size failed in giving the current "
                 "position of the fp\n");
        goto end;
    }

    ret = file_size + 1;
end:
    return ret;
}

ovsa_status_t ovsa_convert_bin_to_pem(const char* in_buff, size_t in_buff_len, char** out_buff) {
    ovsa_status_t ret      = OVSA_OK;
    BIO* pem_bio           = NULL;
    BIO* write_bio         = NULL;
    BIO* b64               = NULL;
    BUF_MEM* pem_write_ptr = NULL;

    if ((in_buff == NULL) || (in_buff_len == 0)) {
        OVSA_DBG(DBG_E, "Error: Converting bin to pem failed with invalid parameter\n");
        ret = OVSA_INVALID_PARAMETER;
        return ret;
    }

    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        OVSA_DBG(DBG_E,
                 "Error: Converting bin to pem failed in getting the b64 encode "
                 "method\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    pem_bio = BIO_new(BIO_s_mem());
    if (pem_bio == NULL) {
        OVSA_DBG(DBG_E, "Error: Converting bin to pem failed in getting new BIO for the pem\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    write_bio = pem_bio;
    write_bio = BIO_push(b64, write_bio);

    if (!BIO_write(write_bio, in_buff, in_buff_len)) {
        OVSA_DBG(DBG_E, "Error: Converting bin to pem failed in writing to pem BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    if (!BIO_flush(write_bio)) {
        OVSA_DBG(DBG_E, "Error: Converting bin to pem failed in flushing the pem BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    BIO_get_mem_ptr(write_bio, &pem_write_ptr);
    if (pem_write_ptr == NULL) {
        OVSA_DBG(DBG_E, "Error: Converting bin to pem failed to extract the pem BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }

    /* App needs to free this memory */
    ret = ovsa_safe_malloc(pem_write_ptr->length + 1, out_buff);
    if (ret != OVSA_OK) {
        OVSA_DBG(DBG_E,
                 "Error: Converting bin to pem failed in allocating memory for "
                 "pem buffer\n");
        ret = OVSA_MEMORY_ALLOC_FAIL;
        goto end;
    }

    if (memcpy_s(*out_buff, pem_write_ptr->length, pem_write_ptr->data, pem_write_ptr->length) !=
        EOK) {
        OVSA_DBG(DBG_E, "Error: Converting bin to pem failed in getting the output buffer\n");
        ret = OVSA_MEMIO_ERROR;
        goto end;
    }

end:
    BIO_free(b64);
    BIO_free_all(pem_bio);
    return ret;
}

ovsa_status_t ovsa_crypto_convert_base64_to_bin(const char* in_buff, size_t in_buff_len,
                                                char* out_buff, size_t* out_buff_len) {
    ovsa_status_t ret = OVSA_OK;
    BIO* bin_bio      = NULL;
    BIO* write_bio    = NULL;
    BIO* b64          = NULL;
    size_t bin_len    = 0;

    if ((in_buff == NULL) || (in_buff_len == 0) || (out_buff == NULL)) {
        OVSA_DBG(DBG_E, "Error: Converting pem to bin failed with invalid parameter\n");
        ret = OVSA_INVALID_PARAMETER;
        return ret;
    }

    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        OVSA_DBG(DBG_E,
                 "Error: Converting pem to bin failed in getting the b64 encode "
                 "method\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }
    bin_bio = BIO_new_mem_buf(in_buff, in_buff_len);
    if (bin_bio == NULL) {
        OVSA_DBG(DBG_E, "Error: Converting pem to bin failed in writing to bin BIO\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }
    write_bio = bin_bio;
    write_bio = BIO_push(b64, write_bio);
    bin_len   = BIO_read(write_bio, out_buff, in_buff_len);
    if (bin_len <= 0) {
        OVSA_DBG(DBG_E, "Error: Converting pem to bin failed in reading the bin\n");
        ret = OVSA_CRYPTO_BIO_ERROR;
        goto end;
    }
    *out_buff_len = bin_len;

end:
    BIO_free(b64);
    BIO_free_all(bin_bio);
    return ret;
}

ovsa_status_t ovsa_read_file_content(const char* filename, char** filecontent, size_t* filesize) {
    ovsa_status_t ret = OVSA_OK;
    size_t file_size  = 0;
    FILE* fptr        = NULL;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    if (filename == NULL || filesize == NULL) {
        OVSA_DBG(DBG_E, "Error: Invalid parameter while reading Quote info\n");
        ret = OVSA_INVALID_PARAMETER;
        goto out;
    }

    fptr = fopen(filename, "rb");
    if (fptr == NULL) {
        ret = OVSA_FILEOPEN_FAIL;
        OVSA_DBG(DBG_E, "Error: Opening file %s failed with code %d\n", filename, ret);
        goto out;
    }

    file_size = ovsa_get_file_size(fptr);
    if (file_size == 0) {
        OVSA_DBG(DBG_E, "Error: Getting file size for %s failed\n", filename);
        ret = OVSA_FILEIO_FAIL;
        fclose(fptr);
        goto out;
    }

    ret = ovsa_safe_malloc((sizeof(char) * file_size), filecontent);
    if ((ret < OVSA_OK) || (*filecontent == NULL)) {
        OVSA_DBG(DBG_E, "Error: PCR quote buffer allocation failed %d\n", ret);
        fclose(fptr);
        goto out;
    }

    if (!fread(*filecontent, 1, file_size - 1, fptr)) {
        OVSA_DBG(DBG_E, "Error: Reading pcr quote failed %d\n", ret);
        ret = OVSA_FILEIO_FAIL;
        fclose(fptr);
        goto out;
    }
    fclose(fptr);
    *filesize = file_size;
out:
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_read_quote_info(ovsa_hw_quote_info_t* hw_quote_info, int sockfd) {
    ovsa_status_t ret       = OVSA_OK;
    char* pcr_list_buf      = NULL;
    char* pcr_quote_buf     = NULL;
    char* pcr_signature_buf = NULL;
    size_t file_size        = 0;
    char tmp_dir[MAX_FILE_LEN];
    char tmp_quote_msg[MAX_FILE_LEN];
    char tmp_quote_sig[MAX_FILE_LEN];
    char tmp_quote_pcr[MAX_FILE_LEN];

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    if (hw_quote_info == NULL) {
        OVSA_DBG(DBG_E, "Error: Invalid parameter while reading Quote info\n");
        ret = OVSA_INVALID_PARAMETER;
        goto out;
    }
    CREATE_TMP_DIR_PATH(tmp_dir, sockfd);
    CREATE_FILE_PATH(tmp_dir, tmp_quote_msg, TPM2_QUOTE_MSG);
    CREATE_FILE_PATH(tmp_dir, tmp_quote_sig, TPM2_QUOTE_SIG);
    CREATE_FILE_PATH(tmp_dir, tmp_quote_pcr, TPM2_QUOTE_PCR);

    /* Read  PCR BIN file */
    ret = ovsa_read_file_content(tmp_quote_pcr, &pcr_list_buf, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Reading Quote info failed with error code %d\n", ret);
        goto out;
    }

    OVSA_DBG(DBG_D, "OVSA: %s: converting %s DER to PEM \n", __func__, tmp_quote_pcr);
    /* convert pcr bin to pem */
    ret = ovsa_convert_bin_to_pem(pcr_list_buf, file_size - 1, &hw_quote_info->hw_quote_pcr);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error Crypto convert_bin_to_pem failed with code %d\n", ret);
        goto out;
    }
    OVSA_DBG(DBG_D, "OVSA: %s: converted %s DER to PEM \n", __func__, tmp_quote_pcr);

    /* read pcr quote */
    ret = ovsa_read_file_content(tmp_quote_msg, &pcr_quote_buf, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Reading Quote info failed with error code %d\n", ret);
        goto out;
    }

    /* convert pcr_quote to pem */
    ret = ovsa_convert_bin_to_pem(pcr_quote_buf, file_size - 1, &hw_quote_info->hw_quote_message);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error Crypto convert_bin_to_pem failed with code %d\n", ret);
        goto out;
    }

    /* read pcr signature */
    ret = ovsa_read_file_content(tmp_quote_sig, &pcr_signature_buf, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Reading Quote info failed with error code %d\n", ret);
        goto out;
    }

    /* convert pcr_quote to pem*/
    ret = ovsa_convert_bin_to_pem(pcr_signature_buf, file_size - 1, &hw_quote_info->hw_quote_sig);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error Crypto convert_bin_to_pem failed with code %d\n", ret);
        goto out;
    }

    /* read AK Pub_key */
    ret = ovsa_read_file_content(TPM2_AK_PUB_KEY, &hw_quote_info->hw_ak_pub_key, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Reading Quote info failed with error code %d\n", ret);
        goto out;
    }

    /* read EK Pub_key */
    ret = ovsa_read_file_content(TPM2_EK_PUB_KEY, &hw_quote_info->hw_ek_pub_key, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Reading Quote info failed with error code %d\n", ret);
        goto out;
    }

    /*
     * Check if EK Certificate exists. If so, read and send it to client
     */
    if (ovsa_check_if_file_exists(TPM2_EK_CERT) == false)
        goto out;

    ret = ovsa_read_file_content(TPM2_EK_CERT, &hw_quote_info->hw_ek_cert, &file_size);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Reading EK Certificate failed with error code %d\n", ret);
        goto out;
    }

out:
    ovsa_safe_free(&pcr_list_buf);
    ovsa_safe_free(&pcr_quote_buf);
    ovsa_safe_free(&pcr_signature_buf);
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}

ovsa_status_t ovsa_send_quote_info(int sockfd, const char* quote_info) {
    ovsa_status_t ret                = OVSA_OK;
    size_t length                    = 0;
    size_t quote_info_payload_length = 0;
    size_t buf_len                   = 0;
    char* quote_info_blob            = NULL;
    char* quote_info_json_payload    = NULL;

    /* create customer license json message blob */
    ret = ovsa_json_create_message_blob(OVSA_SEND_HW_QUOTE, quote_info, &quote_info_blob, &length);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Create nonce_message failed with error code %d\n", ret);
        goto out;
    }
    quote_info_payload_length = length + PAYLOAD_LENGTH + 1;
    ret = ovsa_safe_malloc(sizeof(char) * quote_info_payload_length, &quote_info_json_payload);
    if (ret < OVSA_OK) {
        ret = OVSA_MEMORY_ALLOC_FAIL;
        OVSA_DBG(DBG_E, "Error: Create json blob memory init failed\n");
        goto out;
    }
    memset_s(quote_info_json_payload, quote_info_payload_length, 0);

    ret = ovsa_append_json_payload_len_to_blob(quote_info_blob, &quote_info_json_payload);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:json blob creation failed with %d\n", ret);
        goto out;
    }
    /* Send customer license to Server */
    ret = ovsa_get_string_length((char*)quote_info_json_payload, &buf_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of cust_lic_json_payload string %d\n", ret);
        goto out;
    }

    OVSA_DBG(DBG_I, "OVSA:Sending HW Quote to client\n%s\n length: %ld\n", quote_info_json_payload,
             buf_len);

    ret = ovsa_socket_write(sockfd, quote_info_json_payload, buf_len);

    OVSA_DBG(DBG_I, "OVSA: Sent HW Quote to client successfully\n");

out:
    ovsa_safe_free(&quote_info_blob);
    ovsa_safe_free(&quote_info_json_payload);

    OVSA_DBG(DBG_D, "Exiting %s\n", __func__);
    return ret;
}
ovsa_status_t ovsa_remove_directory(const char* path) {
    ovsa_status_t ret = OVSA_OK;
    size_t path_len   = 0;
    int r             = -1;

    OVSA_DBG(DBG_D, "OVSA:Entering %s\n", __func__);

    DIR* tmpdirectory = opendir(path);
    ret               = ovsa_get_string_length((char*)path, &path_len);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error: Could not get length of path string %d\n", ret);
        return OVSA_FAIL;
    }
    if (tmpdirectory) {
        struct dirent* directory_entry;
        while (directory_entry = readdir(tmpdirectory)) {
            char* buf;
            size_t len;

            /* Skip the names "." and ".." */
            if (!strcmp(directory_entry->d_name, ".") || !strcmp(directory_entry->d_name, ".."))
                continue;
            len = path_len + strlen(directory_entry->d_name) + 2;
            ret = ovsa_safe_malloc(sizeof(char) * len, &buf);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "Error:memory alloc failed with code %d\n", ret);
                return OVSA_MEMORY_ALLOC_FAIL;
            }
            if (buf) {
                struct stat statbuf;
                snprintf(buf, len, "%s%s", path, directory_entry->d_name);
                OVSA_DBG(DBG_D, "OVSA:Deleting '%s' file \n", buf);

                if (!stat(buf, &statbuf)) {
                    ret = unlink(buf);
                    if (ret != OVSA_OK) {
                        ovsa_safe_free(&buf);
                        return OVSA_RMFILE_FAIL;
                    }
                }
                ovsa_safe_free(&buf);
            }
        }
        ret = closedir(tmpdirectory);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error:close directory  failed with code %d\n", ret);
            return OVSA_CLOSEDIR_FAIL;
        }
        OVSA_DBG(DBG_D, "OVSA:Deleting '%s' directory \n", path);
        ret = rmdir(path);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error:remove directory  failed with code %d\n", ret);
            return OVSA_RMDIR_FAIL;
        }
    }
    OVSA_DBG(DBG_D, "OVSA:%s Exit\n", __func__);
    return ret;
}
ovsa_status_t ovsa_remove_quote_files(int sockfd) {
    ovsa_status_t ret = OVSA_OK;
    char tmp_dir[MAX_FILE_LEN];

    CREATE_TMP_DIR_PATH(tmp_dir, sockfd);
    ret = ovsa_remove_directory(tmp_dir);
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "Error:remove directory  failed with code %d\n", ret);
        return OVSA_RMDIR_FAIL;
    }

    OVSA_DBG(DBG_D, "Removed the Quote files from /tmp directory\n");
}
