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
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "json.h"
#include "ovsa.h"
#include "safe_str_lib.h"
#include "tpm.h"
#include "utils.h"

ovsa_status_t ovsa_do_process_cmd(int sockfd) {
    char* nonce;
    int readsize   = 0;
    char* read_buf = NULL;
    char payload_len_str[PAYLOAD_LENGTH + 1];
    char* command       = NULL;
    char* quote_str     = NULL;
    size_t payload_size = 0;

    ovsa_status_t ret = OVSA_OK;
    ovsa_hw_quote_info_t* hw_quote_info;

    ovsa_host_cmd_t cmd = OVSA_INVALID_CMD;

    do {
        /* Read payload length from client */
        memset_s(payload_len_str, sizeof(payload_len_str), 0);
        ret = ovsa_socket_read(sockfd, payload_len_str, PAYLOAD_LENGTH);
        if (ret != OVSA_OK) {
            goto out;
        }

        OVSA_DBG(DBG_D, "Received payload str is %s\n", payload_len_str);

        payload_size = atoi((char*)payload_len_str);
        if (payload_size < 0 || payload_size > RSIZE_MAX_STR) {
            ret = OVSA_MEMORY_ALLOC_FAIL;
            OVSA_DBG(DBG_E, "Error: Read payload length from client is wrong\n");
            goto out;
        }
        OVSA_DBG(DBG_D, "Received payload size is %ld\n", payload_size);

        /* Read payload from client */
        ret = ovsa_safe_malloc(sizeof(char) * payload_size + 1, &read_buf);
        if (ret < OVSA_OK || read_buf == NULL) {
            ret = OVSA_MEMORY_ALLOC_FAIL;
            OVSA_DBG(DBG_E, "Error: Memory allocation of read buf failed with code %d\n", ret);
            goto out;
        }

        ret = ovsa_socket_read(sockfd, read_buf, payload_size);
        if (ret != OVSA_OK) {
            goto out;
        }

        /* Read command from Payload */
        ret = ovsa_json_extract_element((char*)read_buf, "command", (void*)&command);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Read command from json failed %d\n", ret);
            goto out;
        }
        cmd = ovsa_get_command_type(command);
        switch (cmd) {
            case OVSA_SEND_HW_QUOTE:
                /* Read payload from json file */
                ret = ovsa_json_extract_element((char*)read_buf, "payload", (void*)&nonce);
                if (ret < OVSA_OK) {
                    OVSA_DBG(DBG_E, "Error:Read payload from json failed %d\n", ret);
                    goto out;
                }
                OVSA_DBG(DBG_I, "Nonce is %s\n", nonce);

                /* Generate Quote using TPM2 Commands */
                ret = ovsa_tpm2_generate_quote(nonce, sockfd);
                if (ret != OVSA_OK) {
                    OVSA_DBG(DBG_E, "Error: TPM2 Quote generation failed with code %d\n", ret);
                    goto out;
                }
                ret = ovsa_safe_malloc(sizeof(ovsa_hw_quote_info_t), (char**)&hw_quote_info);
                if (ret < OVSA_OK || hw_quote_info == NULL) {
                    ret = OVSA_MEMORY_ALLOC_FAIL;
                    OVSA_DBG(DBG_E, "Error: Memory allocation of read buf failed with code %d\n",
                             ret);
                    goto out;
                }

                /* Read the generated quote info for sending to client */
                ret = ovsa_read_quote_info(hw_quote_info, sockfd);
                if (ret != OVSA_OK) {
                    ovsa_safe_free_hw_quote_info(&hw_quote_info);
                    OVSA_DBG(DBG_E, "Error: Reading Quote failed with code %d\n", ret);
                    goto out;
                }

                /* Create JSON formatted quote blob for sending to client */
                ret = ovsa_json_create_hw_quote_info(hw_quote_info, &quote_str);
                if (ret != OVSA_OK) {
                    ovsa_safe_free_hw_quote_info(&hw_quote_info);
                    OVSA_DBG(DBG_E, "Error: Creation of HW Quote JSON blob failed with code %d\n",
                             ret);
                    goto out;
                }

                /* Send the JSON formatted HW Quote to client */
                ret = ovsa_send_quote_info(sockfd, quote_str);
                if (ret != OVSA_OK) {
                    ovsa_safe_free_hw_quote_info(&hw_quote_info);
                    OVSA_DBG(DBG_E, "Error: Sending HW Quote blob failed with code %d\n", ret);
                    goto out;
                }
                ret = ovsa_remove_quote_files(sockfd);
                if (ret < OVSA_OK) {
                    OVSA_DBG(DBG_E, "Error:remove quote files failed with code %d\n", ret);
                    goto out;
                }
                ovsa_safe_free((char**)&quote_str);
                ovsa_safe_free_hw_quote_info(&hw_quote_info);
                break;
            case OVSA_INVALID_CMD:
            default:
                OVSA_DBG(DBG_I, "Client has sent invalid cmd = %d...\n", cmd);
                ret = OVSA_INVALID_HOST_CMD;
                break;
        }

        ovsa_safe_free((char**)&command);
        ovsa_safe_free((char**)&read_buf);

    } while (true);

out:
    ovsa_safe_free((char**)&command);
    ovsa_safe_free((char**)&read_buf);
    ovsa_safe_free((char**)&quote_str);

    return ret;
}

/*
 * This will handle connection for each client
 */
void* ovsa_connection_handler(void* connfd) {
    OVSA_DBG(DBG_D, "Entering %s: fd %d\n", __func__, *(int*)connfd);

    /* Get the socket descriptor */
    int sockfd = *(int*)connfd;

    ovsa_do_process_cmd(sockfd);

    /* If we reach here, client has exited */
    close(sockfd);

    OVSA_DBG(DBG_D, "Exiting %s: fd %d\n", __func__, *(int*)connfd);
    return 0;
}

int main() {
    int sockfd, connfd, new_connfd, len;
    struct sockaddr_in servaddr, client;
    struct timeval timeout;
    char* port_number = NULL;
    char* kvm_host_ip = NULL;
    int port          = 0;
    static char port_str[MAX_PORT_LEN];
    static char kvm_guest[MAX_IP_ADDR_STR_LEN];

    /*
     ***********************************************************************
     * Get KVM_TCP_PORT_NUMBER & KVM_HOST_IP Using ENV Variable
     ***********************************************************************
     */
    port_number = secure_getenv("KVM_TCP_PORT_NUMBER");
    if (port_number == NULL) {
        port = DEFAULT_TCP_PORT_NUMBER;
    } else {
        strcpy_s(port_str, sizeof(port_str), port_number);
        port = atoi(port_str);
    }
    kvm_host_ip = secure_getenv("KVM_HOST_IP");

    if (kvm_host_ip == NULL)
        strcpy_s(kvm_guest, sizeof(kvm_guest), DEFAULT_HOST_IP);
    else
        strcpy_s(kvm_guest, sizeof(kvm_guest), kvm_host_ip);

    /* socket create and verification */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        OVSA_DBG(DBG_E, "OVSA: Socket connection failed with error %s\n", strerror(errno));
        return 1;
    }

    OVSA_DBG(DBG_I, "Socket successfully created..\n");

    bzero(&servaddr, sizeof(servaddr));
    OVSA_DBG(DBG_I, "\nOVSA: port_number:%d\n", port);

    /* assign IP, PORT */
    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(kvm_guest);
    servaddr.sin_port        = htons(port);

    /* Binding newly created socket to given IP and verification */
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
        OVSA_DBG(DBG_E, "OVSA: socket bind failed with error %s\n", strerror(errno));
        close(sockfd);
        return 1;
    }

    OVSA_DBG(DBG_I, "Socket successfully binded..\n");

    /* Now server is ready to listen and verification */
    if ((listen(sockfd, 5)) != 0) {
        OVSA_DBG(DBG_E, "Listening for connections on Socked failed with error %s\n",
                 strerror(errno));
        close(sockfd);
        return 1;
    }

    OVSA_DBG(DBG_I, "Server listening..\n");

    len = sizeof(client);

    while (true) {
        OVSA_DBG(DBG_I, "OVSA: Waiting for incoming connection...\n");

        /* Accept the data packet from client and verification */
        connfd = accept(sockfd, (SA*)&client, &len);
        char client_IP[MAX_NAME_SIZE];
        inet_ntop(AF_INET, &(client.sin_addr), client_IP, MAX_NAME_SIZE);
        OVSA_DBG(DBG_I, "OVSA:Client IP Address: %s\n", client_IP);

        timeout.tv_sec  = 10;
        timeout.tv_usec = 0;

        if (setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) < 0) {
            OVSA_DBG(DBG_E,
                     "Error: Setsockopt failed while setting receive timeout with "
                     "error %s\n",
                     strerror(errno));
            close(sockfd);
            return 1;
        }

        if (setsockopt(connfd, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout)) < 0) {
            OVSA_DBG(DBG_E, "Error: Setsockopt failed while setting send timeout with error %s\n",
                     strerror(errno));
            close(sockfd);
            return 1;
        }

        pthread_t thread;
        new_connfd = connfd;

        if (pthread_create(&thread, NULL, ovsa_connection_handler, (void*)&new_connfd) < 0) {
            OVSA_DBG(DBG_E, "OVSA: Thread creation failed with error %s\n", strerror(errno));
            close(new_connfd);
            close(sockfd);
            return 1;
        }
        pthread_join(thread, NULL);
    }
    return 0;
}
