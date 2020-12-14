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

#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include "libovsa.h"
#include "ovsa_tool.h"

static ovsa_handle_cmd_t ovsa_cmd_handler[MAX_OVSA_CMDS];
static char* ovsa_cmd[] = {"keygen", "licgen", "protect", "sale"};

static ovsa_status_t (*ovsa_fptr[])(int argc, char* argv[]) = {ovsa_keygen_main, ovsa_licgen_main,
                                                               ovsa_protect_main, ovsa_sale_main};

/* Help options for Ovsa_tool */
static void ovsa_help(const char* argv) {
    printf("%s <command> [Optional subcommand for keygen] <options>\n", argv);
    printf("Supported commands:\n");
    printf("    keygen\n");
    printf("    licgen\n");
    printf("    protect\n");
    printf("    sale\n");
    printf("Supported subcommands for keygen:\n");
    printf("    -storekey\n");
    printf("    -storecert\n");
    printf("    -getcert\n");
    printf("    -sign\n");
    printf("    -verify\n");
    printf(
        "%s keygen -storekey -t ECDSA -k <Key Store File> -n <Name of keystore> -e <Subject "
        "element for CSR generation>\n",
        argv);
    printf("%s keygen -storecert -c <Certificate> -k <Key Store File>\n", argv);
    printf("%s keygen -getcert -k <Key Store File> -c <Certificate>\n", argv);
    printf("%s keygen -sign -p <file to be signed> -o <signed file> -k <key_store file>\n", argv);
    printf("%s keygen -verify -p <file to be verified> -s <signature> -k <key_store file>\n", argv);
    printf(
        "%s licgen -t <License Type> [-l <Usage Count Limit> or <Time Limit>] -n \"License "
        "name\" -v \"License Version\" -u <License URL> -k <key store file> -o <lic conf "
        "file>\n\n",
        argv);
    printf(
        "%s protect -i <Intermediate File> <Model weighs file> <additional files> -n "
        "<Model name> -d <Model "
        "Description> -v <Model Vesrion> -p <Protected model  file> -m <Master license file> -k "
        "<key store file>\n\n",
        argv);
    printf(
        "%s sale -m <Master license file> -k <key store file> -l <license conf file> -t <  "
        "list of TCB "
        "Signature files  > -p <Customer Certificate> -c <Customer license> -g <License GUID>\n\n",
        argv);
    printf("Please use -help to the commands for details of supported options\n");
}

static void ovsa_cmd_handler_init(void) {
    int i = 0;

    for (i = 0; i < MAX_OVSA_CMDS; i++) {
        ovsa_cmd_handler[i].command = ovsa_cmd[i];
        ovsa_cmd_handler[i].funcptr = ovsa_fptr[i];
    }
}

int main(int argc, char* argv[]) {
    ovsa_status_t ret = OVSA_OK;
    int i             = 0;

    if (argc < 2) {
        ret = OVSA_INVALID_PARAMETER;
        OVSA_DBG(DBG_E, "OVSA: Wrong command given. Please follow -help for help option\n");
        goto out;
    }

    ovsa_cmd_handler_init();

    if (!strcmp(argv[1], "-help")) {
        ovsa_help(argv[0]);
        goto out;
    }

    for (i = 0; i < MAX_OVSA_CMDS; i++) {
        if (!strcmp(ovsa_cmd_handler[i].command, argv[1])) {
            optind++;
            ret = (*ovsa_cmd_handler[i].funcptr)(argc, argv);
            if (ret < OVSA_OK) {
                OVSA_DBG(DBG_E, "OVSA: %s command failed with error code %d\n", argv[1], ret);
            }
            goto out;
        }
    }

    OVSA_DBG(DBG_E, "OVSA: Invalid command %s. Please follow -help for help option\n", argv[1]);
out:
    return ret;
}
