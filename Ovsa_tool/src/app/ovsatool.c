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

#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "libovsa.h"
#include "ovsa_tool.h"

static ovsa_handle_cmd_t g_ovsa_cmd_handler[MAX_OVSA_CMDS];
static char* g_ovsa_cmd[] = {"keygen", "licgen", "controlAccess", "sale", "updatecustlicense"};

static ovsa_status_t (*ovsa_fptr[])(int argc, char* argv[]) = {
    ovsa_keygen_main, ovsa_licgen_main, ovsa_controlaccess_main, ovsa_sale_main,
    ovsa_update_custlicense_main};

/* Help options for Ovsa_tool */
static void ovsa_help(const char* argv) {
    printf("%s <command> [Optional subcommand for keygen] <options>\n", argv);
    printf("Supported commands:\n");
    printf("    keygen\n");
    printf("    licgen\n");
    printf("    controlAccess\n");
    printf("    sale\n");
    printf("    updatecustlicense\n");
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
    printf("%s keygen -sign -i <file to be signed> -o <signed file> -k <key_store file>\n", argv);
    printf("%s keygen -verify -i <file to be verified> -s <signature> -k <key_store file>\n", argv);
    printf(
        "%s licgen -t <License Type> [-l <Usage Count Limit> or <Time Limit>] -n \"License "
        "name\" -v \"License Version\" -u <License URL> [<Future server certificate file>] [-u "
        "<License URL> <License Server Certificate> [<Future server certificate file>]] -k <key "
        "store file> -o <lic conf file>\n\n",
        argv);
    printf(
        "%s controlAccess -i <Intermediate File> <Model weighs file> <additional files> -n "
        "<Model name> -d <Model "
        "Description> -v <Model Vesrion> -p <Controlled access model file> -m <Master license "
        "file> -k "
        "<key store file>\n\n",
        argv);
    printf(
        "%s sale -m <Master license file> -k <key store file> -l <license conf file> -t <  "
        "list of TCB "
        "Signature files  > -p <Customer Certificate> -c <Customer license> -g <License GUID>\n\n",
        argv);
    printf(
        "%s updatecustlicense -k <key store file> -l <Customer License File> -p <Customer "
        "Certificate> -u <License URL> <Future server certificate [-u <License URL> <Future server "
        "certificate file>] -c <Updated Customer license>\n\n",
        argv);
    printf("Please use -help to the commands for details of supported options\n");
}

static void ovsa_cmd_handler_init(void) {
    int i = 0;

    for (i = 0; i < MAX_OVSA_CMDS; i++) {
        g_ovsa_cmd_handler[i].command = g_ovsa_cmd[i];
        g_ovsa_cmd_handler[i].funcptr = ovsa_fptr[i];
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
    /*set file mode creation mask*/
    mode_t nmask;
    nmask = S_IRGRP | S_IWGRP | /* group read write */
            S_IROTH | S_IWOTH;  /* other read write */
    umask(nmask);               /*0666 & ~066 = 0600 i.e., (-rw-------)*/

    for (i = 0; i < MAX_OVSA_CMDS; i++) {
        if (!strcmp(g_ovsa_cmd_handler[i].command, argv[1])) {
            optind++;
            ret = (*g_ovsa_cmd_handler[i].funcptr)(argc, argv);
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
