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

#include <getopt.h>
#include <stdio.h>
#include <string.h>

/* runtime.h to be here due to dependency */
#include "runtime.h"
#include "utils.h"

/* Help options for Ovsa_runtime tool */
static void ovsa_runtime_help(char* argv) {
    printf("Help for Ovsa_Runtime command\n");
    printf("%s gen-tcb-signature <options>\n", argv);
    printf("-n : TCB name\n");
    printf("-v : TCB version\n");
    printf("-f : TCB file name to generate\n");
    printf("-k : Keystore name\n");
    printf("Example for Ovsa_Runtime command as below:\n");
    printf("%s gen-tcb-signature -n <TCB name> -v <TCB version> -f <TCB file name> -k <Keystore>\n",
           argv);
}

int main(int argc, char* argv[]) {
    ovsa_status_t ret = OVSA_OK;
    int i             = 0;
    size_t argv_len   = 0;

    if (argc < 2 || argc > MAX_SAFE_ARGC) {
        ret = OVSA_INVALID_PARAMETER;
        OVSA_DBG(DBG_E, "OVSA: Error wrong command given. Please follow -help for help option\n");
        goto out;
    }
    for (i = 0; argc > i; i++) {
        ret = ovsa_get_string_length(argv[i], &argv_len);
        if (ret < OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error could not get length of argv string %d\n", ret);
            goto out;
        }
        if (argv_len > RSIZE_MAX_STR) {
            OVSA_DBG(DBG_E,
                     "OVSA: Error gen-tcb-signature argument'%s' greater than %ld characters not "
                     "allowed \n",
                     argv[i], RSIZE_MAX_STR);
            ret = OVSA_INVALID_PARAMETER;
            goto out;
        }
    }
    if (!strcmp(argv[1], "-help")) {
        ovsa_runtime_help(argv[0]);
        goto out;
    }
    if (!strcmp(argv[1], "gen-tcb-signature")) {
        optind++;
        ret = ovsa_do_tcb_generation(argc, argv);
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "OVSA: Error ovsa TCB generator failed with code %d\n", ret);
        }
        goto out;
    } else {
        OVSA_DBG(DBG_E, "OVSA: Error wrong command given. Please follow -help for help option\n");
        ret = OVSA_INVALID_PARAMETER;
    }

out:
    return ret;
}
