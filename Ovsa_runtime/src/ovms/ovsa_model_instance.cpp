//*****************************************************************************
// Copyright 2020 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//*****************************************************************************

#include "ovsa_model_instance.hpp"

OvsaModelInstance::OvsaModelInstance(std::mutex& mutex) : mutex_lock(mutex) {
    OVSA_DBG(DBG_I, "OvsaModelInstance: Default Custom OvsaModelInstance created\n");
    model_is_blacklisted = false;
}

OvsaModelInstance::OvsaModelInstance(const OvsaModelInstance& s) : mutex_lock(s.mutex_lock) {
    model_ksFile         = std::move(s.model_ksFile);
    model_name           = std::move(s.model_name);
    model_licFile        = std::move(s.model_licFile);
    model_datFile        = std::move(s.model_datFile);
    model_is_blacklisted = s.model_is_blacklisted;
}

OvsaModelInstance::OvsaModelInstance(const std::string modelName, const std::string& ksFile,
                                     const std::string& licFile, const std::string& datFile,
                                     bool licState, std::mutex& mutex)
    : mutex_lock(mutex) {
    OVSA_DBG(DBG_I, " OvsaModelInstance: Instance of Custom OvsaModelInstance created\n");
    model_ksFile         = std::move(ksFile);
    model_name           = std::move(modelName);
    model_licFile        = std::move(licFile);
    model_datFile        = std::move(datFile);
    model_is_blacklisted = licState;
}

OvsaModelInstance::~OvsaModelInstance() {
    watcherJoin();
    OVSA_DBG(DBG_I, "OvsaModelInstance: Instance of Custom OvsaModelInstance deleted\n");
}

bool OvsaModelInstance::getBlackListStatus() {
    OVSA_DBG(DBG_I, "OvsaModelInstance: getBlackListStatus\n");
    return model_is_blacklisted;
}

void OvsaModelInstance::releaseResources() {
    watcherJoin();
}

void OvsaModelInstance::threadFunction(std::future<void> futureObj) {
    OVSA_DBG(DBG_I, "OvsaModelInstance: Thread Start\n");
    int count   = 1;
    bool status = false;
    while (futureObj.wait_for(std::chrono::milliseconds(1)) == std::future_status::timeout) {
        OVSA_DBG(DBG_E, "OvsaModelInstance: Doing Some Work %d\n", count++);
        std::this_thread::sleep_for(std::chrono::milliseconds(watchIntervalSecs));
        // query license check service
        std::unique_lock<std::mutex> lockGuard(mutex_lock);
        int asym_keyslot = -1;
        ovsa_status_t ret =
            ovsa_crypto_load_asymmetric_key((char*)model_ksFile.c_str(), &asym_keyslot);
        if (ret != OVSA_OK) {
            OVSA_DBG(DBG_E, "Error: Get asymmetric keyslot failed with code %d\n", ret);
        }
        status = false;
        ret = ovsa_perform_tls_license_check(asym_keyslot, (char*)model_licFile.c_str(), &status);
        if (ret != OVSA_OK) {
            if (ret == OVSA_LICENSE_SERVER_CONNECT_FAIL)
                OVSA_DBG(DBG_E,
                         "Error: TLS license check service failed, Could not connect to server with %d\n",
                         ret);
            else if (ret == OVSA_LICENSE_CHECK_FAIL)
                OVSA_DBG(DBG_E, "Error: TLS license check service failed, License check failed with %d\n",
                         ret);
            else
                OVSA_DBG(DBG_E, "Error: TLS license check service failed with code %d\n", ret);
        }
        model_is_blacklisted = !status;
        if (!status) {
            OVSA_DBG(DBG_D, "Status will be updated to: %d\n", status);
            break;
        }
        ovsa_crypto_clear_asymmetric_key_slot(asym_keyslot);
        lockGuard.unlock();
    }
    OVSA_DBG(DBG_I, "OvsaModelInstance: Thread END\n");
    watcherJoin();
}

void OvsaModelInstance::startWatcher(const int interval) {
    watchIntervalSecs = interval;

    if ((!watcherStarted) && (watchIntervalSecs > 0)) {
        std::future<void> futureObj = exitSignal.get_future();
        std::thread th(std::thread(&OvsaModelInstance::threadFunction, this, std::move(futureObj)));
        watcherStarted = true;
        watcher_thread = std::move(th);
    }
    OVSA_DBG(DBG_I, "OvsaModelInstance: StartWatcher exit\n");
}

void OvsaModelInstance::watcherJoin() {
    OVSA_DBG(DBG_I, "OvsaModelInstance: watcherJoin()\n");
    if (watcherStarted) {
        exitSignal.set_value();
        if (watcher_thread.joinable()) {
            watcher_thread.detach();
            watcherStarted = false;
        }
    }
}
