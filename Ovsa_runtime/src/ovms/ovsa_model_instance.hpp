//*****************************************************************************
// Copyright 2020-2022 Intel Corporation
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

#include <string.h>

#include <future>
#include <iostream>
#include <mutex>
#include <thread>

#include "ovsa_errors.h"

extern "C" {
ovsa_status_t ovsa_perform_tls_license_check(const int asym_keyslot, const char* customer_license,
                                             bool* status);
ovsa_status_t ovsa_crypto_load_asymmetric_key(const char* keystore_name, int* asym_key_slot);
void ovsa_crypto_clear_asymmetric_key_slot(int asym_key_slot);
ovsa_status_t ovsa_crypto_init();
void ovsa_crypto_deinit();
};

class OvsaModelInstance {
   private:
    std::string model_name;
    std::string model_ksFile;
    std::string model_licFile;
    std::string model_datFile;
    int model_version;
    bool model_is_blacklisted;
    std::mutex& mutex_lock;

   protected:
    std::promise<void> exitSignal;
    int watchIntervalSecs = 0;
    bool watcherStarted   = false;
    std::thread watcher_thread;

   public:
    OvsaModelInstance(std::mutex& mutex);
    OvsaModelInstance(const std::string modelName, const std::string& ksFile,
                      const std::string& licFile, const std::string& datFile, bool licState,
                      int model_version, std::mutex& mutex);
    OvsaModelInstance(const OvsaModelInstance& s);
    OvsaModelInstance& operator=(const OvsaModelInstance& s);
    ~OvsaModelInstance();
    bool getBlackListStatus();
    void releaseResources();
    void threadFunction(std::future<void> futureObj);
    void startWatcher(const int intervalSec);
    void watcherJoin();
};
