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

#include <assert.h>

#include <chrono>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "customloaderinterface.hpp"
#include "ovsa_model_instance.hpp"
#include "rapidjson/document.h"

using namespace ovms;

extern "C" {
ovsa_status_t ovsa_license_check_module(const char* keystore, const char* protected_model,
                                      const char* customer_license, char** decrypt_xml,
                                      char** decrypt_bin, int* xml_len, int* bin_len);
ovsa_status_t ovsa_crypto_init();
void ovsa_crypto_deinit();
void ovsa_safe_free(char** ptr);
};

// Time in seconds at which model status will be checked
#define VALIDITY_CHECK_INTERVAL_MAX 1440 // 24hrs
#define VALIDITY_CHECK_INTERVAL_MIN 1    // 1min

#if OVMS_LICCHECK_MINS < VALIDITY_CHECK_INTERVAL_MIN
#define VALIDITY_CHECK_INTERVAL (VALIDITY_CHECK_INTERVAL_MIN*60*1000) // 1min minimum value
#elif OVMS_LICCHECK_MINS > VALIDITY_CHECK_INTERVAL_MAX
#define VALIDITY_CHECK_INTERVAL (VALIDITY_CHECK_INTERVAL_MAX*60*1000) // 24hrs maximum value
#else
#define VALIDITY_CHECK_INTERVAL (OVMS_LICCHECK_MINS*60*1000)
#endif

typedef std::pair<std::string, int> map_key_t;
/*
 * This class implements am example custom model loader for OVMS.
 * It derives the implementation from base class CustomLoaderInterface
 * defined in ovms. The purpose this example is to demonstrate the
 * usage of various APIs defined in base class, parse loader specific
 * parameters from the config file.
 *
 * It reads the model files and returns the buffers to be loaded by the
 * model server.
 *
 * Also, based on the contents on <model>.status file, it black lists the model
 * or removes the model from blacklisting. During the periodic check on model
 * loader will unload/reload model based on blacklist.
 */

class OvsaCustomLoader : public CustomLoaderInterface {
   private:
    std::map<map_key_t, std::shared_ptr<OvsaModelInstance>> model_map;
    std::mutex critical_ops;
    std::mutex models_watched_mutex;

   protected:
    CustomLoaderStatus ovsa_json_extract_input_params(const std::string& basePath,
                                                      const int version,
                                                      const std::string& loaderOptions,
                                                      std::string& loaderName, std::string& ksFile,
                                                      std::string& licFile, std::string& datFile);
   public:
    OvsaCustomLoader();
    ~OvsaCustomLoader();

    // Virtual functions of the base class defined here
    CustomLoaderStatus loaderInit(const std::string& loader_path);
    CustomLoaderStatus loaderDeInit();
    CustomLoaderStatus unloadModel(const std::string& modelName, int version);
    CustomLoaderStatus loadModel(const std::string& modelName, const std::string& basePath,
                                 const int version, const std::string& loaderOptions,
                                 std::vector<uint8_t>& modelBuffer, std::vector<uint8_t>& weights);
    CustomLoaderStatus getModelBlacklistStatus(const std::string& modelName, int version);
    CustomLoaderStatus retireModel(const std::string& modelName);

};

extern "C" CustomLoaderInterface* createCustomLoader() {
    return new OvsaCustomLoader();
}

OvsaCustomLoader::OvsaCustomLoader() {
    std::cout << "OvsaCustomLoader: Instance of Custom SampleLoader created" << std::endl;
}

OvsaCustomLoader::~OvsaCustomLoader() {
    std::cout << "OvsaCustomLoader: Instance of Custom SampleLoader deleted" << std::endl;
}

CustomLoaderStatus OvsaCustomLoader::loaderInit(const std::string& loader_path) {
    std::cout << "OvsaCustomLoader: Custom loaderInit" << loader_path << std::endl;
    ovsa_status_t ret = ovsa_crypto_init();
    if (ret < OVSA_OK) {
        OVSA_DBG(DBG_E, "OvsaCustomLoader: Crypto init failed with code %d\n", ret);
        return CustomLoaderStatus::MODEL_LOAD_ERROR;
    }
    return CustomLoaderStatus::OK;
}

CustomLoaderStatus OvsaCustomLoader::ovsa_json_extract_input_params(
    const std::string& basePath, const int version, const std::string& loaderOptions,
    std::string& loaderName, std::string& ksFile, std::string& licFile, std::string& datFile) {
    CustomLoaderStatus ret = CustomLoaderStatus::OK;
    rapidjson::Document doc;

    if (basePath.empty() | loaderOptions.empty()) {
        std::cout << "OvsaCustomLoader: Invalid input parameters to loadModel" << std::endl;
        return CustomLoaderStatus::MODEL_LOAD_ERROR;
    }

    std::string fullPath = basePath + "/" + std::to_string(version);

    // parse jason input string
    if (doc.Parse(loaderOptions.c_str()).HasParseError()) {
        return CustomLoaderStatus::MODEL_LOAD_ERROR;
    }

    for (rapidjson::Value::ConstMemberIterator itr = doc.MemberBegin(); itr != doc.MemberEnd();
         ++itr)
        printf("Type of member %s is %s\n", itr->name.GetString(), itr->value.GetString());

    if (doc.HasMember("loader_name")) {
        std::string lname = doc["loader_name"].GetString();
        loaderName        = fullPath + "/" + lname;
        std::cout << "loader_name:" << loaderName << std::endl;
    }

    if (doc.HasMember("protected_file")) {
        std::string protected_file = doc["protected_file"].GetString();
        datFile                    = fullPath + "/" + protected_file + ".dat";
        std::cout << "datFile:" << datFile << std::endl;

        licFile = fullPath + "/" + protected_file + ".lic";
        std::cout << "licFile:" << licFile << std::endl;
    }

    if (doc.HasMember("keystore")) {
        std::string ks = doc["keystore"].GetString();
        ksFile         = fullPath + "/" + ks;
        std::cout << "keystore:" << ksFile << std::endl;
    }

    return ret;
}

/*
 * From the custom loader options extract the model file name and other needed information and
 * load the model and optional bin file into buffers and return
 */
CustomLoaderStatus OvsaCustomLoader::loadModel(const std::string& modelName,
                                               const std::string& basePath, const int version,
                                               const std::string& loaderOptions,
                                               std::vector<uint8_t>& modelBuffer,
                                               std::vector<uint8_t>& weights) {
    std::cout << "OvsaCustomLoader: Custom loadModel" << std::endl;
    char* modelBuf   = NULL;
    char* weightsBuf = NULL;
    int xml_len      = 0;
    int bin_len      = 0;
    std::string type;
    std::string loaderName;
    std::string ksFile;
    std::string licFile;
    std::string datFile;

    if (modelName.empty() || basePath.empty() || loaderOptions.empty()) {
        std::cout << "OvsaCustomLoader: Invalid input parameters to loadModel" << std::endl;
        return CustomLoaderStatus::MODEL_LOAD_ERROR;
    }

    CustomLoaderStatus st = ovsa_json_extract_input_params(basePath, version, loaderOptions,
		                                           loaderName, ksFile, licFile, datFile);
    if (st != CustomLoaderStatus::OK || ksFile.empty() || licFile.empty() || datFile.empty()) {
        std::cout << "OvsaCustomLoader: Invalid custom loader options" << std::endl;
        return CustomLoaderStatus::MODEL_LOAD_ERROR;
    }

    std::unique_lock<std::mutex> lockGuard(critical_ops);
    ovsa_status_t rets = ovsa_license_check_module(ksFile.c_str(), datFile.c_str(), licFile.c_str(),
                                                   &modelBuf, &weightsBuf, &xml_len, &bin_len);
    if (rets != OVSA_OK) {
        if (rets == OVSA_LICENSE_SERVER_CONNECT_FAIL) {
            OVSA_DBG(DBG_E,
                     "OvsaCustomLoader: LICENSE CHECK SERVER CONNECT FAILED"
                     " with %d\n",
                     rets);
        } else if (rets == OVSA_LICENSE_CHECK_FAIL) {
            OVSA_DBG(DBG_E, "OvsaCustomLoader: LICENSE CHECK FAILED with %d\n", rets);
        } else {
            OVSA_DBG(DBG_E, "OvsaCustomLoader: ovsa_license_check_module with code %d\n", rets);
        }
        ovsa_safe_free(&modelBuf);
        ovsa_safe_free(&weightsBuf);
        return CustomLoaderStatus::MODEL_LOAD_ERROR;
    }
    lockGuard.unlock();

    std::vector<uint8_t> wts(&weightsBuf[0], &weightsBuf[bin_len]);
    std::vector<uint8_t> mdl(&modelBuf[0], &modelBuf[xml_len]);
    modelBuffer.insert(modelBuffer.end(), mdl.begin(), mdl.end());
    weights.insert(weights.end(), wts.begin(), wts.end());

    std::lock_guard<std::mutex> guard(models_watched_mutex);
    map_key_t key  = std::make_pair(modelName, version);
    model_map[key] = std::make_shared<OvsaModelInstance>(modelName, ksFile, licFile, datFile, false,
                                                         ref(critical_ops));
    auto itr       = model_map.find(key);
    if (itr != model_map.end()) {
        itr->second->startWatcher(VALIDITY_CHECK_INTERVAL);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    ovsa_safe_free(&modelBuf);
    ovsa_safe_free(&weightsBuf);

    return CustomLoaderStatus::MODEL_TYPE_IR;
}

// Retire the model
CustomLoaderStatus OvsaCustomLoader::retireModel(const std::string& modelName) {
    std::vector<map_key_t> toDelete;
    std::lock_guard<std::mutex> guard(models_watched_mutex);

    for (auto it : model_map) {
        if ((it.first).first == modelName) {
            toDelete.push_back(it.first);
        }
    }

    for (auto itr : toDelete) {
        model_map.erase(itr);
    }
    return CustomLoaderStatus::OK;
}

// Unload model from loaded models list.
CustomLoaderStatus OvsaCustomLoader::unloadModel(const std::string& modelName, const int version) {
    std::cout << "OvsaCustomLoader: Custom unloadModel" << std::endl;

    map_key_t toFind = std::make_pair(modelName, version);
    std::lock_guard<std::mutex> guard(models_watched_mutex);
    auto it = model_map.find(toFind);

    if (it == model_map.end()) {
        std::cout << modelName << " is not loaded" << std::endl;
    } else {
        it->second->releaseResources();
        model_map.erase(it);
    }
    return CustomLoaderStatus::OK;
}

CustomLoaderStatus OvsaCustomLoader::loaderDeInit() {
    std::cout << "OvsaCustomLoader: Custom loaderDeInit" << std::endl;
    ovsa_crypto_deinit();
    return CustomLoaderStatus::OK;
}

CustomLoaderStatus OvsaCustomLoader::getModelBlacklistStatus(const std::string& modelName,
                                                             const int version) {
    std::cout << "OvsaCustomLoader: Custom getModelBlacklistStatus" << std::endl;

    map_key_t toFind = std::make_pair(modelName, version);
    auto it          = model_map.find(toFind);
    if (it == model_map.end()) {
        OVSA_DBG(DBG_E, "OvsaCustomLoader: Model not loaded\n");
        return CustomLoaderStatus::OK;
    }

    bool status = it->second->getBlackListStatus();
    if (status)
        return CustomLoaderStatus::MODEL_BLACKLISTED;
    else
        return CustomLoaderStatus::OK;
}
