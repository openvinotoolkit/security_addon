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
#define MAX_NAME_SIZE 256
typedef struct ovsa_model_files {
    char model_file_name[MAX_NAME_SIZE];
    char* model_file_data;
    int model_file_length;
    struct ovsa_model_files* next;
} ovsa_model_files_t;

ovsa_status_t ovsa_license_check_module(const char* keystore, const char* controlled_access_model,
                                        const char* customer_license,
                                        ovsa_model_files_t** decrypted_files);
ovsa_status_t ovsa_crypto_init();
void ovsa_crypto_deinit();
void ovsa_safe_free_model_file_list(ovsa_model_files_t** listhead);
};

// Time in seconds at which model status will be checked
#define VALIDITY_CHECK_INTERVAL_MAX 1440  // 24hrs
#define VALIDITY_CHECK_INTERVAL_MIN 1     // 1min

#if OVMS_LICCHECK_MINS < VALIDITY_CHECK_INTERVAL_MIN
#define VALIDITY_CHECK_INTERVAL (VALIDITY_CHECK_INTERVAL_MIN * 60 * 1000)  // 1min minimum value
#elif OVMS_LICCHECK_MINS > VALIDITY_CHECK_INTERVAL_MAX
#define VALIDITY_CHECK_INTERVAL (VALIDITY_CHECK_INTERVAL_MAX * 60 * 1000)  // 24hrs maximum value
#else
#define VALIDITY_CHECK_INTERVAL (OVMS_LICCHECK_MINS * 60 * 1000)
#endif

typedef std::pair<std::string, int> map_key_t;
typedef std::pair<std::string, uint8_t> model_file_t;
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
        std::cout << "OvsaCustomLoader: Error invalid input parameters to loadModel" << std::endl;
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
        std::cout << "OvsaCustomLoader: \nloader_name:" << loaderName << std::endl;
    }

    if (doc.HasMember("controlled_access_file")) {
        std::string controlled_access_file = doc["controlled_access_file"].GetString();
        datFile                            = fullPath + "/" + controlled_access_file + ".dat";
        std::cout << "datFile:" << datFile << std::endl;

        licFile = fullPath + "/" + controlled_access_file + ".lic";
        std::cout << "licFile:" << licFile << std::endl;
    }

    if (doc.HasMember("keystore")) {
        std::string ks = doc["keystore"].GetString();
        ksFile         = ks;
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
    std::string type;
    std::string loaderName;
    std::string ksFile;
    std::string licFile;
    std::string datFile;
    ovsa_model_files_t* decrypted_files = NULL;
    CustomLoaderStatus retStatus        = CustomLoaderStatus::MODEL_LOAD_ERROR;

    if (modelName.empty() || basePath.empty() || loaderOptions.empty()) {
        std::cout << "OvsaCustomLoader: Error invalid input parameters to loadModel" << std::endl;
        return CustomLoaderStatus::MODEL_LOAD_ERROR;
    }

    CustomLoaderStatus st = ovsa_json_extract_input_params(basePath, version, loaderOptions,
                                                           loaderName, ksFile, licFile, datFile);
    if (st != CustomLoaderStatus::OK || ksFile.empty() || licFile.empty() || datFile.empty()) {
        std::cout << "OvsaCustomLoader: Error invalid custom loader options" << std::endl;
        return CustomLoaderStatus::MODEL_LOAD_ERROR;
    }

    std::unique_lock<std::mutex> lockGuard(critical_ops);
    ovsa_status_t rets = ovsa_license_check_module(ksFile.c_str(), datFile.c_str(), licFile.c_str(),
                                                   &decrypted_files);
    if (rets != OVSA_OK) {
        if (rets == OVSA_LICENSE_SERVER_CONNECT_FAIL) {
            OVSA_DBG(DBG_E,
                     "OvsaCustomLoader: Error LICENSE CHECK SERVER CONNECT FAILED"
                     " with %d\n",
                     rets);
        } else if (rets == OVSA_LICENSE_CHECK_FAIL) {
            OVSA_DBG(DBG_E, "OvsaCustomLoader: Error LICENSE CHECK FAILED with %d\n", rets);
        } else {
            OVSA_DBG(DBG_E, "OvsaCustomLoader: Error ovsa_license_check_module with code %d\n",
                     rets);
        }
        ovsa_safe_free_model_file_list(&decrypted_files);
        return CustomLoaderStatus::MODEL_LOAD_ERROR;
    }
    lockGuard.unlock();

    std::vector<std::pair<std::string, uint8_t>> modelFileVec;
    ovsa_model_files_t* head = decrypted_files;
    bool file_type_ir        = false;

    while (head != NULL) {
        // model_file_t file_data =  std::make_pair(head->model_file_name,head->model_file_data);
        // modelFileVec.pushback(file_data);
        //

        std::string filename(head->model_file_name);
        size_t found = filename.find(".xml");
        if (found != std::string::npos) {
            std::cout << "OvsaCustomLoader: " << head->model_file_name << std::endl;
            std::vector<uint8_t> mdl(&head->model_file_data[0],
                                     &head->model_file_data[head->model_file_length]);
            modelBuffer.insert(modelBuffer.end(), mdl.begin(), mdl.end());
            if (file_type_ir) {
                retStatus = CustomLoaderStatus::MODEL_TYPE_IR;
            } else {
                file_type_ir = true;
            }
        }

        found = filename.find(".bin");
        if (found != std::string::npos) {
            std::cout << "OvsaCustomLoader: " << head->model_file_name << std::endl;
            std::vector<uint8_t> wts(&head->model_file_data[0],
                                     &head->model_file_data[head->model_file_length]);
            weights.insert(weights.end(), wts.begin(), wts.end());
            if (file_type_ir) {
                retStatus = CustomLoaderStatus::MODEL_TYPE_IR;
            } else {
                file_type_ir = true;
            }
        }

        found = filename.find(".blob");
        if (found != std::string::npos) {
            std::cout << "OvsaCustomLoader: " << head->model_file_name << std::endl;
            std::vector<uint8_t> mdl(&head->model_file_data[0],
                                     &head->model_file_data[head->model_file_length]);
            modelBuffer.insert(modelBuffer.end(), mdl.begin(), mdl.end());
            retStatus = CustomLoaderStatus::MODEL_TYPE_BLOB;
        }

        found = filename.find(".onnx");
        if (found != std::string::npos) {
            std::cout << "OvsaCustomLoader: " << head->model_file_name << std::endl;
            std::vector<uint8_t> mdl(&head->model_file_data[0],
                                     &head->model_file_data[head->model_file_length]);
            modelBuffer.insert(modelBuffer.end(), mdl.begin(), mdl.end());
            retStatus = CustomLoaderStatus::MODEL_TYPE_ONNX;
        }

        head = head->next;
    }
    if (retStatus != CustomLoaderStatus::MODEL_LOAD_ERROR) {
        std::lock_guard<std::mutex> guard(models_watched_mutex);
        map_key_t key  = std::make_pair(modelName, version);
        model_map[key] = std::make_shared<OvsaModelInstance>(modelName, ksFile, licFile, datFile,
                                                             false, version, ref(critical_ops));
        auto itr       = model_map.find(key);
        if (itr != model_map.end()) {
            itr->second->startWatcher(VALIDITY_CHECK_INTERVAL);
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    ovsa_safe_free_model_file_list(&decrypted_files);
    return retStatus;
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
    OVSA_DBG(DBG_D, "OvsaCustomLoader: Custom getModelBlacklistStatus\n");

    map_key_t toFind = std::make_pair(modelName, version);
    auto it          = model_map.find(toFind);
    if (it == model_map.end()) {
        OVSA_DBG(DBG_D, "OvsaCustomLoader: Model:%s Version:%d not loaded\n",
			(char*)modelName.c_str(), version);
        return CustomLoaderStatus::OK;
    }

    bool status = it->second->getBlackListStatus();
    if (status)
        return CustomLoaderStatus::MODEL_BLACKLISTED;
    else
        return CustomLoaderStatus::OK;
}
