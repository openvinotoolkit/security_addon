#!/bin/bash
#
# Copyright (c) 2020-2022 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#set -e

echo
echo "Loading the OpenVINO Model Server docker image..."
echo

if [[ "$(docker images -q openvino/model_server-ovsa-nginx-mtls 2> /dev/null)" == "" ]]; then
        echo "Docker does not exist."
else
	echo "Removing existing docker image..."
        docker image rm -f openvino/model_server-ovsa-nginx-mtls 2>&1 | sed 's/^/    /'
fi

docker load -i model_server-ovsa-nginx-mtls.tar.gz 2>&1 | sed 's/^/    /'

echo
echo "Loading the OpenVINO Model Server docker image completed."
echo
