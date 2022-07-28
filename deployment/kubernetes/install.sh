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
echo "Installing OVSA Kubernetes Components"
echo

echo "Creating /opt/ovsa/k8 directory..."
mkdir -vp /opt/ovsa/k8 2>&1 | sed 's/^/    /'
cp -vR k8-*.sh /opt/ovsa/k8 2>&1 | sed 's/^/    /'

if [ -e ovsa-deployment.yaml.template ]
then
	cp -vR ovsa-deployment.yaml.template /opt/ovsa/k8 2>&1 | sed 's/^/    /'
	cp -vR generic-device-plugin.yaml /opt/ovsa/k8 2>&1 | sed 's/^/    /'
fi

echo "Copying files to /opt/ovsa/host/example_runtime directory..."
mkdir -vp /opt/ovsa/host/example_runtime 2>&1 | sed 's/^/    /'
cp -vR example_runtime/* /opt/ovsa/host/example_runtime/ 2>&1 | sed 's/^/    /'
chown ovsa:ovsa /opt/ovsa/host/example_runtime 2>&1 | sed 's/^/    /'
chown ovsa:ovsa /opt/ovsa/k8 2>&1 | sed 's/^/    /'

echo "Loading the docker images..."
if [[ "$(docker images -q openvino/model_server-ovsa_host-k8 2> /dev/null)" == "" ]]; then
        echo "Docker does not exist."
else
        echo "Removing existing docker image..."
        docker image rm -f openvino/model_server-ovsa_host-k8 2>&1 | sed 's/^/    /'
fi

docker load -i model_server-ovsa_host-k8-docker.tar.gz 2>&1 | sed 's/^/    /'

if [[ "$(docker images -q squat/generic-device-plugin 2> /dev/null)" == "" ]]; then
        echo "Docker does not exist."
else
        echo "Removing existing docker image..."
        docker image rm -f squat/generic-device-plugin:amd64-latest 2>&1 | sed 's/^/    /'
fi

docker load -i generic_device_plugin-docker.tar.gz 2>&1 | sed 's/^/    /'

echo
echo "Installing OVSA Kubernetes Components completed."
echo
