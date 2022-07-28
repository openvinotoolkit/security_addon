#!/bin/bash -e
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

#set -x

DIR=$(dirname $(readlink -f "$0"))

echo $DIR
make -C $DIR/../../ all
make -C $DIR/../../ docker_build developer_pkg lic_server_pkg

rm -rf release_files_k8
rm -rf generic-device-plugin

#create required folders
mkdir -p release_files_k8/ovsa-k8-master
mkdir -p release_files_k8/ovsa-k8-worker
mkdir -p release_files_k8/example_runtime

#copy all required packages
cp $DIR/../../release_files_host/ovsa-license-server.tar.gz release_files_k8/.
cp $DIR/../../release_files_host/ovsa-tools.tar.gz release_files_k8/.
cp $DIR/../../Scripts/guest/OVSAK8_tpm2_init.sh .
cp $DIR/../../Example/runtime/sample.json release_files_k8/example_runtime/.

#build dockers
docker build -f Dockerfile . \
  --build-arg http_proxy="$http_proxy"  \
  --build-arg https_proxy="$https_proxy" \
  --build-arg no_proxy="$no_proxy" \
  --build-arg BASE_IMAGE=openvino/model_server-ovsa_host-nginx-mtls:latest \
  -t openvino/model_server-ovsa_host-k8:latest

docker save -o $DIR/release_files_k8/ovsa-k8-master/model_server-ovsa_host-k8-docker.tar.gz \
                openvino/model_server-ovsa_host-k8:latest

#build generic device plugin docker for tpm
git clone https://github.com/squat/generic-device-plugin.git
cd $DIR/generic-device-plugin
git checkout bd0d5d18081e0b56b00271688f2ded15e6a1b3c3
git apply $DIR/generic-device-plugin.patch
make container-latest
cp manifests/generic-device-plugin.yaml $DIR/.

cd $DIR
docker save -o $DIR/release_files_k8/ovsa-k8-master/generic_device_plugin-docker.tar.gz \
                squat/generic-device-plugin:amd64-latest

#package worker and master k8
cd $DIR/release_files_k8
cp ovsa-k8-master/*.tar.gz ovsa-k8-worker/.
cp -r example_runtime ovsa-k8-master/.
mv example_runtime ovsa-k8-worker/.

cp $DIR/generic-device-plugin.yaml ovsa-k8-master/.
cp $DIR/ovsa-deployment.yaml.template ovsa-k8-master/.
cp $DIR/k8-*.sh ovsa-k8-master/.
cp $DIR/install.sh ovsa-k8-master/.

cp $DIR/k8-clean.sh ovsa-k8-worker/.
cp $DIR/install.sh ovsa-k8-worker/.

tar cvzf ovsa-k8-worker.tar.gz ovsa-k8-worker
tar cvzf ovsa-k8-master.tar.gz ovsa-k8-master
rm -rf ovsa-k8-master ovsa-k8-worker
cd $DIR
rm OVSAK8_tpm2_init.sh generic-device-plugin.yaml

echo
echo "OVSA kubernetes package available inside $DIR/release_files_k8"
echo
