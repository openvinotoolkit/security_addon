#!/bin/bash -x
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

REST_PORT=2225
GRPC_PORT=3335

MTLS_IMAGE=${1:-"gsc-openvino/model_server-ovsa-nginx-mtls:latest"}

echo "Starting container. Hit CTRL+C to stop it. Use another terminal to send some requests, e.g. via using test_rest.sh or test_grpc.sh scripts."
docker run --rm -ti \
        --net=host \
        --device=/dev/sgx_enclave:/dev/sgx_enclave \
        --security-opt=no-new-privileges:true --cap-drop all \
        --cap-add DAC_OVERRIDE \
        --cap-add NET_BIND_SERVICE \
        --cap-add KILL \
        -p 88:8888 \
        -p $REST_PORT:$REST_PORT \
        -p $GRPC_PORT:$GRPC_PORT \
        -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket \
        -v ${PWD}:/sampleloader \
	-v /opt/ovsa/tmp_dir:/opt/ovsa/tmp_dir \
        -v /opt/ovsa/gramine/keystore:/opt/ovsa/gramine/keystore \
        -v /opt/ovsa/gramine/artefacts:/opt/ovsa/gramine/artefacts \
        -v /var/OVSA/Modelserver/server.pem:/certs/server.pem:ro \
        -v /var/OVSA/Modelserver/server.key:/certs/server.key:ro \
        -v /var/OVSA/Modelserver/client_cert_ca.pem:/certs/client_cert_ca.pem:ro \
        -v /var/OVSA/Modelserver/dhparam.pem:/certs/dhparam.pem:ro \
        -v /var/OVSA/Modelserver/client_cert_ca.crl:/certs/client_cert_ca.crl:ro \
	-v /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro \
        $MTLS_IMAGE \
        /ovms_wrapper --config_path /sampleloader/sample.json \
        --grpc_bind_address 8.8.8.8 --port $GRPC_PORT \
        --rest_bind_address 1.1.1.1 --rest_port $REST_PORT \
        --grpc_workers 1 --rest_workers 3

