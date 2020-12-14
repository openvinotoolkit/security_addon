#
# Copyright (c) 2020 Intel Corporation
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

echo "Generating License Server certificate..."
echo "===================================================================================================================================================="
echo "WARNING: For development and testing only. Please follow your organization security practices on handling and distribution of cryptography material."
echo "===================================================================================================================================================="

rm -rf /opt/ovsa/certs && mkdir /opt/ovsa/certs && cd /opt/ovsa/certs
openssl ecparam -name secp521r1 -genkey -out server.key
openssl req -new -out server.csr -key server.key -subj "/C=IN/CN=localhost"
openssl x509 -signkey server.key -in server.csr -sha384 -req -days 365 -out server.crt
cd -

