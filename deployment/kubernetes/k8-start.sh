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

echo "Preparing OVSA Deployment..."

if [ -e $1 ]
then
	echo
        echo "Please specify the DNS name of Master node"
	echo "Execution: ./k8-start.sh \`hostname --fqdn\`"
	echo
	exit
fi

rm -rf $HOME/.kube
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

echo "Starting Flannel...."
#Deploy the Flannel
kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml

echo ""
echo "Starting Generic Device Plugin..."
#Deploy Generic device plugin
kubectl apply -f /opt/ovsa/k8/generic-device-plugin.yaml

echo ""
echo "Install istio inside the cluster ..."
#Install ISTIO in the cluster
/opt/ovsa/k8/istio-1.14.1/bin/istioctl install --set profile=default -y

echo "Inject sidecar proxy to the nodes..."
kubectl label namespace default istio-injection=enabled

sleep 5

echo ""
echo "Creating Secret for TLS and Authentication..."
#Add Certificates to Secret
kubectl create -n istio-system secret generic tls-secret --from-file=tls.crt=/var/OVSA/k8/server.crt --from-file=tls.key=/var/OVSA/k8/server.key --from-file=ca.crt=/var/OVSA/k8/ca.crt


#update Master Node FQDN in Deployment.template and create deployment.yaml file
if [ -e ovsa-deployment.yaml ]
then
	rm ovsa-deployment.yaml
fi
sed 's/FQDN-name/'$1'/g' ovsa-deployment.yaml.template > ovsa-deployment.yaml

#echo "Edit API Server Manifest file to update no-proxy, before deploying OVSA Deployment..."
echo "Starting OVSA Deployment..."
#Start OVSA Deployment
kubectl apply -f ovsa-deployment.yaml
