#!/bin/sh
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
# SPDX-License-Identifier: BSD-3-Clause

usage() {
cat <<EOF
Splices ondie-CA intermediate certificate from DER encoding to PEM.
Usage: $0 [options] FILE
Options:
  -h    print this help text.
EOF
  exit 0
}

while getopts ":h" opt; do
  case $opt in
    h)
      usage
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
  esac
done

if [ "$#" -ne 1 ]; then
    (>&2 echo "Error: expected 1 certificate file parameter, got: $#")
    exit 1
fi

hlen=4
rlen=0
i=0
offset=0
offset_str=""
#flen=$(stat --printf="%s" $1)
flen=$(stat -c"%s" $1)

while [ $offset -lt $flen ];do
  len=$(openssl asn1parse -in $1 -inform DER $offset_str | grep SEQUENCE | \
  head -n 1 | grep -o 'l= [0-9]\{1,\}' | grep -o '[0-9]\{1,\}')

  rlen=$(expr $hlen + $len)

  openssl asn1parse -in $1 -inform DER -length $rlen $offset_str -out $i.der \
  -noout

  openssl x509 -in $i.der -out $i.pem -inform DER -outform PEM
  rm $i.der

  offset=$(expr $offset + $rlen)
  offset_str="-offset $offset"

  i=$(expr $i + 1)
done

echo "Found $i intermediate certificates"
