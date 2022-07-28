#!/usr/bin/env bash
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

set -eu -o pipefail

declare -a urls

usage() {
    echo "Usage: download --url https://example.org/test --url https://mirror.example/blah --output test.tar --sha256 1234..abc"
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --url)
            urls+=("$2")
            shift
            ;;
        --output)
            output="$2"
            shift
            ;;
        --sha256)
            sha256="$2"
            shift
            ;;
        --help|-h)
            usage
            ;;
        *)
            usage 1
            ;;
    esac
    shift
done

if [ -z "${output:-}" ] || [ -z "${sha256:-}" ] || [ -z "${urls[*]}" ]; then
    usage 1
fi

if [ -n "${DL_CACHE:-}" ]; then
    if [ -f "$DL_CACHE/$sha256" ]; then
        echo "download: Found '$output' (${sha256:0:8}...) in cache."
        cp "$DL_CACHE/$sha256" "$output"
        exit 0
    fi
fi

if [ "${DL_OFFLINE:-}" == "true" ]; then
    echo "download: ERROR: File '$output' (${sha256:0:8}...) not found in cache and offline mode is active!"
    exit 1
fi

tmpd="$(mktemp -d -p "${DL_CACHE:-.}")"
cleanup() {
    rm -rf "$tmpd"
}
trap cleanup EXIT

for url in "${urls[@]}"; do
    echo "download: Trying to fetch $url"
    wget --no-check-certificate --timeout=10 -O "$tmpd/unverified" "$url" || true
    sha256_received="$(sha256sum "$tmpd/unverified" | cut -d ' ' -f 1)"
    if [ "$sha256" != "$sha256_received" ]; then
        echo "download: WARNING: Hash mismatch: Expected $sha256 but received $sha256_received"
        continue
    fi
    echo "download: Fetched '$output' (${sha256:0:8}...) successfully."
    if [ -n "${DL_CACHE:-}" ]; then
        mv "$tmpd/unverified" "$DL_CACHE/$sha256"
        cp "$DL_CACHE/$sha256" "$output"
        exit 0
    fi
    mv "$tmpd/unverified" "$output"
    exit 0
done

echo "download: ERROR: Failed to download '$output' (${sha256:0:8}...)! No URLs left to try."
exit 1
