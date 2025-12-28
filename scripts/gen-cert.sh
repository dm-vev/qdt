#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: $0 <cert.pem> <key.pem>" >&2
  exit 1
fi

cert=$1
key=$2

openssl req -x509 -newkey rsa:2048 -sha256 -days 365 \
  -nodes -keyout "$key" -out "$cert" \
  -subj "/CN=135.181.7.44.sslip.io"
