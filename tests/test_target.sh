#!/usr/bin/env bash
# Test that pentest.sh targets the correct host
set -euo pipefail
if grep -q "TARGET=\"api.platform.bitnob.com\"" ./pentest.sh; then
  echo "TARGET is correctly set"
  exit 0
else
  echo "TARGET is NOT set to api.platform.bitnob.com"
  exit 1
fi
