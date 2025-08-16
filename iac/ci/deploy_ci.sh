#!/usr/bin/env bash
# deploy the CI workflow to .github/workflows
mkdir -p .github/workflows
cp "$(dirname "$0")/ci.yml" .github/workflows/ci.yml
echo "Deployed ci.yml to .github/workflows/"
