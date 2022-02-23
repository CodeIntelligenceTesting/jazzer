#!/usr/bin/env bash

if [ -n "${1}" ]; then
  echo "BUILD_BUDDY_CONFIG=--config=ci --remote_header=x-buildbuddy-api-key=${1}";
else
  echo "";
fi
