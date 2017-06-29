#!/usr/bin/env bash

PLATFORM='$(uname -m)'
NAME='$(uname -s)'
FILENAME='emerald-${TRAVIS_OS_NAME}'

mkdir /tmp/.emerald/
mv /target/release/emerald /tmp/.emerald/${FILENAME}
echo "moved release file ${FILENAME}"