#!/usr/bin/env bash

PLATFORM='$(uname -m)'
NAME='$(uname -s)'

mkdir /tmp/.emerald/
mv /target/release/emerald /tmp/.emerald/emerald-${TRAVIS_OS_NAME}
echo "moved release file ${TRAVIS_OS_NAME}"