#!/usr/bin/env bash

PLATFORM='$(uname -m)'
NAME='$(uname -s)'
BIN= emerald-${NAME}-${PLATFORM}

mkdir /tmp/.emerald/
mv /target/release/emerald /tmp/.emerald/${BIN}
echo "moved release file ${BIN}"