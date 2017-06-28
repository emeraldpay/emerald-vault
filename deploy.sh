#!/usr/bin/env bash

mkdir /tmp/.emerald/
PLATFORM='$(uname -m)'
NAME='$(uname -s)'

mv /target/release/emerald /tmp/.emerald/emerald-${NAME}-${PLATFORM}
