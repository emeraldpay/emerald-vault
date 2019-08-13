#!/usr/bin/env bash

set -e

VERSION_BASE="v$(gitversion /showvariable Major).$(gitversion /showvariable Minor).x"
CLI_ARCHIVE_NAME="emerald-cli-mac-$APP_VERSION_GIT_TAG"
mv target/release/emerald-vault ./emerald
zip -j "$CLI_ARCHIVE_NAME.zip" emerald
tar -zcf "$CLI_ARCHIVE_NAME.tar.gz" emerald
echo "Deploy to http://builds.etcdevteam.com/emerald-cli/$VERSION_BASE/"

mkdir deploy
mv *.zip *.tar.gz deploy/
ls -l deploy/

openssl aes-256-cbc -d -in .circleci/gcloud-circleci.json.enc -k $GCP_PASSWD -out gcloud-circleci.json -md sha256
janus deploy -to="builds.etcdevteam.com/emerald-cli/$VERSION_BASE/" -files="deploy/*" -key="gcloud-circleci.json"
echo "Deployed"
