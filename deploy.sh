#!/usr/bin/env bash

set -e

APP_VERSION="$(./gitversion /showvariable FullSemVer)-$(./gitversion /showvariable ShortSha)"
VERSION_BASE="v$(./gitversion /showvariable Major).$(./gitversion /showvariable Minor).x"

CLI_ARCHIVE_NAME="emerald-cli-v$TRAVIS_OS_NAME-$APP_VERSION"
zip -j "$CLI_ARCHIVE_NAME.zip" target/release/emerald-vault
tar -zcf "$CLI_ARCHIVE_NAME.tar.gz" target/release/emerald-vault
echo "Deploy to http://builds.etcdevteam.com/emerald-cli/$VERSION_BASE/"

mkdir deploy
mv *.zip *.tar.gz deploy/
ls -l deploy/

openssl aes-256-cbc -d -in gcloud-travis.json.enc -k $GCP_PASSWD -out gcloud-travis.json
janus deploy -to="builds.etcdevteam.com/emerald-cli/$VERSION_BASE/" -files="./deploy/*" -key="./gcloud-travis.json"
echo "Deployed"
