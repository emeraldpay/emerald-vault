#!/usr/bin/env bash

APP_VERSION="$(./gitversion /showvariable FullSemVer)-$(./gitversion /showvariable ShortSha)"
VERSION_BASE="v$(./gitversion /showvariable Major).$(./gitversion /showvariable Minor).x"

CLI_ARCHIVE_NAME="emerald-cli-$TRAVIS_OS_NAME-$APP_VERSION"
zip -j "$CLI_ARCHIVE_NAME.zip" target/release/emerald-vault
tar -zcf "$CLI_ARCHIVE_NAME.tar.gz" target/release/emerald-vault
echo "Deploy to http://builds.etcdevteam.com/emerald-cli/$VERSION_BASE/"

mkdir deploy
mv *.zip *.tar.gz deploy/
ls -l deploy/

janus deploy -to="builds.etcdevteam.com/emerald-cli/$VERSION_BASE/" -files="./deploy/*" -key="./gcloud-travis.json.enc"
echo "Deployed"
