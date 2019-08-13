#!/usr/bin/env bash

VERSION_BASE=$(janus version -format='v%M.%m.x')
CLI_ARCHIVE_NAME="emerald-cli-$TRAVIS_OS_NAME-$APP_VERSION"
zip -j "$CLI_ARCHIVE_NAME.zip" target/release/emerald
tar -zcf "$CLI_ARCHIVE_NAME.tar.gz" target/release/emerald
echo "Deploy to http://builds.etcdevteam.com/emerald-cli/$VERSION_BASE/"

mkdir deploy
mv *.zip *.tar.gz deploy/
ls -l deploy/

janus deploy -to="builds.etcdevteam.com/emerald-cli/$VERSION_BASE/" -files="./deploy/*" -key="./gcloud-travis.json.enc"
echo "Deployed"