#!/bin/bash

#set parameters needed for gbp import
git config --global user.email "calderon.thomas@gmail"
git config --global user.name "Thomas Calderon"

echo Generating package for $BRANCH_NAME, will output in $DEB_OUTPUT_CONTAINER

COMMIT_SHORT=1.0.x-$(git rev-parse --short HEAD)
git archive --format=tar.gz --prefix=caml-crush-$COMMIT_SHORT/ HEAD > ../caml-crush-$COMMIT_SHORT.tar.gz

#Track needed branches
git checkout --track origin/upstream
git checkout --track origin/debian

gbp import-orig --debian-branch=debian -u $COMMIT_SHORT ../caml-crush-$COMMIT_SHORT.tar.gz

COMMIT_TS=$(git show -s --pretty=format:%ct HEAD)
COMMIT_DATE=$(date --date="@${COMMIT_TS}" +%Y%m%d%H%M)
GBP_SINCE_PARAM="--auto"
export DEBEMAIL="calderon.thomas@gmail.com"
export DEBFULLNAME="Thomas Calderon"
gbp dch $GBP_SINCE_PARAM --snapshot --snapshot-number="${COMMIT_DATE}" --no-multimaint --ignore-branch

gbp buildpackage -uc -us --git-no-sign-tags --git-debian-branch=debian --git-ignore-new

#copy all artefacts in output directory
mv ../caml-crush* $DEB_OUTPUT_CONTAINER/