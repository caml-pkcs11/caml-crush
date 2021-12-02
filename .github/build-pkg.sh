#!/bin/bash

OUTPUT=/tmp/output

git checkout debian
gbp buildpackage -uc -us -S --git-no-sign-tags --git-debian-branch=debian --git-ignore-new --git-export-dir=$OUTPUT

# Build AMD64 package
#docker run --rm -it -e DEB_BUILD_OPTIONS='parallel=1' -v ${OUTPUT}:/tmp/output  caml-crush-pkgsid gbp buildpackage -uc -us --git-no-sign-tags --git-debian-branch=debian --git-ignore-new --git-export-dir=/tmp/output