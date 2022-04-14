#!/bin/bash

platforms="linux"
export GOARCH="amd64"

if [[ $# -ne "0" ]]; then
    case "$1" in
        all) platforms="linux darwin windows"
            ;;
        linux) platforms="linux"
            ;;
        mac) platforms="darwin"
            ;;
        win) platforms="windows"
            ;;
    esac
fi

binBase="../bin"

for platform in $platforms; do
    binDir="${binBase}/${platform}-${GOARCH}"
    mkdir -p ${binDir}
    echo "Building v7.1.1 for ${platform}.."
    if [[ "${platform}" == "windows" ]]; then
        ext=".exe"
    else
        ext=""
    fi
    TARGET=${binDir}/terraform-provider-vtm_v7.1.1${ext}
    CGO_ENABLED=0 GOOS=$platform go build -mod=vendor -o ${TARGET} \
        -a -ldflags '-extldflags "-static -s"' .
done
