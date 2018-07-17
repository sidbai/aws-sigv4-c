#!/usr/bin/env bash

set -ex

mkdir -p build || true
mkdir -p aws_sigv4/deps || true

get_check() {
    if [ -f "aws_sigv4/deps/check_installed" ]; then
        return
    fi
    rm -rf aws_sigv4/deps/check
    pushd aws_sigv4/deps
    git clone --depth 1 https://github.com/libcheck/check.git
    cd check
    git fetch --tags
    # Use a stable release version
    git checkout tags/0.12.0 -b 0.12.0
    autoreconf --install
    ./configure
    make
    make check
    sudo make install
    popd
    touch "aws_sigv4/deps/check_installed"
}

build_aws_sigv4() {
    # Build into build dir
    pushd build
    cmake ../aws_sigv4
    make
    CTEST_OUTPUT_ON_FAILURE=1 make test
    popd
}

get_check
build_aws_sigv4
