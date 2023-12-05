#!/bin/bash -e


# Remove existing bareflank module
./uninstall.sh || true

cmake ..
patch -p1 < string.patch

make -j`nproc`
