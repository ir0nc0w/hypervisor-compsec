#!/bin/bash -e


# Remove existing bareflank module
./uninstall.sh || true

cmake ..

make -j`nproc`
