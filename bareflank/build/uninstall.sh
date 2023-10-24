#!/bin/bash -e

# Unload Bareflank from the system
make unload

# Unlaod Bareflank's driver
make driver_unload
