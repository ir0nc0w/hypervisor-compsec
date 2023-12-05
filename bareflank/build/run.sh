#!/usr/bin/bash

sudo ./prefixes/x86_64-userspace-elf/bin/bfm load ./prefixes/x86_64-vmm-elf/bin/hook

sudo ./prefixes/x86_64-userspace-elf/bin/bfm start

sudo make dump

./prefixes/x86_64-userspace-elf/bin/hook

sudo ./prefixes/x86_64-userspace-elf/bin/bfm stop
