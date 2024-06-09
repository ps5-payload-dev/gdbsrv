#!/usr/bin/env -S gdb -x

target extended-remote :1234
file sample.linux.elf

remote put sample.linux.elf /tmp/sample.linux.elf
set remote exec-file /tmp/sample.linux.elf
start
