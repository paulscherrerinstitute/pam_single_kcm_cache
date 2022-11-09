#!/bin/sh -x

umask 022
touch ChangeLog
mkdir -p config
autoreconf -fiv -Wall
