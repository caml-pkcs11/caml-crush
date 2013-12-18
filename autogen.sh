#!/bin/sh

echo "[Generating configure file ...]"
echo "  |-> Run ./configure with the desired options, and then make"
autoconf configure.ac > configure
chmod +x ./configure
