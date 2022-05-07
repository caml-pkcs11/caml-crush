#!/bin/sh

echo "[Generating configure file ...]"
aclocal
if [ "${OS}" = "Windows_NT" ]
then
  echo "  |-> Using Cygwin environment"
  cp Makefile.Win32.in Makefile.in
  autoconf configure-win32.ac > configure
else
  cp Makefile.Unix.in Makefile.in
  autoupdate
  autoconf configure.ac > configure
fi
echo "  |-> Run ./configure with the desired options, and then make"
chmod +x ./configure
