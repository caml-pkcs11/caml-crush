#!/bin/bash

main_dir="./"
bindings_dir="src/bindings-pkcs11"
rpc_dir="src/rpc-pkcs11"
server_dir="src/pkcs11proxyd"
client_dir="src/client-lib"
filter_dir="src/filter"
filter_filter_dir="src/filter/filter"
filter_backend_dir="src/filter/backend"
filter_frontend_dir="src/filter/frontend"
tests_dir="src/tests"
ocaml_tests_dir="src/tests/ocaml"
c_tests_dir="src/tests/c-based"
scripts_dir="scripts"

clean_dirs=($main_dir $bindings_dir $rpc_dir $server_dir $client_dir $filter_dir $filter_filter_dir $filter_backend_dir $filter_frontend_dir $tests_dir $ocaml_tests_dir $c_tests_dir)

echo "Cleaning the project ..."
make clean &> /dev/null
echo "Cleaning AUTOCONF files ..."
rm -rf autom4te.cache config.log config.status configure 
echo "Cleaning Makefiles ..."
for (( i = 0 ; i < ${#clean_dirs[*]} ; i++ ))
do
  rm -f ${clean_dirs[i]}/Makefile
done
rm -f ${bindings_dir}/Makefile.standalone
echo "Cleaning initrc file ..."
rm -rf ${scripts_dir}/pkcs11proxyd
echo "Cleaning the SSL related files ..."
rm -f create_ssl_files.c create_ssl_files src/client-lib/cert_file.h src/client-lib/ca_file.h src/client-lib/private_key_file.h src/rpc-pkcs11/ca_file.inc src/rpc-pkcs11/cert_file.inc src/rpc-pkcs11/private_key_file.inc
