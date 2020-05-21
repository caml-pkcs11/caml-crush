# Caml Crush: an OCaml PKCS#11 filtering proxy

This software is a computer program whose purpose is to implement
a PKCS#11 proxy as well as a PKCS#11 filter with security features
in mind.

## Introduction

The following projects aim to offer a PKCS#11 proxy with filtering capabilities.

The project is divided in submodules which are detailed below.

>1] OCaml/C PKCS#11 bindings (using OCaml IDL).

>2] XDR RPC generators (to be used with ocamlrpcgen and/or rpcgen).

>3] A PKCS#11 RPC server (daemon) in OCaml using a Netplex RPC basis.

>4] A PKCS#11 filtering module used as a backend to the RPC server.

>5] A PKCS#11 client module that comes as a dynamic library offering 
the PKCS#11 API to the software.

    There is one "optional" part:

>6] Tests in C and OCaml to be used with client module 5] or with the
bindings 1]

Here is a big picture of how the PKCS#11 proxy works:


	 ----------------------   --------  socket (TCP or Unix)  --------------------
	| 3] PKCS#11 RPC server|-|2] RPC  |<+++++++++++++++++++> | 5] Client library  |
	 ----------------------  |  Layer | [SSL/TLS optional]   |  --------          |
	           |              --------                       | |2] RPC  | PKCS#11 |
	 ----------------------                                  | |  Layer |functions|
	| 4] PKCS#11 filter    |                                 |  --------          |
	 ----------------------                                   --------------------
	           |                                                        |
	 ----------------------                                             |
	| 1] PKCS#11 OCaml     |                                  { PKCS#11 INTERFACE }
	|       bindings       |                                            |
	 ----------------------                                       APPLICATION
	           |
	           |
	 { PKCS#11 INTERFACE }
	           |
	  REAL PKCS#11 MIDDLEWARE
	     (shared library)

## Authors

  * Ryad Benadjila (<mailto:ryadbenadjila@gmail.com>)
  * Thomas Calderon (<mailto:calderon.thomas@gmail.com>)
  * Marion Daubignard (<mailto:marion.daubignard@ssi.gouv.fr>)

## Quickstart

### Dependencies - Debian/Ubuntu

    sudo apt-get install autoconf make gcc ocaml-nox camlidl coccinelle \
                         libocamlnet-ocaml-dev libocamlnet-ocaml-bin \
                         libconfig-file-ocaml-dev camlp4

### Build

    ./autogen.sh

    ./configure --with-idlgen --with-rpcgen --with-libnames=foo

    make
    
    sudo make install

[![Build Status](https://travis-ci.com/calderonth/caml-crush.svg?branch=master)](https://travis-ci.com/calderonth/caml-crush)

### Configure the middleware to use

Edit **/usr/local/etc/pkcs11proxyd/filter.conf**, uncomment the **modules** parameter to
have it point to the PKCS#11 middleware you want to use.

Example using the OpenSC middleware:

```ocaml
...
modules = [("foo", "/usr/lib/opensc-pkcs11.so")]
...
```


### Run the proxy server

    /usr/local/bin/pkcs11proxyd -fg -conf /usr/local/etc/pkcs11proxyd/pkcs11proxyd.conf


### Test it

You can test that everything is working with a PKCS#11 application, 
**pkcs11-tool** from the OpenSC suite for example. The following command will
list the available slots.


    pkcs11-tool --module /usr/local/lib/libp11clientfoo.so -L

[Dedicated tests](src/tests/ocaml/HOW_TO_PERFORM_TESTS.md) are also implemented.

## Documentation

  * More detailed documentation can be found [here](doc/INDEX.md).
  * Detailed documentation on the filter can be found [here](doc/FILTER.md).
  * Explanation on current issues and/or limitations can be found [here](ISSUES.md).
  * Explanations on how to run some tests to ensure that issues are addressed can be found [here](src/tests/ocaml/HOW_TO_PERFORM_TESTS.md).
