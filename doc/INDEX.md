# Caml Crush: an OCaml PKCS#11 filtering proxy

This software is a computer program whose purpose is to implement
a PKCS#11 proxy as well as a PKCS#11 filter with security features
in mind.


## Summary

  * [Introduction](#Introduction)
  * [Authors](#Authors)
  * [OS Support](#OSSupport)
  * [Dependencies](#Deps)
  * [Configure (compilation)](#Configuration)
  * [Building the project](#Build)
  * [Server configuration](#ServerConfiguration)
  * [Filter configuration](#Filter)
  * [Running the server](#Running)
  * [Running a client application](#RunningClient)
  * [Hardening of the server](#Harden)

## <a name="Introduction"></a> Introduction

The following projects aim to offer a PKCS#11 proxy with filtering capabilities.

The project is divided in submodules which are detailed below.


    1] OCaml/C PKCS#11 bindings (using OCaml IDL).
    2] XDR RPC generators (to be used with ocamlrpcgen and/or rpcgen).
    3] A PKCS#11 RPC server (daemon) in OCaml using a Netplex RPC basis.
    4] A PKCS#11 filtering module used as a backend to the RPC server.
    5] A PKCS#11 client module that comes as a dynamic library offering 
       the PKCS#11 API to the software.

    There is one "optional" part:

    6] Tests in C and OCaml to be used with client module 5] or with the
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

## Authors <a name="Authors"></a>

  * Ryad Benadjila (<mailto:ryad.benadjila@ssi.gouv.fr>)
  * Thomas Calderon (<mailto:thomas.calderon@ssi.gouv.fr>)

## OS Support <a name="OSSupport"></a>

<pre>
---------------------------------------------------------------------------
|                  |  C Client  | OCaml client | pkcs11proxyd |  SSL/TLS  |
| Operating system | Unix | TCP | Unix |  TCP  | Unix |  TCP  |           |
|:----------------:|:----:|:---:|:----:|:-----:|:----:|:-----:|:---------:|
| Linux i386       |   X  |  X  |   X  |   X   |   X  |   X   |     X     |
| Linux amd64      |   X  |  X  |   X  |   X   |   X  |   X   |     X     |
| Mac OS X         |  no  |  X  |   X  |   X   |   X  |   X   |     X     |
| FreeBSD amd64    |   X  |  X  |   X  |   X   |   X  |   X   |     X     |
| Windows (cygwin) |  wip |  X  |  wip |  wip  |  wip |  wip  |    wip    |
---------------------------------------------------------------------------
    no = not implemented due to some limitations
    wip = work in progress
</pre>

  * The RPC over Unix sockets are not currently supported by rpcgen under Mac OS.

### Endianness

On Linux, the project was tested on little endian and big endian architectures.
This means that it can be used on exotic platforms (say SPARC or Power PC for example). 
The server and the client do not need to have the same endianness.

## Dependencies <a name="Deps"></a>

0] The projects has the following generic dependencies:

  * autoconf
  * make
  * sed
  * C compiler (tested with GCC and Clang)

1] The bindings have the following dependencies:

  * [ocaml][] (`>`= 3.12)
  * [camlidl][] (`>`= 1.05)
  * [coccinelle][] (`>`= 1.0rc10)

[ocaml]: http://caml.inria.fr/ocaml/index.fr.html
[coccinelle]: http://coccinelle.lip6.fr/
[camlidl]: http://caml.inria.fr/pub/old_caml_site/camlidl/

2] The XDR RPC generators (to be used with ocamlrpcgen for the server and the OCaml client, 
and/or rpcgen for the C client).

  * ocamlrpcgen (libocamlnet-ocaml-bin) shipped with [ocamlnet][]
  * rpcgen (shipped with libc)

3] A PKCS#11 RPC server (daemon) in OCaml using a Netplex RPC basis.

  * [ocamlnet][] (`>`= 3.5.1, libocamlnet-ocaml-dev)
    * with ocamlnet-ssl if build with SSL
      (libocamlnet-ssl-ocaml libocamlnet-ssl-ocaml-dev)

[ocamlnet]: http://projects.camlcity.org/projects/ocamlnet.html

4] A PKCS#11 filtering module used as a backend to the RPC server.

  * [config-file][], simple OCaml configuration parser (libconfig-file-ocaml-dev)

[config-file]: http://config-file.forge.ocamlcore.org/
5] The client library has the following dependencies:

  * RPC client code
    * C client (default and recommended)
      * built-in "rpcgen" binary (shipped with libc)
      * [OpenSSL][]/[GnuTLS][] if SSL/TLS support is enabled

[OpenSSL]: http://www.openssl.org/
[GnuTLS]: http://www.gnutls.org/

    * OCaml client (given as an alternative)
      * ocamlnet
      * ocamlnet-ssl if SSL/TLS support is enabled
      * OCaml static libasmrun.a compiled with -fPIC
        * We noticed that OCaml is not built with -fPIC by default, you will
          need to recompile OCaml and all the other libraries to get this working.

### Package dependencies for Ubuntu/Debian

Minimal package list:

    sudo apt-get install autoconf make gcc ocaml-nox camlidl coccinelle \
                         libocamlnet-ocaml-dev libocamlnet-ocaml-bin \
                         libconfig-file-ocaml-dev

Add support for TLS/SSL with OpenSSL:

    sudo apt-get install libocamlnet-ssl-ocaml libocamlnet-ssl-ocaml-dev \
                         libssl-dev

## Configuration <a name="Configuration"></a>

We use autoconf to configure some of the compile time options.

  * autogen.sh is used to create the configure script.

### IDL and RPC code generation

Some portions of code are generated with tools. 
The code in the source tree was generated on a 64-bit machine.
If you want to compile on an 32-bit machine, you have to trigger the generation of those files. 
This is done by adding the following flags at configure time:

Use --with-idlgen to re-generate the OCaml/C stubbing code.

Use --with-rpcgen can be used to re-generate the RPC client/server code as well.

### Client type selection
We support two types of client libraries, an OCaml/C hybrid version and a full C version.
The two implementations have the same feature set, the main difference being that the hybrid one relies on 
ocamlnet for the transport layer. Therefore it is necessary to build this library with the OCaml runtime, which
ends up with a rather big library (~3MB).
This is why we recommend the C version.

Use --with-cclient to compile the client library with native C RPC code (this is the DEFAULT).

Use --with-ocamlclient to compile the hybrid OCaml/C client library.

### PKCS#11 multi-module support
When the client connects to the proxy server it asks for a specific PKCS#11 module to be loaded. This allows the proxy server to support
multiple PKCS#11 libraries (so called "middlewares").
The server looks up in its configuration file for a matching module name (ex: "opensc") with a library path to load (ex: /usr/lib/opensc-pkcs11.so).
Therefore, there will be as many client libraries as supported modules.
The generated client libraries have the following syntax `libp11client<modulename>.so`

The --with-libnames can be used to compile multiple client libraries with different module names.

  * --with-libnames="opensc,mysuperhsm"
    * (libp11clientopensc.so and libp11clientmysuperhsm.so are generated)

If no choice are given a library will be generated, when loaded, this library will ask the server to load a module with an
empty string, it is the server's role to decide whether to fallback on a default module or to block the call.

### Client socket configuration
Use --with-socket to configure the client socket.

  * --with-socket=unix,/run/pkcs11-socket
    * (client will connect to UNIX domain socket located at /run/pkcs11-socket)
  * --with-socket=tcp,127.0.0.1:4444
    * (client will establish a TCP socket with remote peer 127.0.0.1 and port 4444)

### Enable SSL/TLS support
Use --with-ssl to enable the SSL/TLS code (OpenSSL by default, can use --with-gnutls).

#### Client SSL/TLS support
Use --with-ssl-clientfiles to provide CA chain and client certificate and private key.

The client can be compiled to use three modes, file lookup, environement variables or embedding the credentials inside the code.

  * --with-ssl-clientfiles='path;ca=path-to-ca,cert=path-to-cert,privkey=path-to-key'
    * (client will load files with given path at runtime)

  * --with-ssl-clientfiles='env'
    * (client will lookup the following environement variables PKCS11PROXY\_SSL\_CA, PKCS11PROXY\_SSL\_CERT and PKCS11\_SSL\_PRIVKEY)

  * --with-ssl-clientfiles='embed;ca=path-to-ca,cert=path-to-cert,privkey=path-to-key'
    * (the files will be parsed and embedded within the compiled code through C headers)

#### Server SSL/TLS support
The server uses its configuration file to enable SSL/TLS and configure the certificate paths.

### Disable filtering capabilities
You can compile the proxy server without filtering capabilities with the --without-filter switch. In this case, 
the server will directly send PKCS#11 requests to the PKCS#11 library.

## Build and install <a name="Build"></a>

### Building the project

From the top directory do:

    make

### Installing the project

From the top directory do:

    make install

It will perform the following action:

  * install the **pkcs11proxyd** daemon in the *${PREFIX}/usr/bin* directory
  * copy default configuration files to *${PREFIX}/etc/pkcs11proxyd/*

## Server configuration <a name="ServerConfiguration"></a>
The server process is based on the Netplex library from ocamlnet.
It uses a configuration file to setup the basic netplex features ([netplex documentation][]).

Several items were added in order to feed the proxy with some parameters, they are detailed
below.

[netplex documentation]: http://projects.camlcity.org/projects/ocamlnet.html

### Server socket configuration
Netplex has the following syntax for the socket configuration.

To configure a UNIX domain:

    ...
    protocol{
        ...
        type = "local";
        path = "/run/pkcs11-socket";
        ...
    }
    ...

To configure a TCP socket listening on 127.0.0.1 and port 4444:

    ...
    protocol{
        ...
        type = "internet";
        bind = "127.0.0.1:4444";
        ...
    }
    ...

### Server SSL/TLS configuration
The SSL/TLS support can be turned on with the following configuration directives:

    ...
    processor {
      ...
      use_ssl = true;
      cafile = "/etc/pkcs11proxy/certs/ca.crt";
      certfile = "/etc/pkcs11proxy/certs/server.crt";
      certkey = "/etc/pkcs11proxy/certs/server.key";
      cipher_suite = "AES256-SHA256";
      ...
    };
    ...

The cipher\_suite parameter accepts the classic OpenSSL "colon" separated cipher list.
Please note that the following ciphers are explicitely turned off:

    !aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK:!RC4


**WARNING**: As of today, the [ocaml-ssl][] (0.4.6) bindings is ONLY capable of using TLS 1.0 and cannot provide PFS.
If you care about PFS, please read the dedicated section in [ISSUES](../ISSUES.md).
[ocaml-ssl]: https://github.com/savonet/ocaml-ssl/

### Server PKCS#11 module support configuration (when filtering is DISABLED)
As mentionned previously, the client asks for a specific module name.
If you disabled the filtering engine during compilation, you have to configure the module path of the different libraries in the server configuration.

The "libnames" parameter binds module "names" and the path to the corresponding PKCS#11 library.

    ...
    processor {
      ...
      libnames="opensc:/usr/lib/opensc-pkcs11.so;mysuperhsm:/usr/local/lib/libmysuperhsm.so;";
      ...
    };
    ...

This parameter is ignored when the project is compiled with filtering capabilities.

### Server PKCS#11 filter configuration path

When filtering is enabled, the PKCS#11 server fetches the filtering rules from a file whose path must 
be provided in the main server configuration file, in the `processor` section.

    ...
    processor {
      ...
      filter_config="PATH/filter.conf";
      ...
    };
    ...


## Filter configuration <a name="Filter"></a>

See the [filter dedicated section](FILTER.md) for details.

## Running the server <a name="Running"></a>

By default the server will detach itself from the terminal and run as a proper
daemon. It is possible to run it as a foreground process for debugging purposes.

#### Command-line server startup

For debugging purpose, you can start the server process with the following command line:

  * pkcs11proxyd -fg -conf /etc/pkcs11proxy/server.conf -debug-pkcs11

This will start the daemon in foreground mode and turn on the tracing of PKCS#11 RPC calls.

#### Init script startup

A basic init script can be found in the *scripts* directory. You **must** adapt it to your needs.

Once this is done, you can copy it to */etc/init.d/*. The server will not be launched at startup until
a symlink is created for each runlevels the daemon should be started.
This is done by calling this command (*defaults* might not suit your needs):

    update-rc.d -f pkcs11proxyd defaults

## Running a client application <a name="RunningClient"></a>

Once the server is running, you can use a PKCS#11 compliant application with the generated libraries.

For instance, you could use "pkcs11-tool" from the [OpenSC][] suite to query slot information from the client library.

  * pkcs11-tool --module ./libp11clientopensc.so -L

[OpenSC]: https://www.opensc-project.org/opensc/

## Hardening of the server <a name="Harden"></a>

It is a sane security practice to drop unnecessary privileges at an early stage
when starting a process. We plan to provide a *sandboxing* launcher that
can be used to bootstrap our server process in another project.
This is needed because the necessary APIs to drop privileges and harden the process
are not available from OCaml. In the meantime, you can still use already
available launcher such as **capsh**.

### Augmenting the sandbox

**FIXME**: Document C\_Daemonize() function call that can be use to finalize
privilege reduction.
