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

  * Ryad Benadjila (<mailto:ryadbenadjila@gmail.com>)
  * Thomas Calderon (<mailto:calderon.thomas@gmail.com>)
  * Marion Daubignard (<mailto:marion.daubignard@ssi.gouv.fr>)

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
| Windows (native) |  no  |  X  |  no  |  no   |  no  |  no   |    wip    |
| Windows (cygwin) |  wip |  X  |  wip |  wip  |  wip |  wip  |    wip    |
---------------------------------------------------------------------------
    no = not implemented due to some limitations
    wip = work in progress
</pre>

  * The RPC over Unix sockets are not currently supported by rpcgen under Mac OS.
  * The Windows native port only includes the client library, see [dedicated section](WIN32.md)

### Endianness

On Linux, the project was tested on little endian and big endian architectures.
This means that it can be used on exotic platforms (say SPARC or Power PC for example). 
The server and the client do not need to have the same endianness.

## Dependencies <a name="Deps"></a>

The project dependencies requirements are detailed [here](DEPS.md).
Most users should be fine to compile Caml Crush using the pre-packaged tools.

### Package dependencies for Ubuntu/Debian

Minimal package list:

    sudo apt-get install autoconf make gcc ocaml-nox camlidl coccinelle \
                         libocamlnet-ocaml-dev libocamlnet-ocaml-bin \
                         libconfig-file-ocaml-dev camlp4

Add support for TLS/SSL with OpenSSL:

    sudo apt-get install libocamlnet-ssl-ocaml libocamlnet-ssl-ocaml-dev \
                         libssl-dev

## Configuration <a name="Configuration"></a>

Caml Crush is a versatile tool that can be thoroughly configured.
Some features are embedded at compile-time and enabled through the
use of *autoconf* and a *configure* script.

Users compiling Caml Crush should read the [pre-build checklist](PRE-BUILD.md)
in order to get a better grasp of the various parameters available.

We use autoconf to configure some of the compile time options.

  * autogen.sh is used to create the configure script.

## Build and install <a name="Build"></a>

### Building the project

From the top directory do:

    make

### Installing the project

From the top directory do:

    make install

It will perform the following action:

  * install the **pkcs11proxyd** daemon into *${PREFIX}/usr/bin*
  * install the client library to *${PREFIX}/usr/lib/*
  * copy default configuration files to *${SYSCONFDIR}/pkcs11proxyd/*

## Server configuration <a name="ServerConfiguration"></a>
The server process is based on the Netplex library from ocamlnet.
It uses a configuration file to setup the basic netplex features ([netplex documentation][]).

Several items were added in order to feed the proxy with some parameters, they are detailed
in the [dedicated section](SERVER-CONF.md)

[netplex documentation]: http://projects.camlcity.org/projects/ocamlnet.html

## Filter configuration <a name="Filter"></a>

See the [filter dedicated section](FILTER.md) for details.

## Running the server <a name="Running"></a>

By default the server will detach itself from the terminal and run as a proper
daemon. It is possible to run it as a foreground process for debugging purposes.

#### Command-line server startup

For debugging purpose, you can start the server process with the following command line:

    pkcs11proxyd -fg -conf /etc/pkcs11proxy/server.conf -debug-pkcs11

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

    pkcs11-tool --module ./libp11clientopensc.so -L

[OpenSC]: https://www.opensc-project.org/opensc/

### Client RPC timeout
Each RPC operation has a timeout that is set up (25 seconds by default).
If a **slow** cryptographic operation is performed, it is likely that the RPC layer
will abort due to the timeout. Although on the server-side the operation will
complete, the client application will catch the following example error:

    Error RPC with C_GenerateKeyPair
    error: PKCS11 function C_GenerateKeyPair failed: rv = unknown PKCS11 error (0xffffffff)

To provide some more flexibility we introduced an environment variable that can
be used to control the timeout value. Therefore, one can use `PKCS11PROXY_RPC_TIMEOUT`
to configure a custom timeout setting.

## Hardening of the server <a name="Harden"></a>

It is a sane security practice to drop unnecessary privileges at an early stage
when starting a process. We plan to provide a *sandboxing* launcher that
can be used to bootstrap our server process in another project.
This is needed because the necessary APIs to drop privileges and harden the process
are not available from OCaml. In the meantime, you can still use already
available launchers such as [capsh](http://man7.org/linux/man-pages/man1/capsh.1.html).

If one wants to manually implement sandboxing features, here are some starting points:

  * changing the id of the process if it is launched as **root**
  * chrooting the process, or using BSD Jails when available
  * dropping capabilities, see [libcap-ng](http://people.redhat.com/sgrubb/libcap-ng)
  * limiting possible system calls, see [libseccomp](http://sourceforge.net/projects/libseccomp)
  * ... and so on

### Augmenting the sandbox with user defined actions

Since there are no straightforward privilege reduction and sandboxing helpers in OCaml, 
we have implemented a specific `c_Daemonize` function in the Netplex RPC server 
([src/pkcs11proxyd/server.ml](../src/pkcs11proxyd/server.ml), see below). This function is of 
course **not** exposed in the RPC layer to the clients, it can only be called inside 
the server code. 

This function is called inside the `post_add_hook` method of the Netplex server, meaning 
that the socket is already created and bound to its given port at this point of the program, 
which implies that all the privileges can be dropped here (especially allowing listening on 
the _well-known ports_ < 1024).

```ocaml
let c_Daemonize (param) =
  debug_print_call "C_Daemonize";
  (* To keep things consistent c_Daemonize can pass through filter as well *)
  let ret = Pkcs11.c_Daemonize param in
  debug_print_ret "C_Daemonize" ret;
  (Int64.of_nativeint ret)
...

let custom_hooks =
...
      method post_add_hook _ ctrl =
...
        (* Call C_Daemonize *)
        if !ref_daemonize_args = "" then
          begin
          let param = (Pkcs11.string_to_byte_array "") in
          let _ = c_Daemonize param in
          ()
          end
        else
          begin
          let param = (Pkcs11.string_to_byte_array !ref_daemonize_args) in
          let _ = c_Daemonize param in
          ()
          end
...
```

The `c_Daemonize` OCaml function is in fact a wrapper to the `ML_CK_C_Daemonize` C function 
defined in [src/bindings-pkcs11/pkcs11\_functions.c](../src/bindings-pkcs11/pkcs11_functions.c).
This allows to inject custom native C code here (see below) to overcome OCaml's existing 
libraries limitations. For now, `ML_CK_C_Daemonize` **does not do anything**, it is rather 
an "empty shell" that you will have to fill in.

```C
CK_RV ML_CK_C_Daemonize(unsigned char *param, unsigned long param_len)
{
  CK_RV rv = 0;
  DEBUG_CALL(ML_CK_C_Daemonize, " calling\n");
  /* TODO: If you decide so, it is possible to implement some privilege
   * reduction primitives here. The advantage of doing it here is that you
   * would not need the "sandbox" launcher.
   * This is called after the OCaml netplex binds the socket.
   */
  ...
  return rv;
}
```
