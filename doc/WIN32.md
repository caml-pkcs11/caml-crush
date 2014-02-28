# Caml Crush: an OCaml PKCS#11 filtering proxy

## Windows support

This page explains how to build on Microsoft Windows.
Please note that this support is experimental and incomplete.

## Client library
Because of the lack of proper tool on Windows, you will have to
download and prepare the source on a "Linux" environment (it can be
done in Cygwin).

Download the source code and prepare it with the following commands:

    cd src/client-lib
    #Copy file in order to get correct include path in file generated
    cp ../rpc-pkcs11/pkcs11_rpc.x ./
    #Generate header for Win32 compatibility (i.e. without MT support)
    rpcgen -h -N pkcs11_rpc.x > pkcs11_rpc.h
    #Generate xdr helpers
    rpcgen -c -N pkcs11_rpc.x > pkcs11_rpc_xdr.c
    #Generate client stubs
    rpcgen -l -N pkcs11_rpc.x > pkcs11_rpc_clnt.c
    #Remove local copy of XDR file
    rm pkcs11_rpc.x
    #Patch generated xdr implementation (optional: remove unused buffer)
    spatch --no-show-diff --sp-file ./pkcs11_rpc_xdr.cocci ./pkcs11_rpc_xdr.c --in-place


### Dependencies
There is not native support of ONC RPC for Microsoft Windows. However some porting efforts have been made
in the past. The open source oncrpc-win32 has been modified and is used in order to provide the
RPC layer in the client library.

There is no upstream, so you will have to use our modified version of [oncrpc-win32][].
You can use the projects file with Visual Studio to build the "librpc" target.

[oncrpc-win32]: https://github.com/tc-anssi/oncrpc-win32

The build has been tested on Visual Studio 2012.

Please note that you will have to select the "right" target depending on your need.
We have tried both static and DLL approach.
The Makefile.Win32 that we provide will expect a static library "oncrpc.lib" to link against.
(Modify the solution properties to your need (arch, DLL/Static, C-Runtime).

### Configuring Windows build environment
Please refer to Makefile.Win32 and adapt the include paths.

Note that you will have to adapt the makefile to configure the
client to reach the proxy server.

### Build
Once the oncrpc library and the client source code is prepared, copy the code on the Windows build environment
and compile with the following commands.

    cd src\client-lib
    nmake /f Makefile.Win32 nodebug=1

This should start the compilation, you will end up with a DLL matching the libname you
provided in the Makefile (libclientp11.dll).

To build the debug target, remove the "nodebug=1" parameter. However note that you have to
link against a coherent (Debug/Release) version of oncrpc.lib

### Test it

You can test that everything is working with a PKCS#11 application, 
**pkcs11-tool** from the OpenSC suite for example. The following command will
list the available slots.


    pkcs11-tool --module <Path-to-my-newly-compiled-library>\libp11client.dll
