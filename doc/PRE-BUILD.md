# Caml Crush: an OCaml PKCS#11 filtering proxy

## Pre-build checklist

### IDL and RPC code generation

Some portions of code are generated with tools. 
The code in the source tree was generated on a *64-bit* machine.
If you want to compile on an 32-bit architecture, you have to trigger the generation of those files. 
This is done at configure time with the flags described below.

To re-generate the OCaml/C stubbing code, use:

  * --with-idlgen

To re-generate the RPC client/server code as well:

  * --with-rpcgen

### Client type selection
We support two types of client libraries, an OCaml/C hybrid version and a full C version.
The two implementations have the same feature set, the main difference being that the hybrid one relies on 
ocamlnet for the transport layer. The compiled library embeds the OCaml runtime which is rather big (~3MB).
The C version has a lighter memory footprint, it is the default at compile-time.

To compile the client library with native C RPC code (this is the DEFAULT):

  * --with-cclient

To compile the hybrid OCaml/C client library:

  * --with-ocamlclient

### PKCS#11 multi-module support
When the client connects to the proxy server it asks for a specific PKCS#11 module to be loaded. This allows the proxy server to support
multiple PKCS#11 libraries (so called "middlewares").
The server looks up in its configuration file for a matching module name (ex: "opensc") with a library path to load (ex: /usr/lib/opensc-pkcs11.so).
By default, the client library will read the module name from the **.camlcrushlibname** file located in the current user's directory. In this case, a single client library is compiled `libp11client.so`

The --with-libname-file flag enables the behavior previously described (this is the DEFAULT).

This behavior can be modified to compile as many client libraries as supported modules.
The generated client libraries have the following syntax `libp11client<modulename>.so`

The --with-libnames can be used to compile multiple client libraries with different module names.

  * --with-libnames="opensc,mysuperhsm"
    * (libp11clientopensc.so and libp11clientmysuperhsm.so are generated)

In the two cases described above, an environment variable can be used to change the module name that will be sent to the proxy server.
This behavior is controlled using the `PKCS11PROXY_LIBNAME` variable.

### Client socket configuration
The client library socket is defined at compile time.
Use --with-client-socket to configure the client socket.

  * --with-client-socket=unix,/run/pkcs11-socket
    * (client will connect to UNIX domain socket located at /run/pkcs11-socket)
  * --with-client-socket=tcp,127.0.0.1:4444
    * (client will establish a TCP socket with remote peer 127.0.0.1 and port 4444)

However, an environment variable can be used to change the socket parameters.
This behavior is controlled using the `PKCS11PROXY_SOCKET_PATH` variable.
Please note that you cannot change the socket type, only UNIX path or TCP parameters.

### Enable SSL/TLS support
The link between the client and the server can be secured using TLS mutual
authentication via certificates.
To enable SSL use one of the following flag:

  * --with-ssl
  * --with-gnutls

OpenSSL or GnuTLS stacks can be used by the client library, the OCaml stack only uses bindings to OpenSSL.

#### Client SSL/TLS support
Use --with-ssl-clientfiles to provide CA chain and client certificate and private key.

The client can be compiled to use three modes, file lookup, environment variables (default) or embedding the credentials inside the code.

  * --with-ssl-clientfiles='path;ca=path-to-ca,cert=path-to-cert,privkey=path-to-key'
    * (client will load files with given path at runtime)

  * --with-ssl-clientfiles='env'
    * (client will lookup the following environment variables `PKCS11PROXY_CA_FILE`, `PKCS11PROXY_CERT_FILE` and `PKCS11PROXY_PRIVKEY_FILE`)

  * --with-ssl-clientfiles='embed;ca=path-to-ca,cert=path-to-cert,privkey=path-to-key'
    * (the files will be parsed and embedded within the compiled code through C headers)

#### Server SSL/TLS support
The server uses its configuration file to enable SSL/TLS and to configure its private key and the path to certificates.

### Disable filtering capabilities
You can compile the proxy server without filtering capabilities with the --without-filter switch.
In this case, the server will directly send PKCS#11 requests to the PKCS#11 library.
This is NOT recommended and should not be used in production.
