# Caml Crush: an OCaml PKCS#11 filtering proxy

## Detailed project dependencies

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

