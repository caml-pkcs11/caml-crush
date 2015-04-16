# Caml Crush: an OCaml PKCS#11 filtering proxy

## Detailed Server configuration
The server process is based on the Netplex library from ocamlnet.
It uses a configuration file to setup the basic netplex features ([netplex documentation][]).

Several items were added in order to feed the proxy with some parameters, they are detailed
below.

[netplex documentation]: http://projects.camlcity.org/projects/ocamlnet.html

### Server socket configuration
Netplex has the following syntax for the socket configuration.

To configure a UNIX domain:

```ocaml
...
protocol{
    ...
    type = "local";
    path = "/run/pkcs11-socket";
    ...
}
...
```

To configure a TCP socket listening on 127.0.0.1 and port 4444:

```ocaml
...
protocol{
    ...
    type = "internet";
    bind = "127.0.0.1:4444";
    ...
}
...
```

### Server SSL/TLS configuration
The SSL/TLS support can be turned on with the following configuration directives:

```ocaml
...
processor {
  ...
  use_ssl = true;
  cafile = "/etc/pkcs11proxy/certs/ca.crt";
  certfile = "/etc/pkcs11proxy/certs/server.crt";
  certkey = "/etc/pkcs11proxy/certs/server.key";
  cipher_suite = "AES256-SHA256";
  (* Optional, allows to use DHE cipher suites, generate custom DH paramerters *)
  dh_params = "/usr/local/etc/tests/certs/dhparams.pem";
  (* Optional, allows to use ECDHE cipher suites *)
  ec_curve_name = "prime256v1";
  (* Optional, allows to use a custom certificate verification depth *)
  verify_depth = 4;
  ...
};
...
```

Please note that the current implementation expects PEM files and that
the private key has to be un-encrypted.

The cipher\_suite parameter accepts the classic OpenSSL "colon" separated cipher list.
Please note that the following ciphers are explicitely turned off:

    !aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK:!RC4


**WARNING**: The [ocaml-ssl][] (0.4.6) bindings is ONLY capable of using TLS 1.0 and cannot provide PFS.
If you care about PFS, please use ocaml-ssl (0.4.7) and read the dedicated section in [ISSUES](../ISSUES.md).
[ocaml-ssl]: https://github.com/savonet/ocaml-ssl/

### Server PKCS#11 module support configuration (when filtering is DISABLED)
As mentionned previously, the client asks for a specific module name.
If you disabled the filtering engine during compilation, you have to configure the module path of the different libraries in the server configuration.

The "libnames" parameter binds module "names" and the path to the corresponding PKCS#11 library.

```ocaml
...
processor {
  ...
  libnames="opensc:/usr/lib/opensc-pkcs11.so;mysuperhsm:/usr/local/lib/libmysuperhsm.so;";
  ...
};
...
```

This parameter is ignored when the project is compiled with filtering capabilities.

### Server PKCS#11 filter configuration path

When filtering is enabled, the PKCS#11 server fetches the filtering rules from a file whose path must 
be provided in the main server configuration file, in the `processor` section.

```ocaml
...
processor {
  ...
  filter_config="PATH/filter.conf";
  ...
};
...
```
