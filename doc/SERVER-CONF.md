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

### Server SSL/TLS configuration for versions > 1.0.6
The SSL/TLS support can be turned on with the following configuration directives:

```ocaml
...
processor {
  ...
      tls {
        (* Ciphersuites, GnuTLS syntax *)
        (* TLS 1.2, PFS-only suites, no DSS, no CAMELLIA *)
        algorithms = "SECURE256:+SECURE128:-VERS-TLS-ALL:+VERS-TLS1.2:-RSA:-DHE-DSS:-CAMELLIA-128-CBC:-CAMELLIA-256-CBC";

        (* Uncomment to enable DHE parameters, used for PFS *)
        (*
        dh_params {
          (* Pre-computed DH parameters *)
          pkcs3_file = "/etc/pkcs11proxyd/dhparams.pem";
          (* Run-time DH parameters, warning: this takes a long time *)
          (*bits = 2048;*)
        };
        *)
        x509 {
         key {
           crt_file = "server.pem";
           key_file = "server.key";
         };
         trust {
           crt_file = "cacert.pem";
         };
        }
      };
  ...
};
...
```

Please note that the current implementation expects PEM files and that
the private key has to be un-encrypted.

The algorithm parameter accepts GnuTLS cipher list, the default only allows TLS 1.2 and modern PFS-enabled suites.
The dh\_params can be configured to enable DHE suites. Also, parameters can be generated at startup but note that it will slow down startup.

Please note that Caml Crush does not yet support TLS client authentication when using OCamlnet 4.

### Server SSL/TLS configuration for older releases
The SSL/TLS support can be turned on with the following configuration directives:

```ocaml
...
processor {
  ...
  use_ssl = true;
  (* Provide full certificate chain in cafile *)
  cafile = "/etc/pkcs11proxy/certs/ca.crt";
  certfile = "/etc/pkcs11proxy/certs/server.crt";
  certkey = "/etc/pkcs11proxy/certs/server.key";
  (* OpenSSL cipher syntax, one or many suites can be configured, or alias such as HIGH *)
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


**WARNING**: Since Caml Crush 1.0.5, we require ocaml-ssl 0.4.7. This allows to enable PFS support and force TLS 1.2. Hence, if you want to link against older ocaml-ssl, you must manually modify the source code or use an older release.

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
