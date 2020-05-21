define([PACKAGE_VERSION_MAJOR], [1])
define([PACKAGE_VERSION_MINOR], [0])
define([PACKAGE_VERSION_FIX], [8])

AC_INIT(cam-crush, [PACKAGE_VERSION_MAJOR.PACKAGE_VERSION_MINOR.PACKAGE_VERSION_FIX])

#Include autoconf macros (ocaml and version comparisons)
m4_include([m4/ax_compare_version.m4])

AC_CONFIG_SRCDIR([src/client-lib/modwrap.c])

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


AC_CONFIG_FILES([$bindings_dir/Makefile $bindings_dir/Makefile.standalone $rpc_dir/Makefile $server_dir/Makefile $client_dir/Makefile $filter_filter_dir/Makefile $filter_backend_dir/Makefile $filter_frontend_dir/Makefile $filter_dir/Makefile $tests_dir/Makefile $ocaml_tests_dir/Makefile $c_tests_dir/Makefile $scripts_dir/pkcs11proxyd])

AC_ARG_WITH(caml-crush, [  --without-caml-crush    compile only pkcs11 bindings, (this is NOT the default)], [], with_caml_crush=yes)
AC_ARG_WITH(client-socket, [  --with-client-socket    configure client socket type and path, default is tcp with 127.0.0.1 (format is --with-client-socket="unix,path" or --with-client-socket="tcp,address:port")])
AC_ARG_WITH(libname-file, [  --with-libname-file     configure library to fetch libname from a disk file (default)])
AC_ARG_WITH(libnames, [  --with-libnames         configure library names to be generated, comma deparated (default is the empty string). E.g: --with-libnames=foo,bar])
AC_ARG_WITH(ocamlclient, [  --with-ocamlclient      use OCaml client library and RPC instead of default native C one])
AC_ARG_WITH(cclient, [  --with-cclient          use C based client library and RPC (this is the default)])
AC_ARG_WITH(debuglibs, [  --with-debuglibs        activate verbose debug output for the modules of the proxy that do not support it dynamically (the bindings and the client library)])
AC_ARG_WITH(rpcgen, [  --with-rpcgen           force regeneration of the rpc header and code files again (this is NOT the default)])
AC_ARG_WITH(idlgen, [  --with-idlgen           force regeneration of the idl header and code files again (this is NOT the default)])
AC_ARG_WITH(ssl, [  --with-ssl              use SSL authentication and encryption over the transport layer (TCP or Unix socket). Use the OpenSSL library by default if --with-gnutls is not given.])
AC_ARG_WITH(gnutls, [  --with-gnutls           use the gnutls library instead of the OpenSSL library for native C client RPC over ssl.)])
AC_ARG_WITH(ssl-clientfiles, [  --with-ssl-clientfiles  CA and client certificate files as well as private key (in pem format) for SSL on the target. These are paths on the client if there is a prepending path, environment variables if there is a prepending env (PKCS11PROXY_SSL_CA/PKCS11PROXY_SSL_CERT/PKCS11_SSL_PRIVKEY: this is the default), or a path of files on the host to be embedded inside the client if there is a prepending embed. E.g: --with-ssl-clientfiles='path;ca=path_to_ca,cert=path_to_cert,privkey=path_to_key')], sslfiles="$withval")
AC_ARG_WITH(ssl-servercerts, [  --with-ssl-servercerts  enforce the client to strictly accept authentication with specific servers that use the certificates provided either in the folder or in a file (as a concatenation of certificates)], sslservercerts="$withval")
AC_ARG_WITH(filter, [ --without-filter         compile the server without the filter: all the PKCS#11 commands are passed through to the bindings.], [], with_filter=yes)

AC_ARG_WITH(aliasing, [ --with-aliasing          aliasing of the sessions and objects handles. There are two aliasing modes: incremental and random (non predictable aliases): --with-aliasing=rand or --with-aliasing=inc, default is random.], aliasing="$withval")
AC_ARG_WITH(daemonize, [ --with-daemonize        compile with daemonization primitives support (User can amend C_Daemonize function to provide its own privilege reduction primitives inside the server process instead of using the sandbox launcher).])

full_libdir=`eval eval eval eval eval echo "${libdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`

# Install the library in a sub-directory
full_libdir="$full_libdir/caml-crush"
libdir=$full_libdir

# Summary helpers
AC_DEFUN([WRITE_TO_FILE],[
printf "%-40s:   %s\n" $2 $3 >> $1
])
AC_DEFUN([SHOW_SUMMARY],[
cat $1 && rm -f $1
])

#Try to detect host_type and set variable
if host_type=`${srcdir}/config.guess`; then :; else
  echo "Cannot guess host type"
  exit 2
fi

# Remove any existing summary file
rm -f ./summary
echo "###########################################" >> ./summary
echo "###               SUMMARY               ###" >> ./summary
echo "###########################################" >> ./summary

##########
# CHECK Make

case $host_type in
   *-gnu*)
	make_exe=make
	;;
   *freebsd*)
	make_exe=gmake
	;;
   *)
	make_exe=make
	;;
esac
AC_CHECK_PROG(MAKEPROG,$make_exe,$make_exe,no)
if test "$MAKEPROG" == "no"
then
  AC_MSG_ERROR(Cannot find GNU make as $make_exe.)
fi
AC_SUBST(MAKEPROG,$MAKEPROG)

##########
# CHECK OCaml an needed binaries
AC_DEFUN([AC_PROG_OCAML],
[dnl
# checking for ocamlc
AC_CHECK_PROG(OCAMLC,ocamlc,yes,no)
if test "$OCAMLC" == "no"
then
  AC_MSG_ERROR(Cannot find ocamlc.)
fi
OCAMLVERSION=$(ocamlc -version)
AC_MSG_RESULT(OCaml version is $OCAMLVERSION)
OCAMLLIB=$(ocamlc -where)
AC_MSG_RESULT(OCaml library path is $OCAMLLIB)
# checking for ocamlopt
AC_CHECK_PROG(OCAMLOPT,ocamlopt,ocamlopt)
OCAMLBEST=byte
if test -z "$OCAMLOPT"; then
	AC_MSG_WARN(Cannot find ocamlopt; bytecode compilation only.)
else
	TMPVERSION=$($OCAMLOPT -version)
	if test "$TMPVERSION" != "$OCAMLVERSION" ; then
	    AC_MSG_RESULT(versions differs from ocamlc; ocamlopt discarded.)
	    unset OCAMLOPT
	else
	    OCAMLBEST=opt
	fi
fi
# checking for ocamlc.opt
AC_CHECK_PROG(OCAMLCDOTOPT,ocamlc.opt,ocamlc.opt)
if test "$OCAMLCDOTOPT"; then
	TMPVERSION=$($OCAMLCDOTOPT -version)
	if test "$TMPVERSION" != "$OCAMLVERSION" ; then
	    AC_MSG_RESULT(versions differs from ocamlc; ocamlc.opt discarded.)
	else
	    OCAMLC=$OCAMLCDOTOPT
	fi
fi
# checking for ocamlopt.opt
if test "$OCAMLOPT" ; then
    AC_CHECK_PROG(OCAMLOPTDOTOPT,ocamlopt.opt,ocamlopt.opt)
    if test "$OCAMLOPTDOTOPT"; then
	TMPVERSION=$($OCAMLOPTDOTOPT -version)
	if test "$TMPVERSION" != "$OCAMLVERSION" ; then
	    AC_MSG_RESULT(version differs from ocamlc; ocamlopt.opt discarded.)
	else
	    OCAMLOPT=$OCAMLOPTDOTOPT
	fi
    fi
fi
# checking for ocamldep
AC_CHECK_PROG(OCAMLDEP,ocamldep,ocamldep,AC_MSG_WARN(Cannot find ocamldep.))

#checking for ocamlmklib
AC_CHECK_PROG(OCAMLMKLIB,ocamlmklib,ocamlmklib, AC_MSG_WARN(Cannot find ocamlmklib.))

AC_SUBST(OCAMLC)
AC_SUBST(OCAMLOPT)
AC_SUBST(OCAMLDEP)
AC_SUBST(OCAMLBEST)
AC_SUBST(OCAMLVERSION)
AC_SUBST(OCAMLLIB)
AC_SUBST(OCAMLMKLIB)
])
# CHECK for ocamlp4 needed for 
# some conditional compilation
AC_DEFUN([AC_PROG_CAMLP4],
[dnl
AC_REQUIRE([AC_PROG_OCAML])
# checking for camlp4
AC_CHECK_PROG(CAMLP4,camlp4,yes,no)
if test "$CAMLP4" == "no"; then
	TMPVERSION=$($CAMLP4 -v 2>&1| sed -n -e 's|.*version *\(.*\)$|\1|p')
	if test "$TMPVERSION" != "$OCAMLVERSION" ; then
	    AC_MSG_ERROR(versions differs from ocamlc)
 	else
	    AC_CHECK_PROG(CAMLP4O,camlp4o,camlp4o)
	fi
fi
AC_SUBST(CAMLP4)
AC_SUBST(CAMLP4O)
])
# CHECK for OCaml findlib needed 
# for dependency solving
AC_DEFUN([AC_PROG_FINDLIB],
[dnl
# checking for ocamlfind
   AC_CHECK_PROG(OCAMLFIND,ocamlfind,ocamlfind,
   AC_MSG_ERROR(ocamlfind not found))
   AC_SUBST(OCAMLFIND)
])
AC_DEFUN([AC_CHECK_OCAML_PKG],
[dnl
AC_REQUIRE([AC_PROG_FINDLIB])
    AC_MSG_CHECKING(OCaml package $1)
    if $OCAMLFIND query $1 >/dev/null 2>/dev/null; then
      AC_MSG_RESULT(found)
      pkg_$2="$1"
    else
      AC_MSG_ERROR(not found)
      unset pkg_$2
    fi
])
AC_DEFUN([AC_CHECK_OCAML_PKG_VERS],
[dnl
AC_REQUIRE([AC_PROG_FINDLIB])
    AC_MSG_CHECKING(OCaml package $1)
    if $OCAMLFIND query $1 >/dev/null 2>/dev/null; then
      AC_MSG_RESULT(found)
      pkg_vers_$2=$($OCAMLFIND query -format "%v" $1)
    else
      AC_MSG_ERROR(not found)
      unset pkg_vers_$2
    fi
])
dnl
dnl
dnl
dnl AC_ARG_OCAML_INSTALLDIR adds a --with-installdir option
AC_DEFUN([AC_ARG_OCAML_INSTALLDIR],
[dnl
AC_ARG_WITH(installdir,[  --with-installdir=DIR	  specify installation directory],INSTALLDIR="$withval")
if ! test "$INSTALLDIR" -o "$use_findlib" ; then
    INSTALLDIR='$(OCAMLLIB)/$(NAME)'
fi
AC_SUBST(INSTALLDIR)
])
dnl
dnl
dnl
dnl AC_CHECK_OCAML_MODULE looks for a module in a given path
dnl 1 -> name (for printing)
dnl 2 -> env var name
dnl 3 -> module to check
dnl 4 -> default dirs
AC_DEFUN([AC_CHECK_OCAML_MODULE],
[dnl
AC_MSG_CHECKING($1 directory)
cat > conftest.ml <<EOF
open $3
EOF
unset found
for $2 in $$2 $4 ; do
  if $OCAMLC -c -I "$$2" conftest.ml > /dev/null 2>&1 ; then
    found=yes
    break
  fi
done
if test "$found" ; then
  AC_MSG_RESULT($$2)
else
  AC_MSG_RESULT(not found)
  unset $2
fi
AC_SUBST($2)])

#***********************#
AC_PROG_OCAML

##########
# CHECK HEADERS
# OCAML
export CFLAGS="$CFLAGS -I$OCAMLLIB"
export CPPFLAGS="$CPPFLAGS -I$OCAMLLIB"
AC_CHECK_HEADERS([caml/mlvalues.h],,AC_MSG_ERROR(Could not find OCaml headers.))
# OCAML IDL
AC_CHECK_HEADERS([caml/camlidlruntime.h],,AC_MSG_ERROR(Could not find OCaml IDL headers.))
# Dynamic linker
AC_CHECK_HEADERS([dlfcn.h],,AC_MSG_ERROR(Could not find dlfcn headers.))
# pthread
AC_CHECK_HEADERS([pthread.h],,AC_MSG_ERROR(Could not find pthread headers.))

AC_PROG_CAMLP4
AC_PROG_FINDLIB
if test "$with_caml_crush" == "yes" #--without-caml-crush was not set
then
# CHECK for ocamlnet RPC
AC_CHECK_OCAML_PKG([rpc], rpc)
# CHECK for ocaml str regexp package
AC_CHECK_OCAML_PKG([str], str)
# CHECK for the config-file package
AC_CHECK_OCAML_PKG([config-file], configfile)
# CHECK for the camlidl library
fi
AC_CHECK_OCAML_PKG([camlidl], camlidl)

##########
# CHECK LIBS for basic linking
# CHECK for dl
case $host_type in
   *freebsd*)
	AC_MSG_NOTICE(System is FreeBSD skip libdl check)
        ;;
   *)
	AC_CHECK_LIB(dl, dlopen, DL_LIB="-ldl",
               AC_MSG_ERROR(Cannot find dl library.))
	;;
esac
# CHECK pthread
AC_CHECK_LIB(pthread, pthread_mutex_init, THREAD_LIB="-lpthread",
               AC_MSG_ERROR(Cannot find pthread library.))

# IDL generation handling
####
# CHECK for the camlidl program, 
# only needed if we need to generate the idl files again
if test "$with_idlgen" != ""
then
	AC_CHECK_PROG(CAMLIDL,camlidl,yes,no)
        if test "$CAMLIDL" == "no"
        then
          AC_MSG_ERROR(Cannot find camlidl: needed for PKCS11 bindings generation.)
        fi
	AC_CHECK_PROG(COCCINELLE,spatch,yes,no)
        if test "$COCCINELLE" == "no"
        then
          AC_MSG_ERROR(Cannot find spatch binary: needed for PKCS11 bindings generation - install coccinelle.)
        fi
        AC_SUBST(idl_gen, "idl")
  	WRITE_TO_FILE(summary, "IDL gen", "YES")
else
  	WRITE_TO_FILE(summary, "IDL gen", "NO")
fi

# DEBUG MODE HANDLING
if test "$with_debuglibs" != ""
then
        AC_MSG_NOTICE([Using debug mode libs])
        AC_SUBST(debug_mode, "debug")
        WRITE_TO_FILE(summary, "debug libs", "YES")
else
        AC_SUBST(debug_mode, "")
        WRITE_TO_FILE(summary, "debug libs", "NO")
fi

if test "$with_caml_crush" == "yes" #--without-caml-crush was not set
    then
  
############# OCAML RELATED CHECKS #########
# CHECK if OCaml runtime was build with 
# -fPIC: if yes, build the ocaml client 
# against the local lib. If no, fail
# and advise user to either use the C client
# or to rebuild the OCaml binaries. 
if test "$with_ocamlclient" != ""
    then
    AC_MSG_CHECKING(OCaml support for fPIC)
    # Try to compile a sample program
    ML_TEST_FILE="mltest"
    ML=".ml"
    CMI=".cmi"
    CMX=".cmx"
    OBJ=".o"
cat <<EOM >$ML_TEST_FILE$ML
let _ = Printf.printf "Testing -fPIC\n"
EOM
    $OCAMLOPT -output-obj -o a.so $ML_TEST_FILE$ML 2> ocamlopt.log
    OCAMLOPT_ERR=`cat ocamlopt.log | grep -i error`
    if test "$OCAMLOPT_ERR" != ""
    then
        rm -f $ML_TEST_FILE$CMI $ML_TEST_FILE$CMX $ML_TEST_FILE$OBJ $ML_TEST_FILE$ML a.so ocamlopt.log
        AC_MSG_RESULT(no)
        AC_MSG_WARN(OCaml is not compiled with fPIC support either use --with-cclient or recompile the OCaml suite)
        AC_MSG_ERROR(OCaml client cannot be compiled. Read the documentation for more details.)
    else
        AC_MSG_RESULT(yes)
    fi
    rm -f $ML_TEST_FILE$CMI $ML_TEST_FILE$CMX $ML_TEST_FILE$OBJ $ML_TEST_FILE$ML a.so ocamlopt.log
fi


########## INTERNAL OPTIONS ###########
#########
# RPC TYPE HANDLING
summary=""
if test "$with_ocamlclient" != ""
then
	if test "$with_cclient" != ""
	then
		AC_MSG_ERROR([--with-ocamlclient and --with-cclient are NOT compatible!])
	fi
	WRITE_TO_FILE(summary, "client type", "OCaml based client (OCamlnet RPC)")
	AC_MSG_NOTICE([Using OCaml based client and RPC instead of native C client])
	AC_SUBST(client_to_compile, "camlrpc")
	AC_SUBST(client_to_compile_debug, "camlrpc_debug")
else
	WRITE_TO_FILE(summary, "client type", "Native C client (RPC generated with native rpcgen)")
	AC_MSG_NOTICE([Using default C based client and RPC])

	AC_CHECK_HEADERS([rpc/rpc.h],,AC_MSG_ERROR(Could not find C RPC headers.))
	AC_CHECK_HEADERS([rpc/clnt.h],,AC_MSG_ERROR(Could not find C RPC client headers.))

	AC_SUBST(client_to_compile, "crpc")
	AC_SUBST(client_to_compile_debug, "crpc_debug")
fi


# LIBNAME HANDLING
if test -n "${with_libnames+x}" && test -n "${with_libname_file+x}"
then
	AC_MSG_ERROR([--with-libname-file incompatible --with-libnames!, choose one])
fi
#default no choice
if test -z "${with_libnames+x}" && test -z "${with_libname_file+x}"
then
        AC_MSG_NOTICE([Client library configured to read libname from a file])
	AC_SUBST(lib_names, "\"\"")
        AC_SUBST(libname_file, "-DLIBNAME_FILE")
        WRITE_TO_FILE(summary, "client lib",  "Using .camlcrushlibname file")
fi

#using builtin
if test -n "${with_libnames+x}"
then
	libraries=$(echo $with_libnames | sed 's/\([[^,]]*\)/\"\1\"/g' | tr ',' ' ')
	AC_MSG_NOTICE([Client libraries configured for $libraries])
	AC_SUBST(lib_names, $libraries)
	WRITE_TO_FILE(summary, "client libs", "$libraries")
fi

#using disk file
if test -n "${with_libname_file+x}"
then
        AC_MSG_NOTICE([Client library configured to read libname from a file])
	AC_SUBST(lib_names, "\"\"")
        AC_SUBST(libname_file, "-DLIBNAME_FILE")
        WRITE_TO_FILE(summary, "client lib",  "Using ${with_libname_file} file")
fi

# SOCKET HANDLING
unix="UNIX_SOCKET"
tcp="TCP_SOCKET"
if test "$with_client_socket" != ""
then
        socket_type=$(echo $with_client_socket | sed 's/\(.*\),.*/\1/g')
        case $socket_type in
                unix)
			unix_path=$(echo $with_client_socket | sed 's/unix,//g')
			AC_MSG_NOTICE([Client library configured to use Unix socket located at $unix_path])
			AC_SUBST(socket_path, $unix_path)
			#Dummy port, not used for Unix socket
			AC_SUBST(socket_type, $unix)
			WRITE_TO_FILE(summary, "client socket", "unix -> $unix_path")
			;;
                tcp)
			tcp_host=$(echo $with_client_socket | sed 's/tcp,\(.*\)/\1/g')
			AC_MSG_NOTICE([Client library configured to use Tcp socket with host $tcp_path])
			AC_SUBST(socket_path, $tcp_host)
			AC_SUBST(socket_type, $tcp)
			WRITE_TO_FILE(summary, "client socket", "tcp -> $tcp_host")
			;;
                *)
			AC_MSG_ERROR(Unsupported socket type)
			;;
	esac
else
	tcp_path="127.0.0.1:4444"
	AC_MSG_NOTICE([Client library configured to use default: Tcp socket with host $tcp_path])
	AC_SUBST(socket_path, $tcp_path)
	AC_SUBST(socket_type, $tcp)
	WRITE_TO_FILE(summary, "client socket", "tcp -> $tcp_path (DEFAULT)")

fi

#########
# RPC library support checks
if test "$with_ocamlclient" == ""
then
	#socket_type now contains UNIX_SOCKET/TCP_SOCKET
        case $socket_type in
                UNIX_SOCKET)
			# Check the library against RPC unix client creation
			AC_CHECK_LIB(c, clntunix_create, ,
			AC_MSG_ERROR(Cannot find RPC clntunix_create symbol in C library.))
			;;
                TCP_SOCKET)
			# Check the library against RPC tcp client creation
			AC_CHECK_LIB(c, clnttcp_create, ,
			AC_MSG_ERROR(Cannot find RPC clnttcp_create symbol in C library.))
			;;
                *)
			AC_MSG_ERROR(We should not end up in this test.)
			;;
	esac

fi



# RPC generation handling
####
# CHECK for the rpcgen programs 
if test "$with_rpcgen" != ""
then
        AC_MSG_NOTICE([OCaml RPC generation forced for server side ...])
        AC_CHECK_PROG(OCAMLRPCGEN,ocamlrpcgen,yes,no)
        if test "$OCAMLRPCGEN" == "no"
        then
          AC_MSG_ERROR(Cannot find ocamlrpcgen: needed for RPC server generation.)
        fi
        AC_SUBST(caml_rpc_gen, rpc)
	# rpcgen is only needed if we generate native C client RPC
        if test "$with_ocamlclient" == ""
        then
        	AC_MSG_NOTICE([Native C RPC generation for client side ...])
                AC_CHECK_PROG(RPCGEN,rpcgen,yes,no)
                if test "$RPCGEN" == "no"
                then
                  AC_MSG_ERROR(Cannot find rpcgen: needed for native C client library RPC generation.)
                fi
                RPCGENVERSION=$(rpcgen --version)
                AC_MSG_RESULT(rpcgen found, version is $RPCGENVERSION)
                AC_SUBST(c_rpc_gen, "rpc")
		#Linux C_RPC can be patched to avoid unused buffer
		case $host_type in
			*linux*)
                                AC_SUBST(linux_c_rpc_patch, "linux_c_rpc_patch")
				;;
			*)
                                AC_SUBST(linux_c_rpc_patch, "")
				;;
		esac
        else
        	AC_MSG_NOTICE([OCaml RPC generation forced for client side ...])
                AC_SUBST(c_rpc_gen,"")
        fi
	WRITE_TO_FILE(summary, "RPC gen", "YES")
else
	AC_SUBST(caml_rpc_gen,"")
	WRITE_TO_FILE(summary, "RPC gen", "NO")
fi
# FIXME: Need to check rpcgen support for MT
AC_SUBST(rpc_mt_define, "-DRPCGEN_MT")
AC_SUBST(caml_rpc_clean, pkcs11_rpc_*)
AC_SUBST(c_rpc_clean, "pkcs11_rpc.h pkcs11_rpc_xdr.c pkcs11_rpc_svc.c pkcs11_rpc_clnt.c")

# SSL/GnuTLS handling
if test "$with_ssl" != ""
then
	WRITE_TO_FILE(summary, "SSL", "YES (on the server and client side)")
	if test "$with_ssl_clientfiles" == ""
	then
        	AC_MSG_ERROR([--with-ssl needs --with-ssl-clientfiles!])
	fi
        AC_MSG_NOTICE([Using OCaml RPC over ssl for server side ...])

	#Compare version of OCamlnet for TLS support
	#get the version in pkg_vers_rpc var
	AC_CHECK_OCAML_PKG_VERS([rpc], rpc)
	AX_COMPARE_VERSION([$pkg_vers_rpc], [lt], [4.0.0], [use_ocamlnet_tls=no], [use_ocamlnet_tls=yes])
	if test "$use_ocamlnet_tls" == "yes"
	then
		AC_MSG_NOTICE([Using newer Ocamlnet TLS])
		# Since Ocamlnet TLS is based on gnutls, check
		# that the library dev package is installed
		AC_CHECK_LIB(gnutls, gnutls_record_recv, GNUTLS_LIB="-lgnutls",
		AC_MSG_ERROR(Cannot find symbol in gnutls library.))
		# Check that the Ocaml nettls-gnutls is installed
		AC_CHECK_OCAML_PKG([nettls-gnutls], nettlsgnutls)
		# Position the ssl define and linking for the server
        	AC_SUBST(caml_server_ssl_define, "-DWITH_SSL")
	        AC_SUBST(caml_server_ssl_package, "-package \"nettls-gnutls\"")
	else
		AC_MSG_NOTICE([Using standard OCaml-SSL TLS])
		AC_CHECK_OCAML_PKG([ssl], ssl)
                # Check for the ocaml-ssl version: we only support
                # version >= 0.4.7
		AC_CHECK_OCAML_PKG_VERS([ssl], ssl)
                AX_COMPARE_VERSION([$pkg_vers_ssl], [lt], [0.4.7], [ocaml_ssl_bad_version=yes], [ocaml_ssl_bad_version=no])
                if test "$ocaml_ssl_bad_version" == "yes"
                then
                        AC_MSG_ERROR(Version of ocaml-ssl must be >= 0.4.7.)
                fi
		AC_CHECK_OCAML_PKG([rpc-ssl], rpcssl)
		# Position the ssl define and linking for the server
		AC_SUBST(caml_server_ssl_define, "-DWITH_SSL -DWITH_SSL_LEGACY")
	        AC_SUBST(caml_server_ssl_package, "-package \"ssl\" -package \"rpc-ssl\"")
	fi
	# We need the ssl and rpc-ssl package for RPC over ssl support
        if test "$with_ocamlclient" == ""
	then
		if test "$with_gnutls" != ""
		then
			WRITE_TO_FILE(summary, " -SSL client lib", "GnuTLS")
        		AC_MSG_NOTICE([Using native C RPC over ssl (gnu-tls) for client side ...])
                        # If we compile the native C client, and if the gnu-tls 
			# library is configured, we check it
                        # Check the headers
                        AC_CHECK_HEADERS([gnutls/gnutls.h],,AC_MSG_ERROR(Could not find gnutls headers.))
                        # Check the library against all the symbols we use
                        AC_CHECK_LIB(gnutls, gnutls_record_recv, GNUTLS_LIB="-lgnutls",
                                AC_MSG_ERROR(Cannot find symbol in gnutls library.))
                        AC_CHECK_LIB(gnutls, gnutls_record_send, GNUTLS_LIB="-lgnutls",
                                AC_MSG_ERROR(Cannot find symbol in gnutls library.))
                        AC_CHECK_LIB(gnutls, gnutls_global_init, GNUTLS_LIB="-lgnutls",
                                AC_MSG_ERROR(Cannot find symbol in gnutls library.))
                        AC_CHECK_LIB(gnutls, gnutls_init, GNUTLS_LIB="-lgnutls",
                                AC_MSG_ERROR(Cannot find symbol in gnutls library.))
                        AC_CHECK_LIB(gnutls, gnutls_perror, GNUTLS_LIB="-lgnutls",
                                AC_MSG_ERROR(Cannot find symbol in gnutls library.))
                        AC_CHECK_LIB(gnutls, gnutls_priority_set_direct, GNUTLS_LIB="-lgnutls",
                                AC_MSG_ERROR(Cannot find symbol in gnutls library.))
                        AC_CHECK_LIB(gnutls, gnutls_credentials_set, GNUTLS_LIB="-lgnutls",
                                AC_MSG_ERROR(Cannot find symbol in gnutls library.))
                        AC_CHECK_LIB(gnutls, gnutls_transport_set_ptr, GNUTLS_LIB="-lgnutls",
                                AC_MSG_ERROR(Cannot find symbol in gnutls library.))
                        AC_CHECK_LIB(gnutls, gnutls_handshake, GNUTLS_LIB="-lgnutls",
                                AC_MSG_ERROR(Cannot find symbol in gnutls library.))
                        AC_CHECK_LIB(gnutls, gnutls_certificate_get_peers, GNUTLS_LIB="-lgnutls",
                                AC_MSG_ERROR(Cannot find symbol in gnutls library.))
                        AC_CHECK_LIB(gnutls, gnutls_certificate_verify_peers2, GNUTLS_LIB="-lgnutls",
                                AC_MSG_ERROR(Cannot find symbol in gnutls library.))
                        AC_CHECK_LIB(gnutls, gnutls_strerror, GNUTLS_LIB="-lgnutls",
                                AC_MSG_ERROR(Cannot find symbol in gnutls library.))
                        AC_CHECK_LIB(gnutls, gnutls_bye, GNUTLS_LIB="-lgnutls",
                                AC_MSG_ERROR(Cannot find symbol in gnutls library.))
                        AC_CHECK_LIB(gnutls, gnutls_deinit, GNUTLS_LIB="-lgnutls",
                                AC_MSG_ERROR(Cannot find symbol in gnutls library.))
                        AC_CHECK_LIB(gnutls, gnutls_certificate_free_credentials, GNUTLS_LIB="-lgnutls",
                                AC_MSG_ERROR(Cannot find symbol in gnutls library.))
                        AC_CHECK_LIB(gnutls, gnutls_global_deinit, GNUTLS_LIB="-lgnutls",
                                AC_MSG_ERROR(Cannot find symbol in gnutls library.))

                        AC_CHECK_LIB(gnutls, gnutls_certificate_set_x509_trust_mem, GNUTLS_LIB="-lgnutls",
                                AC_MSG_ERROR(Cannot find symbol in gnutls library.))
                        AC_CHECK_LIB(gnutls, gnutls_certificate_set_x509_key_mem, GNUTLS_LIB="-lgnutls",
                                AC_MSG_ERROR(Cannot find symbol in gnutls library.))

                        AC_SUBST(c_ssl_package, "-lgnutls")
	                AC_SUBST(c_gnutls_define, "-DGNU_TLS")
		else
			WRITE_TO_FILE(summary, " -SSL client lib", "OpenSSL")
        		AC_MSG_NOTICE([Using native C RPC over ssl (OpenSSL) for client side ...])
			# If we compile the native C client, we need 
			# the openssl library bu default
			# Check the headers
			AC_CHECK_HEADERS([openssl/ssl.h],,AC_MSG_ERROR(Could not find openssl headers.))
			# Check the library
			AC_CHECK_LIB(ssl, SSL_read, OPENSSL_LIB="-lssl",
               			AC_MSG_ERROR(Cannot find symbol in openssl library.))
			# Check if we are in presence of openssl >= 1.1.0 or not
			AC_CHECK_LIB(ssl, OPENSSL_init_ssl, OPENSSL_LIB="-lssl", new_openssl=no)
			# Check for used symbols
			AC_CHECK_LIB(ssl, SSL_write, OPENSSL_LIB="-lssl",
               			AC_MSG_ERROR(Cannot find symbol in openssl library.))
			if test "$new_openssl" == "no"; then
				AC_MSG_NOTICE([Openssl < 1.1.0 detected])
				# SSL_load_error_strings is deprecated in openssl >= 1.1.0
				AC_CHECK_LIB(ssl, SSL_load_error_strings, OPENSSL_LIB="-lssl",
					AC_MSG_ERROR(Cannot find symbol in openssl library.))
				# SSL_library_init is deprecated in openssl >= 1.1.0
				AC_CHECK_LIB(ssl, SSL_library_init, OPENSSL_LIB="-lssl",
					AC_MSG_ERROR(Cannot find symbol in openssl library.))
			else
				AC_MSG_NOTICE([Openssl >= 1.1.0 detected])
				AC_CHECK_LIB(ssl, OPENSSL_init_ssl, OPENSSL_LIB="-lssl",
					AC_MSG_ERROR(Cannot find symbol in openssl library.))
			fi
			AC_CHECK_LIB(ssl, SSL_CTX_new, OPENSSL_LIB="-lssl",
               			AC_MSG_ERROR(Cannot find symbol in openssl library.))
			#AC_CHECK_LIB(ssl, SSL_CTX_set_options, OPENSSL_LIB="-lssl",
               		#	AC_MSG_ERROR(Cannot find symbol in openssl library.))
			AC_CHECK_LIB(ssl, SSL_CTX_load_verify_locations, OPENSSL_LIB="-lssl",
               			AC_MSG_ERROR(Cannot find symbol in openssl library.))
			AC_CHECK_LIB(ssl, SSL_CTX_use_certificate_file, OPENSSL_LIB="-lssl",
               			AC_MSG_ERROR(Cannot find symbol in openssl library.))
			AC_CHECK_LIB(ssl, SSL_CTX_use_PrivateKey_file, OPENSSL_LIB="-lssl",
               			AC_MSG_ERROR(Cannot find symbol in openssl library.))
			AC_CHECK_LIB(ssl, SSL_CTX_check_private_key, OPENSSL_LIB="-lssl",
               			AC_MSG_ERROR(Cannot find symbol in openssl library.))
			AC_CHECK_LIB(ssl, SSL_new, OPENSSL_LIB="-lssl",
               			AC_MSG_ERROR(Cannot find symbol in openssl library.))
			AC_CHECK_LIB(ssl, SSL_set_fd, OPENSSL_LIB="-lssl",
               			AC_MSG_ERROR(Cannot find symbol in openssl library.))
			AC_CHECK_LIB(ssl, SSL_connect, OPENSSL_LIB="-lssl",
               			AC_MSG_ERROR(Cannot find symbol in openssl library.))
			AC_CHECK_LIB(ssl, SSL_get_peer_certificate, OPENSSL_LIB="-lssl",
               			AC_MSG_ERROR(Cannot find symbol in openssl library.))
			AC_CHECK_LIB(ssl, SSL_get_verify_result, OPENSSL_LIB="-lssl",
               			AC_MSG_ERROR(Cannot find symbol in openssl library.))
			AC_CHECK_LIB(ssl, SSL_shutdown, OPENSSL_LIB="-lssl",
               			AC_MSG_ERROR(Cannot find symbol in openssl library.))
			AC_CHECK_LIB(ssl, SSL_free, OPENSSL_LIB="-lssl",
               			AC_MSG_ERROR(Cannot find symbol in openssl library.))
			AC_CHECK_LIB(ssl, SSL_CTX_free, OPENSSL_LIB="-lssl",
               			AC_MSG_ERROR(Cannot find symbol in openssl library.))

			AC_CHECK_LIB(ssl, SSL_CTX_get_cert_store, OPENSSL_LIB="-lssl",
               			AC_MSG_ERROR(Cannot find symbol in openssl library.))
			AC_CHECK_LIB(ssl, SSL_CTX_use_certificate, OPENSSL_LIB="-lssl",
               			AC_MSG_ERROR(Cannot find symbol in openssl library.))
			AC_CHECK_LIB(ssl, SSL_CTX_use_RSAPrivateKey, OPENSSL_LIB="-lssl",
               			AC_MSG_ERROR(Cannot find symbol in openssl library.))
			# Following symbols might use the libcrypto
			AC_SEARCH_LIBS([BIO_new_mem_buf], [ssl crypto], [],
               			AC_MSG_ERROR(Cannot find SSL symbol in libraries.))
			AC_CHECK_LIB(ssl, PEM_read_bio_X509, OPENSSL_LIB="-lssl",
               			AC_MSG_ERROR(Cannot find symbol in openssl library.))
			AC_CHECK_LIB(ssl, PEM_read_bio_RSAPrivateKey, OPENSSL_LIB="-lssl",
               			AC_MSG_ERROR(Cannot find symbol in openssl library.))
			AC_CHECK_LIB(ssl, X509_STORE_add_cert, OPENSSL_LIB="-lssl",
               			AC_MSG_ERROR(Cannot find symbol in openssl library.))

		        AC_SUBST(c_ssl_package, "-lssl")
                        AC_SUBST(c_gnutls_define, "")
		fi
                AC_SUBST(c_ssl_define, "-DWITH_SSL")
                AC_SUBST(caml_client_ssl_define, "")
	else
                if test "$with_gnutls" != ""
                then
			AC_MSG_ERROR([--with-ocamlclient and --with-gnutls are NOT compatible!])
		fi
		WRITE_TO_FILE(summary, " -SSL client lib", "OpenSSL (OCaml bindings)")
       		AC_MSG_NOTICE([Using OCaml RPC over ssl for client side ...])
                AC_SUBST(c_ssl_package, "")
                AC_SUBST(c_gnutls_define, "")
                AC_SUBST(c_ssl_define, "")
                AC_SUBST(caml_client_ssl_define, "-DWITH_SSL")
        	AC_SUBST(caml_client_ssl_package, "-package \"ssl\" -package \"rpc-ssl\"")
	fi
else
        if test "$with_gnutls" != ""
        then
        	AC_MSG_ERROR([--with-gnutls needs --with-ssl!])
        fi
        AC_SUBST(caml_client_ssl_package, "")
        AC_SUBST(c_ssl_package, "")
        AC_SUBST(c_gnutls_define, "")
        AC_SUBST(c_ssl_define, "")
        AC_SUBST(caml_client_ssl_define, "")
        AC_SUBST(caml_client_ssl_package, "")
	WRITE_TO_FILE(summary, "SSL", "NO (neither on the server nor on the client side)")
fi



###################################################################
###################################################################
###################################################################
###################################################################
# HANDLE SSL files
# Macro to create the ssl headers, for C and ML clients, from the 
# given files $1 is the file path, $2 is the file type ("ca", "cert",
# "priv" for private key, "server" for the allowed servers certificates)
AC_DEFUN([CREATE_SSL_HEADERS],[
C_FILE="./create_ssl_files.c"
FILE="./create_ssl_files"
rm -f $C_FILE $FILE
cat <<EOM >$C_FILE
#include <stdio.h>
#include <stdlib.h>
#define OUT_C   0
#define OUT_ML  1
#define OUT_UNK 2
unsigned char output_type = OUT_UNK;
size_t mygetline(char **lineptr, size_t *n, FILE *stream) {
  char *bufptr = NULL;
  char *p = bufptr;
  size_t size;
  int c;

  if (lineptr == NULL) {
    return -1;
  }
  if (stream == NULL) {
    return -1;
  }
  if (n == NULL) {
    return -1;
  }
  bufptr = *lineptr;
  size = *n;
  c = fgetc(stream);
  if (c == EOF) {
    return -1;
  }
  if (bufptr == NULL) {
    bufptr = malloc(128);
    if (bufptr == NULL) {
      return -1;
    }
    size = 128;
  }
  p = bufptr;
  while(c != EOF) {
    if ((p - bufptr) > (size - 1)) {
      size = size + 128;
      bufptr = realloc(bufptr, size);
      if (bufptr == NULL) {
        return -1;
	}
      }
      *p++ = c;
      if (c == '\n') {
	break;
      }
      c = fgetc(stream);
  }
  *p++ = '\0';
  *lineptr = bufptr;
  *n = size;
  return p - bufptr - 1;
}
int write_line(FILE* fp, char* line, size_t lsize){
  int i;
  size_t end;
  /* Check if we have a \n or \r\n at the end of the line */
  if(lsize >= 2){
    if(line[[lsize-2]] == '\r'){
      end = lsize - 2;
    }
    else{
      end = lsize-1;
    }
  }
  else{
    end = lsize-1;
  }
  for(i=0; i<end; i++){
    if((line[[i]] < 0x20) || (line[[i]] > 0x7E)){
      printf("Error: non ASCII character in PEM file!\n");
      return -1;
    }
    else{
      fprintf(fp, "%c", line[[i]]);
    }
  }
  fprintf(fp, "\\\n");
  return 1;
}
int main(int argc, char* argv[[]]){
  if(argc != 4){
    printf("Error: expected three arguments ...\n");
    return -1;
  }
  if(strcmp("C", argv[[3]]) == 0){
    output_type = OUT_C;
  }
  else if(strcmp("ML", argv[[3]]) == 0){
    output_type = OUT_ML;
  }
  else{
    printf("Error: argument %s is not known (should be \"C\" or \"ML\")\n", argv[[3]]);
    return -1;
  }
  /* Open the input file given as arg1 */
  FILE *f = fopen(argv[[1]], "r");
  if(f == NULL){
    printf("Error: can't open file %s for reading\n", argv[[1]]);
    return -1;
  }
  /* Read the first line and check it depending on the type */
  char *line = NULL;
  size_t len = 0;
  int lsize = mygetline(&line, &len, f);
  /* --------------- */
  /* --------------- */
  if(strcmp(argv[[2]], "cert") == 0){
    FILE *certf;
    if(output_type == OUT_C){
      certf = fopen("src/client-lib/cert_file.h", "w");
    }
    else{
      certf = fopen("src/client-lib/cert_file.inc", "w");
    }
    if(certf == NULL){
      printf("Error: can't open cert header for writing\n");
      return -1;
    }
    if((strcmp(line, "-----BEGIN CERTIFICATE-----\n") != 0) && (strcmp(line, "-----BEGIN CERTIFICATE-----\r\n") != 0)){
      printf("Error: file %s doesn't seem to be a PEM certificate!\n", argv[[1]]);
      return -1;
    }
    /* OK: we have a PEM certificate, copy everything until we reach the end */
    int num_lines = 0;
    if(output_type == OUT_C){
      fprintf(certf, "/* Override the ISO C89 max string length by locally removing warnings */\n");
      fprintf(certf, "#ifdef __GNUC__\n#pragma GCC diagnostic push\n#pragma GCC diagnostic ignored \"-Woverlength-strings\"\n#endif\n");
      fprintf(certf, "const char cert_file_buff[[]] = \"");
    }
    else{
      fprintf(certf, "let cert_file_buff = \"");
    }
    while((strcmp(line, "-----END CERTIFICATE-----\n") != 0) && (strcmp(line, "-----END CERTIFICATE-----\r\n") != 0)){
      if(write_line(certf, line, lsize) != 1){
        return -1;
      }
      lsize = mygetline(&line, &len, f);
      num_lines++;
    }
    if(write_line(certf, line, lsize) != 1){
      return -1;
    }
    if(output_type == OUT_C){
      fprintf(certf, "\";\\n\\n");
      fprintf(certf, "#ifdef __GNUC__\n#pragma GCC diagnostic pop\n#endif\n");
    }
    else{
      fprintf(certf, "\"\\n\\n");
    }

    fclose(certf);
    fclose(f);
  }
  /* --------------- */
  /* --------------- */
  else if(strcmp(argv[[2]], "ca") == 0){
    FILE *caf;
    if(output_type == OUT_C){
      caf = fopen("src/client-lib/ca_file.h", "w");
    }
    else{
      caf = fopen("src/client-lib/ca_file.inc", "w");
    }
    if(caf == NULL){
      printf("Error: can't open ca header for writing\n");
      return -1;
    }
    int num_certs = 0;
    int num_lines = 0;
    /* We might have to get more certificates*/
    if((strcmp(line, "-----BEGIN CERTIFICATE-----\n") != 0) && (strcmp(line, "-----BEGIN CERTIFICATE-----\r\n") != 0)){
      printf("Error: file %s doesn't seem to be a PEM certificate!\n", argv[[1]]);
      return -1;
    }
GET_NEW_CA_CERT:
    num_certs++;
    /* OK: we have a PEM certificate, copy everything until we reach the end */
    if(output_type == OUT_C){
      fprintf(caf, "/* Override the ISO C89 max string length by locally removing warnings */\n");
      fprintf(caf, "#ifdef __GNUC__\n#pragma GCC diagnostic push\n#pragma GCC diagnostic ignored \"-Woverlength-strings\"\n#endif\n");
      fprintf(caf, "const char ca_file_buff%d[[]] = \"", num_certs-1);
    }
    else{
      fprintf(caf, "let ca_file_buff%d = \"", num_certs-1);
    }
    while((strcmp(line, "-----END CERTIFICATE-----\n") != 0) && (strcmp(line, "-----END CERTIFICATE-----\r\n") != 0)){
      if(write_line(caf, line, lsize) != 1){
        return -1;
      }
      lsize = mygetline(&line, &len, f);
      num_lines++;
    }
    if(write_line(caf, line, lsize) != 1){
      return -1;
    }
    if(output_type == OUT_C){
      fprintf(caf, "\";\\n\\n");
      fprintf(caf, "#ifdef __GNUC__\n#pragma GCC diagnostic pop\n#endif\n");
    }
    else{
      fprintf(caf, "\"\\n\\n");
    }
    lsize = mygetline(&line, &len, f);
    if((strcmp(line, "-----BEGIN CERTIFICATE-----\n") == 0) || (strcmp(line, "-----BEGIN CERTIFICATE-----\r\n") == 0)){
      goto GET_NEW_CA_CERT;
    }
    /* We ve got all the certificates */
    if(output_type == OUT_C){
      fprintf(caf, "const char* ca_file_buff[[]] = {");
      unsigned int i;
      for(i=0; i < num_certs-1; i++){
        fprintf(caf, "ca_file_buff%d, ", i);
      }
      fprintf(caf, "ca_file_buff%d};\n\n", num_certs-1);
      fprintf(caf, "#define CA_CERTS_NB %d\n", num_certs);
    }
    else{
      fprintf(caf, "let ca_file_buff = [[");
      unsigned int i;
      for(i=0; i < num_certs-1; i++){
        fprintf(caf, "ca_file_buff%d; ", i);
      }
      fprintf(caf, "ca_file_buff%d]]\n\n", num_certs-1);
    }

    fclose(caf);
    fclose(f);
  }
  /* --------------- */
  /* --------------- */
  else if(strcmp(argv[[2]], "privkey") == 0){
    FILE *privkeyf;
    if(output_type == OUT_C){
      privkeyf = fopen("src/client-lib/private_key_file.h", "w");
    }
    else{
      privkeyf = fopen("src/client-lib/private_key_file.inc", "w"); 
    }
    if(privkeyf == NULL){
      printf("Error: can't open private key header for writing\n");
      return -1;
    }
    if((strcmp(line, "-----BEGIN RSA PRIVATE KEY-----\n") != 0) && (strcmp(line, "-----BEGIN RSA PRIVATE KEY-----\r\n") != 0)){
      printf("Error: file %s doesn't seem to be a PEM certificate!\n", argv[[1]]);
      return -1;
    }
    /* OK: we have a PEM certificate, copy everything until we reach the end */
    int num_lines = 0;
    if(output_type == OUT_C){
      fprintf(privkeyf, "/* Override the ISO C89 max string length by locally removing warnings */\n");
      fprintf(privkeyf, "#ifdef __GNUC__\n#pragma GCC diagnostic push\n#pragma GCC diagnostic ignored \"-Woverlength-strings\"\n#endif\n");
      fprintf(privkeyf, "const char private_key_file_buff[[]] = \"");
    }
    else{
      fprintf(privkeyf, "let private_key_file_buff = \"");
    }
    while((strcmp(line, "-----END RSA PRIVATE KEY-----\n") != 0) && (strcmp(line, "-----END RSA PRIVATE KEY-----\r\n") != 0)){
      if(write_line(privkeyf, line, lsize) != 1){
        return -1;
      }
      lsize = mygetline(&line, &len, f);
      num_lines++;
    }
    if(write_line(privkeyf, line, lsize) != 1){
      return -1;
    }
    if(output_type == OUT_C){
      fprintf(privkeyf, "\";\\n\\n");
      fprintf(privkeyf, "#ifdef __GNUC__\n#pragma GCC diagnostic pop\n#endif\n");
    }
    else{
      fprintf(privkeyf, "\"\\n\\n");
    }

    fclose(privkeyf);
    fclose(f);
  }
  /* --------------- */
  /* --------------- */
  else if(strcmp(argv[[2]], "server") == 0){
    FILE *serverf;
    if(output_type == OUT_C){
      serverf = fopen("src/client-lib/server_file.h", "w");
    }
    else{
      serverf = fopen("src/client-lib/server_file.inc", "w");
    }
    if(serverf == NULL){
      printf("Error: can't open server header for writing\n");
      return -1;
    }
    int num_certs = 0;
    int num_lines = 0;
    /* We might have to get more certificates*/
    if((strcmp(line, "-----BEGIN CERTIFICATE-----\n") != 0) && (strcmp(line, "-----BEGIN CERTIFICATE-----\r\n") != 0)){
      printf("Error: file %s doesn't seem to be a PEM certificate!\n", argv[[1]]);
      return -1;
    }
GET_NEW_SERVER_CERT:
    num_certs++;
    /* OK: we have a PEM certificate, copy everything until we reach the end */
    if(output_type == OUT_C){
      fprintf(serverf, "/* Override the ISO C89 max string length by locally removing warnings */\n");
      fprintf(serverf, "#ifdef __GNUC__\n#pragma GCC diagnostic push\n#pragma GCC diagnostic ignored \"-Woverlength-strings\"\n#endif\n");
      fprintf(serverf, "const char server_file_buff%d[[]] = \"", num_certs-1);
    }
    else{
      fprintf(serverf, "let server_file_buff%d = \"", num_certs-1);
    }
    while((strcmp(line, "-----END CERTIFICATE-----\n") != 0) && (strcmp(line, "-----END CERTIFICATE-----\r\n") != 0)){
      if(write_line(serverf, line, lsize) != 1){
        return -1;
      }
      lsize = mygetline(&line, &len, f);
      num_lines++;
    }
    if(write_line(serverf, line, lsize) != 1){
      return -1;
    }
    if(output_type == OUT_C){
      fprintf(serverf, "\";\\n\\n");
      fprintf(serverf, "#ifdef __GNUC__\n#pragma GCC diagnostic pop\n#endif\n");
    }
    else{
      fprintf(serverf, "\"\\n\\n");
    }
    lsize = mygetline(&line, &len, f);
    if((strcmp(line, "-----BEGIN CERTIFICATE-----\n") == 0) || (strcmp(line, "-----BEGIN CERTIFICATE-----\r\n") == 0)){
      goto GET_NEW_SERVER_CERT;
    }
    /* We ve got all the certificates */
    if(output_type == OUT_C){
      fprintf(serverf, "const char* server_file_buff[[]] = {");
      unsigned int i;
      for(i=0; i < num_certs-1; i++){  
        fprintf(serverf, "server_file_buff%d, ", i);
      }
      fprintf(serverf, "server_file_buff%d};\n\n", num_certs-1);
      fprintf(serverf, "#define SERVER_CERTS_NB %d\n", num_certs);
    }
    else{
      fprintf(serverf, "let server_file_buff = [[");
      unsigned int i;
      for(i=0; i < num_certs-1; i++){
        fprintf(serverf, "server_file_buff%d; ", i);
      }
      fprintf(serverf, "server_file_buff%d]]\n\n", num_certs-1);
    }

    fclose(serverf);
    fclose(f);
  }
  /* --------------- */
  /* --------------- */
  else{
    printf("Error: unknown ssl file type %s (expected \"ca\", \"cert\", \"privkey\" or \"server\")\n", argv[[2]]);
    return -1;
  }
  
  return 0;
}
EOM
$CC $C_FILE -o $FILE &> /dev/null
OUT=$?
if [[ "$OUT" != "0" ]];then
       	AC_MSG_ERROR([problem when compiling $C_FILE])
fi 
if test "$2" != "";then
	# Case where we take care of client ssl files
	$FILE "$1" "cert" $4
	OUT=$?
	if [[ "$OUT" != "0" ]];then
		rm -f $C_FILE $FILE
		AC_MSG_ERROR([problem when importing the ssl file $1 of type cert])
	fi
	$FILE "$2" "ca" $4
	OUT=$?
	if [[ "$OUT" != "0" ]];then
		rm -f $C_FILE $FILE
		AC_MSG_ERROR([problem when importing the ssl file $2 of type ca])
	fi
	$FILE "$3" "privkey" $4
	OUT=$?
	if [[ "$OUT" != "0" ]];then
		rm -f $C_FILE $FILE
		AC_MSG_ERROR([problem when importing the ssl file $3 of type privkey])
	fi
else
	# Case where we take care of server certificate files
	$FILE "$1" "server" $4
	OUT=$?
	if [[ "$OUT" != "0" ]];then
		rm -f $C_FILE $FILE
		AC_MSG_ERROR([problem when importing the ssl file $1 of type server certificates])
	fi
fi
# Job done: remove unnecessary files
rm -f $C_FILE $FILE
])
###################################################################
###################################################################
###################################################################
###################################################################
###################################################################


if test "$with_ssl_clientfiles" != ""
	then
	if test "$with_ssl" == ""
	then
        	AC_MSG_ERROR([--with-ssl-clientfiles needs --with-ssl!])
	fi
	# Parse the given arguments
	sslfilestype=$(echo $sslfiles | sed 's/\([[^;]]*\);.*/\1/g')
        if test "$(echo $sslfiles | grep "ca=")" != ""
        then
	  sslfilesca=$(echo $sslfiles | sed 's/.*ca=\([[^,]]*\).*/\1/g')
        else
          sslfilesca=""
        fi
        if test "$(echo $sslfiles | grep "cert=")" != ""
        then
	  sslfilescert=$(echo $sslfiles | sed 's/.*cert=\([[^,]]*\).*/\1/g')
        else
          sslfilescert=""
        fi
        if test "$(echo $sslfiles | grep "privkey=")" != ""
        then
	  sslfilesprivkey=$(echo $sslfiles | sed 's/.*privkey=\([[^,]]*\).*/\1/g')
        else
          sslfilesprivkey=""
        fi
	AC_MSG_NOTICE([ssl type: $sslfilestype])
	AC_MSG_NOTICE([ssl ca: $sslfilesca])
	AC_MSG_NOTICE([ssl cert: $sslfilescert])
	AC_MSG_NOTICE([ssl privkey: $sslfilesprivkey])
	# If the files are a path, put them in the makefiles
	if test "$sslfilestype" == "path"
	then
		AC_SUBST(c_client_ssl_files, "-DSSL_FILES_PATH")
		AC_SUBST(c_client_ssl_ca_file, "-DPKCS11PROXY_CA_FILE=\\\"$sslfilesca\\\"")
		AC_SUBST(c_client_ssl_cert_file, "-DPKCS11PROXY_CERT_FILE=\\\"$sslfilescert\\\"")
		AC_SUBST(c_client_ssl_privkey_file, "-DPKCS11PROXY_PRIVKEY_FILE=\\\"$sslfilesprivkey\\\"")

		AC_SUBST(caml_client_ssl_files, "-DSSL_FILES_PATH")
		AC_SUBST(caml_client_ssl_ca_file, "-DPKCS11PROXY_CA_FILE=\\\\\\\"$sslfilesca\\\\\\\"")
		AC_SUBST(caml_client_ssl_cert_file, "-DPKCS11PROXY_CERT_FILE=\\\\\\\"$sslfilescert\\\\\\\"")
		AC_SUBST(caml_client_ssl_privkey_file, "-DPKCS11PROXY_PRIVKEY_FILE=\\\\\\\"$sslfilesprivkey\\\\\\\"")
		WRITE_TO_FILE(summary, " -SSL files", "Paths provided")
		WRITE_TO_FILE(summary, "  |SSL CA certificates", "path->$sslfilesca")
		WRITE_TO_FILE(summary, "  |SSL client certificate", "path->$sslfilescert")
		WRITE_TO_FILE(summary, "  |SSL client private key", "path->$sslfilesprivkey")
	else
		if test "$sslfilestype" == "embed"
		then
			# Check if the files exist, trigger an error if this is not the case
			AC_CHECK_FILE($sslfilesca, [], [AC_MSG_ERROR([CA file $sslfilesca does not exist!])])
			AC_CHECK_FILE($sslfilescert, [], [AC_MSG_ERROR([CA file $sslfilescert does not exist!])])
			AC_CHECK_FILE($sslfilesprivkey, [], [AC_MSG_ERROR([CA file $sslfilesprivkey does not exist!])])

			# Embed the files by creating necessary .h files for the C Client 
			AC_SUBST(c_client_ssl_files, "-DSSL_FILES_EMBED")
			AC_SUBST(c_client_ssl_ca_file, "")
			AC_SUBST(c_client_ssl_cert_file, "")
			AC_SUBST(c_client_ssl_privkey_file, "")

			# Embed the files by creating necessary .mli files for the Client 
			AC_SUBST(caml_client_ssl_files, "-DSSL_FILES_EMBED")
			AC_SUBST(caml_client_ssl_ca_file, "")
			AC_SUBST(caml_client_ssl_cert_file, "")
			AC_SUBST(caml_client_ssl_privkey_file, "")
			WRITE_TO_FILE(summary, " -SSL files", "Embedded")
			WRITE_TO_FILE(summary, "  |SSL CA certificates", "embed->$sslfilesca")
			WRITE_TO_FILE(summary, "  |SSL client certificate", "embed->$sslfilescert")
			WRITE_TO_FILE(summary, "  |SSL client private key", "embed->$sslfilesprivkey")
			if test "$with_ocamlclient" == ""
        		then
				CREATE_SSL_HEADERS($sslfilescert, $sslfilesca, $sslfilesprivkey, "C")
			else
				CREATE_SSL_HEADERS($sslfilescert, $sslfilesca, $sslfilesprivkey, "ML")
			fi
		else
			if test "$sslfilestype" == "env"
			then
				# Default path file
				AC_SUBST(c_client_ssl_files, "-DSSL_FILES_ENV")
				AC_SUBST(c_client_ssl_ca_file, "-DPKCS11PROXY_CA_FILE=\"PKCS11PROXY_CA_FILE\"")
				AC_SUBST(c_client_ssl_cert_file, "-DPKCS11PROXY_CERT_FILE=\"PKCS11PROXY_CERT_FILE\"")
				AC_SUBST(c_client_ssl_privkey_file, "-DPKCS11PROXY_PRIVKEY_FILE=\"PKCS11PROXY_PRIVKEY_FILE\"")

				AC_SUBST(caml_client_ssl_files, "-DSSL_FILES_ENV")
				AC_SUBST(caml_client_ssl_ca_file, "-DPKCS11PROXY_CA_FILE=\\\\\\\"PKCS11PROXY_CA_FILE\\\\\\\"")
				AC_SUBST(caml_client_ssl_cert_file, "-DPKCS11PROXY_CERT_FILE=\\\\\\\"PKCS11PROXY_CERT_FILE\\\\\\\"")
				AC_SUBST(caml_client_ssl_privkey_file, "-DPKCS11PROXY_PRIVKEY_FILE=\\\\\\\"PKCS11PROXY_PRIVKEY_FILE\\\\\\\"")

				WRITE_TO_FILE(summary, "-SSL files", "Environment variables (at client runtime)")
				WRITE_TO_FILE(summary, "  |SSL CA certificates", "env->PKCS11PROXY_CA_FILE")
				WRITE_TO_FILE(summary, "  |SSL client certificate", "env->PKCS11PROXY_CERT_FILE")
				WRITE_TO_FILE(summary, "  |SSL client private key", "env->PKCS11PROXY_PRIVKEY_FILE")
				# If the user gave file parameter, tell him that we won't use it
				if test "$sslfilesca" != ""
				then
                                	WRITE_TO_FILE(summary, "  /!\ WARNING!", "CA file provided but env selected => paths are NOT used")
				fi
				if test "$sslfilescert" != ""
				then
                                	WRITE_TO_FILE(summary, "  /!\ WARNING!", "Client certificate file provided but env selected => paths are NOT used")

				fi
				if test "$sslfilesprivkey" != ""
				then
                                	WRITE_TO_FILE(summary, "  /!\ WARNING!", "Client key file provided but env selected => paths are NOT used")

				fi
			else
				AC_MSG_ERROR([Error: --with-ssl-clientfiles $sslfilestype is not known: should be either 'path', 'embed' or 'env'])
			fi
		fi
	fi
else
	# Default are environment variables for ssl client files
	if test "$with_ssl" != ""
	then
		# Default path file
		AC_SUBST(c_client_ssl_files, "-DSSL_FILES_ENV")
		AC_SUBST(c_client_ssl_ca_file, "-DPKCS11PROXY_CA_FILE=\"PKCS11PROXY_CA_FILE\"")
		AC_SUBST(c_client_ssl_cert_file, "PKCS11PROXY_CERT_FILE=\"PKCS11PROXY_CERT_FILE\"")
		AC_SUBST(c_client_ssl_privkey_file, "PKCS11PROXY_PRIVKEY_FILE=\"PKCS11PROXY_PRIVKEY_FILE\"")

		AC_SUBST(caml_client_ssl_files, "-DSSL_FILES_ENV")
		AC_SUBST(caml_client_ssl_ca_file, "-DPKCS11PROXY_CA_FILE=\\\\\\\"PKCS11PROXY_CA_FILE\\\\\\\"")
		AC_SUBST(caml_client_ssl_cert_file, "PKCS11PROXY_CERT_FILE=\\\\\\\"PKCS11PROXY_CERT_FILE\\\\\\\"")
		AC_SUBST(caml_client_ssl_privkey_file, "PKCS11PROXY_PRIVKEY_FILE=\\\\\\\"PKCS11PROXY_PRIVKEY_FILE\\\\\\\"")
	else
		# Undef
		AC_SUBST(c_client_ssl_files, "")
		AC_SUBST(c_client_ssl_ca_file, "")
		AC_SUBST(c_client_ssl_cert_file, "")
		AC_SUBST(c_client_ssl_privkey_file, "")

		AC_SUBST(caml_client_ssl_files, "")
		AC_SUBST(caml_client_ssl_ca_file, "")
		AC_SUBST(caml_client_ssl_cert_file, "")
		AC_SUBST(caml_client_ssl_privkey_file, "")
	fi
fi

# Handling the optional strict server certificates enforcing
if test "$with_ssl_servercerts" != ""
	then
	if test "$with_ssl" == ""
	then
        	AC_MSG_ERROR([--with-ssl-servercerts needs --with-ssl!])
	fi
        # Check if the user provided embed, env or path
 	sslserverfilestype=$(echo $sslservercerts | sed 's/\([[^;]]*\);.*/\1/g')
        getcerts=$(echo $sslservercerts | grep "certs=")
        if test "$getcerts" != ""
        then
		sslfilesserver=$(echo $sslservercerts | sed 's/.*certs=\([[^,]]*\).*/\1/g')
        else
        	sslfilesserver=""
        fi
        if test "$sslfilesserver" == ""
        then
        	AC_MSG_ERROR([Bad --with-ssl-servercerts option formatting, see help])

        fi
        AC_MSG_NOTICE([ssl server certificates type: $sslserverfilestype])
	AC_MSG_NOTICE([ssl server certificates path: $sslfilesserver])

	if test "$sslserverfilestype" == "embed"
	then
		# Check if we have a path or a file
		if [[ -d $sslfilesserver ]]; then
                	# We have a path, create the concatenated file
			cat $sslfilesserver/*.pem > ./server_certs.crt
			cat $sslfilesserver/*.crt >> ./server_certs.crt
			if [[ ! -s ./server_certs.crt ]]; then
				AC_MSG_ERROR([Server certificates path $sslfilesserver does not contain any certificate (please make sure they have a .crt extension)!])
			fi
			WRITE_TO_FILE(summary, " -SSL server certificate files", "Embedded ($sslfilesserver/*.pem and $sslfilesserver/*.crt)")
                else
  			# Check if the files exist, trigger an error if this is not the case
	  		AC_CHECK_FILE($sslfilesserver, [], [AC_MSG_ERROR([Server certificates file $sslfilesserver does not exist!])])
			cp $sslfilesserver ./server_certs.crt	
			WRITE_TO_FILE(summary, " -SSL server certificate files", "Embedded ($sslfilesserver)")
                fi
		# Embed the files by creating necessary .h files for the C Client 
		AC_SUBST(c_client_ssl_server, "-DSSL_SERVER_FILES_EMBED")

		# Embed the files by creating necessary .mli files for the Client 
		AC_SUBST(caml_client_ssl_server, "-DSSL_SERVER_FILES_EMBED")
		if test "$with_ocamlclient" == ""
       		then
			CREATE_SSL_HEADERS("./server_certs.crt", "", "", "C")
		else
			CREATE_SSL_HEADERS("./server_certs.crt", "", "", "ML")
		fi
		# Purge the local crt file
		rm ./server_certs.crt
	else
		AC_MSG_ERROR([Error: --with-ssl-server $sslserverfilestype is not known: should be 'embed'])
	fi
else
	AC_SUBST(c_client_ssl_server, "")
	AC_SUBST(caml_client_ssl_server, "")
fi



# Compiling with/without the filter
if test "$with_filter" == "yes"
then
        AC_SUBST(filter_include, "-I \$(filter_filter_dir) -I \$(filter_frontend_dir)")
        AC_SUBST(filter_files, "\$(filter_backend_dir)/backend.cmx \$(filter_filter_dir)/filter_common.cmx \$(filter_filter_dir)/filter_actions.cmx \$(filter_filter_dir)/filter_configuration.cmx \$(filter_filter_dir)/filter.cmx  \$(filter_frontend_dir)/frontend.cmx")
        AC_SUBST(filter_define, "")
        AC_SUBST(with_filter, "filter")
        AC_SUBST(with_filter_clean, "filter_clean")
        WRITE_TO_FILE(summary, "Using PKCS11 filter on server side", "YES")
else
        AC_SUBST(filter_include, "-package \"str\"")
        AC_SUBST(filter_files, "")
        AC_SUBST(filter_define, "-DWITHOUT_FILTER")
        AC_SUBST(with_filter, "")
        AC_SUBST(with_filter_clean, "")
        WRITE_TO_FILE(summary, "Using PKCS11 filter on server side", "NO")
fi

# With or without the sessions and objects handles aliasing
if test "$with_aliasing" != ""
then
        if test "$aliasing" == "yes"
        then
                aliasing="rand"
        fi
        if test "$aliasing" == "inc"
        then
                AC_SUBST(aliasing_def, "-DUSE_ALIASING")
                WRITE_TO_FILE(summary, "Aliasing (sessions and objects handles)", "inc (incremental)")
        else
                if test "$aliasing" == "rand"
                then
                        AC_SUBST(aliasing_def, "-DUSE_ALIASING -DRANDOM_ALIASING")
                        WRITE_TO_FILE(summary, "Aliasing (sessions and objects handles)", "rand (random)")
                else
                        AC_SUBST(aliasing_def, "")
                        AC_MSG_ERROR([Unknown aliasing method $aliasing])
                fi
        fi
else
        WRITE_TO_FILE(summary, "Aliasing (sessions and objects handles)", "none")
fi

# Compiling with the daemonization primitives
if test "$with_daemonize" == "yes"
then
	AC_SUBST(caml_server_daemonize_define, "-DDAEMONIZE")
	WRITE_TO_FILE(summary, "Compiling daemonization support", "YES")
else
	AC_SUBST(caml_server_daemonize_define, "")
	WRITE_TO_FILE(summary, "Compiling daemonization support", "NO")
fi

  #Enable compiling other components
  AC_SUBST(with_bindings, "bindings")
  AC_SUBST(with_bindings_clean, "bindings_clean")
  AC_SUBST(with_rpc, "rpc")
  AC_SUBST(with_rpc_clean, "rpc_clean")
  AC_SUBST(with_client, "client")
  AC_SUBST(with_client_clean, "client_clean")
  AC_SUBST(with_server, "server")
  AC_SUBST(with_server_clean, "server_clean")

else # --without-caml-crush was set
  #Disable compiling other components
  AC_SUBST(with_bindings, "bindings")
  AC_SUBST(with_bindings_clean, "bindings_clean")
  AC_SUBST(with_rpc, "")
  AC_SUBST(with_rpc_clean, "")
  AC_SUBST(with_filter, "")
  AC_SUBST(with_filter_clean, "")
  AC_SUBST(with_client, "")
  AC_SUBST(with_client_clean, "")
  AC_SUBST(with_server, "")
  AC_SUBST(with_server_clean, "")

  WRITE_TO_FILE(summary, "bindings only", "OCaml PKCS11 bindings only")
  AC_MSG_NOTICE([Compiling OCaml bindings only])
fi #END COMPILE CAML CRUSH


AC_OUTPUT(Makefile)

SHOW_SUMMARY([summary])
