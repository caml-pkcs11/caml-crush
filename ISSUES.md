# Caml Crush: an OCaml PKCS#11 filtering proxy

## Current ISSUES and LIMITATIONS

The following document address the current issues and limitations of the
project.

Back to [README.md](README.md).

## Summary

  * Client library
    * [Handling CK\_MECHANISM structures](#Mech)
    * [Handling buffers](#Buffer)
    * [Handling synchronization](#Sync)
  * Server and filter limitations library
    * [PFS](#PFS)
    * [Client library redirection based on connection source](#Redir)
    * [Possible DoS](#DoS)
  * Misc
    * [Unsupported PKCS#11 features](#Unsupported)
    * [OpenBSD](#BSD)

### Client library

#### Handling CK\_MECHANISM structures <a name="Mech"></a>

The following functions are designed to do their best to parse input mechanism structures:

    value custom_c2ml_pkcs11_struct_ck_mechanism(struct ck_mechanism *_c1,
                                             camlidl_ctx _ctx);
    void custom_sanitize_ck_mechanism(struct ck_mechanism *mech);

PKCS#11 allows vendors to define their own custom mechanism. It can be used
by passing **CKM\_VENDOR\_DEFINED** as mechanism type in the structure.
Vendors are free to use whatever suits their needs as mechanism parameter.
Our implementation only support vendor defined mechanism that are using an 
**unsigned char array** as parameter.

#### Handling buffers <a name="Buffer"></a>

When designing our OCaml PKCS#11 bindings we decided **not** to reproduce some
of the concepts of the standard.

For instance, one can call the C\_Digest() function with an insufficiently large receive 
buffer. When this happens, the standard states that the middleware is supposed to do the
following:

  * update the pointer that holds the length of the buffer
  * return the CKR\_BUFFER\_TOO\_SMALL error code 

This way the client application can use the updated counter value to allocate 
some more memory and call C\_Digest(). The same check is performed and the
result gets copied if the buffer is large enough. 
We can picture the C\_Digest() operation as a couple of transactions that will be made.

We chose to relax this constraint on the OCaml side. Developers using those
bindings do not have to care about memory allocation. Therefore when calling
C\_Digest() from OCaml, the value is immediately returned to the caller.
A subsequent call to C\_Digest() would logically result with the 
CKR\_OPERATION\_NOT\_INITIALIZED error code.

This is fine until you assemble all the pieces together. Because PKCS#11 client
applications that will use our PKCS#11 client library which communicate with
the proxy will expect the "classic" behavior described earlier.

Therefore, we had to manage a state within the client library to keep results 
in memory, checking that the application is giving us a large enough buffer or 
returning CKR\_BUFFER\_TOO\_SMALL when needed.
The workaround uses a linked list to keep track of calls made to crypto operations
and stores the result for the given slot/session\_id until the client has allocated its memory and
calls the function again to fetch the result.

The following functions are concerned:

  - C\_Digest/C\_Encrypt/C\_Decrypt/C\_Sign
  - C\_DigestUpdate/C\_EncryptUpdate/C\_DecryptUpdate/C\_SignUpdate
  - C\_DigestFinal/C\_EncryptFinal/C\_DecryptFinal/C\_SignFinal
  - C\_DigestEncryptUpdate/C\_DecryptDigestUpdate/C\_SignEncryptUpdate/C\_DecryptVerifyUpdate
  - C\_SignRecover/C\_VerifyRecover
  - C\_WrapKey
  - C\_GetOperationState

This is transparent to the client applications.

#### Handling synchronization (OCaml client library) <a name="Sync"></a>

On the synchronization side, a global lock is implemented around the calls in order
for the client library to be thread safe. The main issue is that it is not possible
for multiple threads to call the OCaml runtime in a safe way. At most one thread can
call the runtime. Therefore, a global mutex is used to serialize PKCS#11 calls.
This works well for most of the PKCS#11 calls except the C\_WaitForSlotEvent call which
can block. To avoid deadlocks, when an application calls C\_WaitForSlotEvent
with the block flag, the library will poll for events with the non-blocking function.

This is transparent to the application.

#### Handling synchronization (C client library)

Although the C client library is not concerned by the synchronization issue
described previously, we decided to keep the locking strategy.
Therefore the C client library uses the same synchronization primitives.
It make the code more readable and has no side effects.
This potentially reduces performance and could be improved in future releases.

### Server and filter limitations library

#### [PFS][] (Perfect Forward Secrecy) support <a name="PFS"></a>
The up-to-date package of [ocaml-ssl][] is only able to do TLS 1.0 sessions
establishment. This means that the ciphersuites available do not include newer
algorithms (such as AES-GCM).
[ocaml-ssl]: https://github.com/savonet/ocaml-ssl

The second issue is that the code (up to 0.4.6) does not support initializing a
Diffie-Hellman context for OpenSSL. Meaning that even on TLS 1.0, DHE-suites
are not available. With binary versions of [ocaml-ssl][] and [ocamlnet][], [PFS][] 
is therefore **not** available.
[ocamlnet]: http://projects.camlcity.org/projects/ocamlnet.html
[PFS]: http://en.wikipedia.org/wiki/Forward_secrecy

We strongly recommend using PFS, this is why we pushed modifications 
to [ocaml-ssl][] to support TLS 1.2 and to add code to initialize a DH context 
 - see [this][pull3] pull request as well as [this one][pull4].
[pull3]: https://github.com/savonet/ocaml-ssl/pull/3
[pull4]: https://github.com/savonet/ocaml-ssl/pull/4

Until these modifications make it in the binary distribution, you need to
recompile [ocaml-ssl][] and [ocamlnet][] (more details on the dependencies 
in the [documentation](doc/INDEX.md)).

#### Client library redirection based on connection source <a name="Redir"></a>
For now, the same PKCS#11 library (provided in the configuration file) is 
loaded for all the clients. One would want to load different libraries 
depending on the client: for instance depending on its certificate, on its 
IP address, and so on. This feature is planned in future releases.

#### Possible Denial-of-Service (DoS) <a name="DoS"></a>

The server code has two potential issues regarding DoS.

##### Unhandled SSL exceptions
Exceptions that arise when using [ocamlnet][] with SSL are not properly handled.
When this happens, the container instance stays in a **zombie** state.

This issue has been communicated to the [ocamlnet][] and fixed with a patch
for the ocamlnet-3.6.6 version. Patch is available:

  * [here][1] 
  * [or here][2]

[1]: http://permalink.gmane.org/gmane.comp.lang.ocaml.lib.net.devel/360
[2]: http://sourceforge.net/mailarchive/message.php?msg_id=31717036


##### RPC system shutdown
The ocamlnet library used to implement the server process uses a master/slave approach.
When the server receives a new connection, a child process is forked and work
is assigned. In order to synchronize and send/receive orders, the server process
and container communicate through a Unix socket. This socket can also be used
for the administration of the server process. Therefore, if an attacker finds a 
vulnerability in the container process, it could use the socket to shutdown 
the server process.

This issue is related to the design of the Netplex library, we plan to modify
the current implementation in order to separate the communication channel
and the administration of the Netplex process.

### Misc
#### Unsupported PKCS#11 features <a name="Unsupported"></a>

The project lacks the following features:

  * Support for callbacks (C\_OpenSession, ...)

Adding support for callback is not an impossible task, but as this is not a
widely used functionnality we decided to focus on other features. We plan 
however to add it in a future release.


#### OpenBSD <a name="BSD"></a>

  - C client cannot be compiled because the RPC "hyper" symbol is missing
  - Check support for the OCaml client.
