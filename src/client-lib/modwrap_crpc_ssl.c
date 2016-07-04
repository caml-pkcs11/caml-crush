/*------------------------ MIT License HEADER ------------------------------------
    Copyright ANSSI (2013-2015)
    Contributors : Ryad BENADJILA [ryad.benadjila@ssi.gouv.fr],
    Thomas CALDERON [thomas.calderon@ssi.gouv.fr]
    Marion DAUBIGNARD [marion.daubignard@ssi.gouv.fr]

    This software is a computer program whose purpose is to implement
    a PKCS#11 proxy as well as a PKCS#11 filter with security features
    in mind. The project source tree is subdivided in six parts.
    There are five main parts:
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

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.

    Except as contained in this notice, the name(s) of the above copyright holders
    shall not be used in advertising or otherwise to promote the sale, use or other
    dealings in this Software without prior written authorization.

    The current source code is part of the client library 5] source tree:
                                                          --------------------
                                                         | 5] Client library  |
                                                         |  --------          |
                                                         | |        | PKCS#11 |
                                                         | |        |functions|
                                                         |  --------          |
                                                          --------------------
                                                                    |
                                                                    |
                                                          { PKCS#11 INTERFACE }
                                                                    |
                                                              APPLICATION

    Project: PKCS#11 Filtering Proxy
    File:    src/client-lib/modwrap_crpc_ssl.c

-------------------------- MIT License HEADER ----------------------------------*/
#define GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#ifdef WITH_SSL
#include "modwrap.h"

/* Init global paths to certificates depending on the configured strategy */
#ifdef SSL_FILES_PATH
const char ca_file_path[] = PKCS11PROXY_CA_FILE;
const char cert_file_path[] = PKCS11PROXY_CERT_FILE;
const char private_key_path[] = PKCS11PROXY_PRIVKEY_FILE;
#elif defined(SSL_FILES_ENV)
const char *ca_file_path;
const char *cert_file_path;
const char *private_key_path;
#elif defined(SSL_FILES_EMBED)
/* These include files contain the certificates and the private key to use for ssl */
#include "ca_file.h"
#include "cert_file.h"
#include "private_key_file.h"
#ifdef SSL_SERVER_FILES_EMBED
#include "server_file.h"
#endif
#ifdef GNU_TLS
/* Embedded GnuTLS data */
gnutls_datum_t ca_file_mem[CA_CERTS_NB];
gnutls_datum_t cert_file_mem;
gnutls_datum_t private_key_file_mem;
#else
/* Embedded OpenSSL data */
/* CA_CERTS_NB is defined in the ca_file.h file */
BIO *ca_file_mem_bio[CA_CERTS_NB];
BIO *cert_file_mem_bio;
BIO *private_key_file_mem_bio;
X509 *ca_file_mem[CA_CERTS_NB];
X509 *cert_file_mem;
RSA *private_key_file_mem;
#endif
#else
#error WITH_SSL but no method were found to provide certificates
#endif

#if defined(SSL_SERVER_FILES_EMBED)
/* Check if a given certificate is in a list of certificates */
#ifdef GNU_TLS
/* GnuTLS case */

unsigned char is_certificate_in_list(gnutls_datum_t* cert, const char* cert_pem_list[], int cert_pem_list_num);
unsigned char is_certificate_in_list(gnutls_datum_t* cert, const char* cert_pem_list[], int cert_pem_list_num){
  /* In order to compare certificates, we compare their DER representation */
  int i;

  for(i=0; i<cert_pem_list_num; i++){
    gnutls_datum_t tmp_cert_pem;
    gnutls_datum_t tmp_cert_der;
    int ret;

    /* Get DER from PEM files */
    tmp_cert_pem.data = (unsigned char*)cert_pem_list[i];
    tmp_cert_pem.size = strlen(cert_pem_list[i]);
    ret = gnutls_pem_base64_decode_alloc("CERTIFICATE", &tmp_cert_pem, &tmp_cert_der);
    if(ret != GNUTLS_E_SUCCESS){
      printf("Error when getting allowed server certificate from memory (embedded PEM files to DER)\n");
      return 0;
    }
    if(tmp_cert_der.size == cert->size){
      if(memcmp(tmp_cert_der.data, cert->data, cert->size) == 0){
        /* We have found a good certificate */
        free(tmp_cert_der.data);
        return 1;
      }
    }
    gnutls_free(tmp_cert_der.data);
  }
  return 0;
}
#else
/* OpenSSL case: we have a X59 internal structure to be compared with PEM files */
unsigned char is_certificate_in_list(X509* cert, const char* cert_pem_list[], int cert_pem_list_num);
unsigned char is_certificate_in_list(X509* cert, const char* cert_pem_list[], int cert_pem_list_num){
  /* In order to compare certificates, we compare their DER representation */
  int i, len;
  unsigned char *buf, *cert_der;
  /* X509 to DER */
  len = i2d_X509(cert, NULL);
  buf = OPENSSL_malloc(len);
  if(buf == NULL){
    printf("Error when comparing allowed server certificate: client certificate X509 to DER failed \n");
    return 0;
  }
  cert_der = buf;
  i2d_X509(cert, &buf);

  for(i=0; i<cert_pem_list_num; i++){
    BIO *tmp_bio = NULL;
    X509* tmp_cert = NULL;
    unsigned char *tmp_buf, *tmp_cert_der;
    int tmp_len;

    /* Get the PEM of the certificate we want to compare and transform it to DER representation */
    tmp_bio = BIO_new_mem_buf((char *)cert_pem_list[i], -1);
    tmp_cert = PEM_read_bio_X509(tmp_bio, NULL, 0, NULL);
    if (tmp_cert == NULL) {
      /* Cleanup */
      OPENSSL_free(cert_der);
      BIO_free(tmp_bio);
      printf("Error when getting allowed server certificate from memory (embedded PEM files)\n");
      return 0;
    }
    /* X509 to DER */
    tmp_len = i2d_X509(tmp_cert, NULL);
    tmp_buf = (unsigned char*)malloc(tmp_len);
    if(buf == NULL){
      /* Cleanup */
      OPENSSL_free(cert_der);
      BIO_free(tmp_bio);
      printf("Error when comparing allowed server certificate: server certificate X509 to DER failed \n");
      return 0;
    }
    tmp_cert_der = tmp_buf;
    i2d_X509(tmp_cert, &tmp_buf);

    /* We have our two DER representations, compare them */
    if(len != tmp_len){
      goto TEST_NEXT;
    }
    if(memcmp(cert_der, tmp_cert_der, len) != 0){
      goto TEST_NEXT;
    }
    else{
      /* Comparison is OK */
      OPENSSL_free(cert_der);
      BIO_free(tmp_bio);
      X509_free(tmp_cert);
      OPENSSL_free(tmp_cert_der);
      return 1;
    }

TEST_NEXT:
    /* Cleanup */
    BIO_free(tmp_bio);
    X509_free(tmp_cert);
    OPENSSL_free(tmp_cert_der);
  }

  /* Cleanup */
  OPENSSL_free(cert_der);
  return 0;
}
#endif
#endif

int provision_certificates(void)
{
#if defined(SSL_FILES_EMBED)
  int i;
  /* We handle SSL_FILES_EMBED here */
#ifdef GNU_TLS
  /* GnuTLS case */
  /* CA chain files */
  for (i = 0; i < CA_CERTS_NB; i++) {
    ca_file_mem[i].data = (unsigned char *)(ca_file_buff[i]);
    /* Size is statically determined, -1 for the null terminating byte */
    if ((int)(sizeof(ca_file_buff[i]) - 1) <= 0) {
      fprintf(stderr, "Error when getting ca ...\n");
      return -1;
    } else {
      ca_file_mem[i].size = sizeof(ca_file_buff[i]) - 1;
    }
  }
  /* Cert file */
  cert_file_mem.data = (unsigned char *)cert_file_buff;
  /* Size is statically determined, -1 for the null terminating byte */
  if ((int)(sizeof(cert_file_buff) - 1) <= 0) {
    fprintf(stderr, "Error when getting cert ...\n");
    return -1;
  } else {
    cert_file_mem.size = sizeof(cert_file_buff) - 1;
  }
  /* Private key file */
  private_key_file_mem.data = (unsigned char *)private_key_file_buff;
  /* Size is statically determined, -1 for the null terminating byte */
  if ((int)(sizeof(private_key_file_buff) - 1) <= 0) {
    fprintf(stderr, "Error when getting private key ...\n");
    return -1;
  } else {
    private_key_file_mem.size = sizeof(private_key_file_buff) - 1;
  }
#else
  /* OpenSSL case */
  /* CA chain files */
  for (i = 0; i < CA_CERTS_NB; i++) {
    ca_file_mem_bio[i] = BIO_new_mem_buf((char *)(ca_file_buff[i]), -1);
    ca_file_mem[i] = PEM_read_bio_X509(ca_file_mem_bio[i], NULL, 0, NULL);
    if (ca_file_mem[i] == NULL) {
      printf
	  ("Error when getting certificate %d from the CA chain in memory (embedded PEM files)\n",
	   i);
      return -1;
    }
  }
  /* Client cert file */
  cert_file_mem_bio = BIO_new_mem_buf((char *)cert_file_buff, -1);
  cert_file_mem = PEM_read_bio_X509(cert_file_mem_bio, NULL, 0, NULL);
  if (cert_file_mem == NULL) {
    printf
	("Error when getting client certificate from memory (embedded PEM files)\n");
    return -1;
  }
  /* Client private key */
  private_key_file_mem_bio = BIO_new_mem_buf((char *)private_key_file_buff, -1);
  private_key_file_mem =
      PEM_read_bio_RSAPrivateKey(private_key_file_mem_bio, NULL, 0, NULL);
  if (private_key_file_mem == NULL) {
    printf("Error when getting private key from memory (embedded PEM files)\n");
    return -1;
  }
#endif
/*****/
#elif defined(SSL_FILES_ENV)
  ca_file_path = getenv(xstr(PKCS11PROXY_CA_FILE));
  cert_file_path = getenv(xstr(PKCS11PROXY_CERT_FILE));
  private_key_path = getenv(xstr(PKCS11PROXY_PRIVKEY_FILE));
  if (ca_file_path == NULL || cert_file_path == NULL
      || private_key_path == NULL) {
    printf
	("PKCS11PROXY_CA_FILE/PKCS11PROXY_CERT_FILE/PKCS11PROXY_PRIVKEY_FILE environment variables not set\n");
    return -1;
  }
#endif
  return 0;
}

void override_net_functions(CLIENT * client)
{
  struct ct_data *ct = (struct ct_data *)client->cl_private;
  xdrrec_create(&(ct->ct_xdrs), 0, 0, (caddr_t) ct, readnet, writenet);
}

#ifdef WIN32 /* In the Windows case, use native WIN32 API */
int readnet(char *ctptr, char *buf, int len)
{
  fd_set mask;
  fd_set readfds;
  struct ct_data *ct = (struct ct_data *)ctptr;

#ifdef DEBUG
  fprintf(stderr, "client: overriding readtcp, len = %d\n", len);
#endif

  if (len == 0)
          return 0;
  FD_ZERO(&mask);
  FD_SET(ct->ct_sock, &mask);

  while (TRUE) {
    readfds = mask;
    switch (select(0 /* unused in winsock */, &readfds, NULL, NULL,
                   &(ct->ct_wait))) {
    case 0:
            ct->ct_error.re_status = RPC_TIMEDOUT;
            return -1;

    case -1:
            if (WSAerrno == EINTR)
                    continue;
            ct->ct_error.re_status = RPC_CANTRECV;
            ct->ct_error.re_errno = WSAerrno;
            return -1;
    }
    break;
  }
#ifdef GNU_TLS
  /* Perform the actual read using GnuTLS, which will read
   * one TLS "record", which is hopefully a complete message.
   */
  len = gnutls_record_recv(gnutls_global_session, buf, len);
#else
  len = SSL_read(ssl, buf, len);
#endif
  switch (len) {
  case 0:
          /* premature eof */
          ct->ct_error.re_errno = WSAECONNRESET;
          ct->ct_error.re_status = RPC_CANTRECV;
          len = -1;  /* it's really an error */
          break;

  case -1:
          ct->ct_error.re_errno = WSAerrno;
          ct->ct_error.re_status = RPC_CANTRECV;
          break;
  }
  return len;
}
#else /* *NIX case */
int readnet(char *ctptr, char *buf, int len)
{
  struct ct_data *ct = (struct ct_data *)ctptr;
  struct pollfd fd;
  int milliseconds = (ct->ct_wait.tv_sec * 1000) + (ct->ct_wait.tv_usec / 1000);

#ifdef DEBUG
  fprintf(stderr, "client: overriding readtcp, len = %d\n", len);
#endif

  if (len == 0)
    return 0;

  /* The poll here is copied from the original readtcp.  It's
   * to allow the RPC layer to implement a timeout.
   */
  fd.fd = ct->ct_sock;
  fd.events = POLLIN;
  while (TRUE) {
    switch (poll(&fd, 1, milliseconds)) {
    case 0:
      ct->ct_error.re_status = RPC_TIMEDOUT;
      return -1;

    case -1:
      if (errno == EINTR)
	continue;
      ct->ct_error.re_status = RPC_CANTRECV;
      ct->ct_error.re_errno = errno;
      return -1;
    }
    break;
  }

#ifdef GNU_TLS
  /* Perform the actual read using GnuTLS, which will read
   * one TLS "record", which is hopefully a complete message.
   */
  len = gnutls_record_recv(gnutls_global_session, buf, len);
#else
  len = SSL_read(ssl, buf, len);
#endif
  switch (len) {
  case 0:
    /* premature eof */
    ct->ct_error.re_errno = ECONNRESET;
    ct->ct_error.re_status = RPC_CANTRECV;
    len = -1;			/* it's really an error */
    break;

  case -1:
    ct->ct_error.re_errno = errno;
    ct->ct_error.re_status = RPC_CANTRECV;
    break;
  }

  return len;
}
#endif /* end switch between WIN32 and non WIN32 */

/* The writing SSL override is the same for WIN32 and 
 * *NIX cases
 */
int writenet(char *ctptr, char *buf, int len)
{
  struct ct_data *ct = (struct ct_data *)ctptr;

#ifdef DEBUG
  fprintf(stderr, "client: overriding writetcp, len = %d\n", len);
#endif

#ifdef GNU_TLS
  if (gnutls_record_send(gnutls_global_session, buf, len) < 0) {
#else
  if (SSL_write(ssl, buf, len) <= 0) {
#endif
    ct->ct_error.re_errno = errno;
    ct->ct_error.re_status = RPC_CANTSEND;
    return -1;
  }

  return len;
}
#endif /* end of SSL case where we override read and write functions */

/* A very basic TLS client, with X.509 authentication. */
#ifdef GNU_TLS

int start_gnutls(int sock)
{
  int ret;
  const char *err;
  unsigned certslen = 0;
  const gnutls_datum_t *certs;
  unsigned status = (unsigned)-1;
#ifdef SSL_FILES_EMBED
  int i;
#endif
  gnutls_global_session_allocated = xcred_allocated = 0;

  gnutls_global_init();

  /* X509 stuff */
  gnutls_certificate_allocate_credentials(&xcred);
  xcred_allocated = 1;

  /* Call our custom certificate lookup function */
  ret = provision_certificates();
  if (ret != 0) {
    return ret;
  }
#ifdef SSL_FILES_EMBED
  for (i = 0; i < CA_CERTS_NB; i++) {
    ret =
	gnutls_certificate_set_x509_trust_mem(xcred, &ca_file_mem[i],
					      GNUTLS_X509_FMT_PEM);
    if (ret < 0) {
      fprintf(stderr, "*** failed\n");
      gnutls_perror(ret);
      return ret;
    }
  }
#else
  /* sets the trusted cas file */
  ret =
      gnutls_certificate_set_x509_trust_file(xcred, ca_file_path,
					     GNUTLS_X509_FMT_PEM);
  if (ret < 0) {
    fprintf(stderr, "*** failed\n");
    gnutls_perror(ret);
    return ret;
  }
#endif
#ifdef SSL_FILES_EMBED
  ret =
      gnutls_certificate_set_x509_key_mem(xcred, &cert_file_mem,
					  &private_key_file_mem,
					  GNUTLS_X509_FMT_PEM);
#else
  /* sets the client cert/key cas file */
  ret =
      gnutls_certificate_set_x509_key_file(xcred, cert_file_path,
					   private_key_path,
					   GNUTLS_X509_FMT_PEM);
#endif
  if (ret < 0) {
    fprintf(stderr, "*** failed\n");
    gnutls_perror(ret);
    return ret;
  }

  /* Initialize TLS session */
  gnutls_init(&gnutls_global_session, GNUTLS_CLIENT);
  gnutls_global_session_allocated = 1;

  /* Use default priorities */
  ret = gnutls_priority_set_direct(gnutls_global_session, "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2", &err);
  if (ret < 0) {
    if (ret == GNUTLS_E_INVALID_REQUEST) {
      fprintf(stderr, "Syntax error at: %s\n", err);
    }
    return ret;
  }

  /* put the x509 credentials to the current session */
  gnutls_credentials_set(gnutls_global_session, GNUTLS_CRD_CERTIFICATE, xcred);

  /* connect to the peer with previous socket */
  gnutls_transport_set_ptr(gnutls_global_session,
			   (gnutls_transport_ptr_t) (long)sock);

  /* Perform the TLS handshake */
  ret = gnutls_handshake(gnutls_global_session);

  if (ret < 0) {
    fprintf(stderr, "*** Handshake failed\n");
    gnutls_perror(ret);
    return ret;
  }
#ifdef DEBUG
  fprintf(stderr, "- Handshake was completed\n");
  /* XXX You need to verify the peer's certificate matches its name. */
  fprintf(stderr, "XXX need to verify peer's certificate matches its name.\n");
#endif

  /*
   *  Obtain the server certificate chain.  The server certificate
   *  itself is stored in the first element of the array.
   */
  certs = gnutls_certificate_get_peers(gnutls_global_session, &certslen);
  if (certs == NULL || certslen == 0) {
    fprintf(stderr, "error: could not obtain peer certificate\n");
    return -1;
  }

  /* Validate the certificate chain. */
  ret = gnutls_certificate_verify_peers2(gnutls_global_session, &status);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "error: gnutls_certificate_verify_peers2: %s\n",
	    gnutls_strerror(ret));
    return -1;
  }

#ifdef SSL_SERVER_FILES_EMBED
  /* We have to check the provided authorized server certificates */
  if(is_certificate_in_list((gnutls_datum_t*)&certs[0], server_file_buff, SERVER_CERTS_NB) == 0){
    fprintf(stderr, "SSL_connect error: peer server certificate is not in the allowed list!\n");
    return -1;
  }
#endif

  /* Print session info. */
#ifdef DEBUG
  print_info(gnutls_global_session);
#endif
  return 0;
}

/* Destroy GNU_TLS SSL context */
int purge_gnutls(void)
{
  if(gnutls_global_session_allocated == 1){
    gnutls_bye(gnutls_global_session, GNUTLS_SHUT_RDWR);
    gnutls_deinit(gnutls_global_session);
  }
  if(xcred_allocated == 1){
    gnutls_certificate_free_credentials(xcred);
  }
  gnutls_global_deinit();

  return 0;
}

#ifdef DEBUG
#ifdef __GNUC__
/* Locally remove the gcc warning about unused function */
/* (we leave the code for potential debug purpose)      */
__attribute__ ((used))
static void tls_log_func(int level, const char *str)
#else
static void tls_log_func(int level, const char *str)
#endif
{
  fprintf(stderr, "|<%d>| %s", level, str);
}
#endif

/* This is an informational function which prints details of the GnuTLS
 * session.
 */
void print_info(gnutls_session_t gsession)
{
  const char *tmp;
  gnutls_credentials_type_t cred;
  gnutls_kx_algorithm_t kx;

  /* print the key exchange's algorithm name */
  kx = gnutls_kx_get(gsession);
  tmp = gnutls_kx_get_name(kx);
  fprintf(stderr, "- Key Exchange: %s\n", tmp);

  /* Check the authentication type used and switch
   * to the appropriate.
   */
  cred = gnutls_auth_get_type(gsession);
  switch (cred) {
  case GNUTLS_CRD_SRP:
    fprintf(stderr, "- SRP session with username <not supported>\n");
    /* The following function has gone walkies in my version of GnuTLS:
     * gnutls_srp_server_get_username (gsession);
     */
    break;

  case GNUTLS_CRD_ANON:	/* anonymous authentication */

    fprintf(stderr, "- Anonymous DH using prime of %d bits\n",
	    gnutls_dh_get_prime_bits(gsession));
    break;

  case GNUTLS_CRD_CERTIFICATE:	/* certificate authentication */

    /* Check if we have been using ephemeral Diffie Hellman.
     */
    if (kx == GNUTLS_KX_DHE_RSA || kx == GNUTLS_KX_DHE_DSS) {
      fprintf(stderr, "\n- Ephemeral DH using prime of %d bits\n",
	      gnutls_dh_get_prime_bits(gsession));
    }

    /* if the certificate list is available, then
     * print some information about it.
     */
    /*
       print_x509_certificate_info (gsession);
     */

  case GNUTLS_CRD_PSK:
    fprintf(stderr, "- PSK\n");
    break;

  case GNUTLS_CRD_IA:
    fprintf(stderr, "- IA\n");
    break;
  }				/* switch */

  /* print the protocol's name (ie TLS 1.0)
   */
  tmp = gnutls_protocol_get_name(gnutls_protocol_get_version(gsession));
  fprintf(stderr, "- Protocol: %s\n", tmp);

  /* print the certificate type of the peer.
   * ie X.509
   */
  tmp = gnutls_certificate_type_get_name(gnutls_certificate_type_get(gsession));

  fprintf(stderr, "- Certificate Type: %s\n", tmp);

  /* print the compression algorithm (if any)
   */
  tmp = gnutls_compression_get_name(gnutls_compression_get(gsession));
  fprintf(stderr, "- Compression: %s\n", tmp);

  /* print the name of the cipher used.
   * ie 3DES.
   */
  tmp = gnutls_cipher_get_name(gnutls_cipher_get(gsession));
  fprintf(stderr, "- Cipher: %s\n", tmp);

  /* Print the MAC algorithms name.
   * ie SHA1
   */
  tmp = gnutls_mac_get_name(gnutls_mac_get(gsession));
  fprintf(stderr, "- MAC: %s\n", tmp);
}
#endif

#if defined(WITH_SSL) && !defined(GNU_TLS)

int start_openssl(int sock)
{
  int ret;
  int verifystatus;
  X509 *peercert;
#ifdef SSL_FILES_EMBED
  int i;
  X509_STORE *openssl_store;
#endif
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  /* Deprecated in openssl >= 1.1.0 */
  SSL_load_error_strings();
  SSL_library_init();
#else
  OPENSSL_init_ssl(0, NULL);
#endif
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  ctx = SSL_CTX_new(TLSv1_2_method());
#else
  ctx = SSL_CTX_new(TLS_method());
#endif
  if (ctx == NULL) {
    fprintf(stderr, "OpenSSL error could not create SSL CTX\n");
    return -1;
  }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  /* For openssl >= 1.1.0 set the minimum TLS version
   * with SSL_CTX_set_min_proto_version
   */
  ret = SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  if(ret == 0){
    fprintf(stderr, "OpenSSL error when setting TLS1_2 with SSL_CTX_set_min_proto_version\n");
    return -1;
  }
#endif

#ifdef SSL_OP_NO_COMPRESSION
  /* No compression and no SSL_v2 */
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_COMPRESSION);
#else
  /* OpenSSL might not support disabling compression */
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
#endif

  /* Call our custom certificate lookup function */
  ret = provision_certificates();
  if (ret != 0) {
    return ret;
  }
#ifdef SSL_FILES_EMBED
  openssl_store = SSL_CTX_get_cert_store(ctx);
  if (openssl_store == NULL) {
    fprintf(stderr, "OpenSSL error while loading the X509 certificate store\n");
    return -1;
  }
  for (i = 0; i < CA_CERTS_NB; i++) {
    ret = X509_STORE_add_cert(openssl_store, ca_file_mem[i]);
    if (ret != 1) {
      fprintf(stderr, "OpenSSL error while loading %d CA certificate\n", i);
      return -1;
    }

  }
#else
  ret = SSL_CTX_load_verify_locations(ctx, ca_file_path, NULL);
  if (ret != 1) {
    fprintf(stderr, "OpenSSL error while loading CA\n");
    return -1;
  }
#endif

#ifdef SSL_FILES_EMBED
  ret = SSL_CTX_use_certificate(ctx, cert_file_mem);
#else
  ret = SSL_CTX_use_certificate_file(ctx, cert_file_path, SSL_FILETYPE_PEM);
#endif
  if (ret != 1) {
    fprintf(stderr, "OpenSSL error while parsing cert\n");
    return -1;
  }
#ifdef SSL_FILES_EMBED
  ret = SSL_CTX_use_RSAPrivateKey(ctx, private_key_file_mem);
#else
  ret = SSL_CTX_use_PrivateKey_file(ctx, private_key_path, SSL_FILETYPE_PEM);
#endif

  if (ret != 1) {
    fprintf(stderr, "OpenSSL error while parsing pkey\n");
    return -1;
  }
  if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr, "OpenSSL error no PKEY in CTX\n");
    return -1;
  }
  ssl = SSL_new(ctx);
  if (ssl == NULL) {
    fprintf(stderr, "OpenSSL error could not create SSL structure\n");
    return -1;
  }
  ret = SSL_set_fd(ssl, sock);

  if (ret != 1) {
    fprintf(stderr, "OpenSSL error attaching to socket\n");
    return -1;
  }

  ret = SSL_connect(ssl);
  if (ret != 1) {
    fprintf(stderr, "OpenSSL *** Handshake error\n");
    return -1;
  }

  /* Obtain the server certificate. */
  peercert = SSL_get_peer_certificate(ssl);
  if (peercert == NULL) {
    fprintf(stderr, "OpenSSL peer certificate missing");
    return -1;
  }

  /* Check the certificate verification result.
   * Could allow an explicit certificate validation override
   */
  verifystatus = SSL_get_verify_result(ssl);
  if (verifystatus != X509_V_OK) {
    fprintf(stderr, "SSL_connect: verify result: %s\n",
	    X509_verify_cert_error_string(verifystatus));
    return -1;
  }

#ifdef SSL_SERVER_FILES_EMBED
  /* We have to check the provided authorized server certificates */
  if(is_certificate_in_list(&peercert[0], server_file_buff, SERVER_CERTS_NB) == 0){
    fprintf(stderr, "SSL_connect error: peer server certificate is not in the allowed list!\n");
    return -1;
  }
#endif

  return 0;
}

int purge_openssl(void)
{
  if (ssl != NULL) {
    switch (SSL_shutdown(ssl)) {
    case 1:
      break;
    case 0:
      SSL_shutdown(ssl);
      break;
    case -1:
      fprintf(stderr, "Error while shutting down\n");
    }
    SSL_free(ssl);
  }
  if (ctx != NULL) {
    SSL_CTX_free(ctx);
  }
  return 0;
}
#else

/* Disable -Wpedantic locally to avoid the empty translation unit */
/* warning (which is indeed not ISO C compliant)                  */
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic pop
#endif

#endif
