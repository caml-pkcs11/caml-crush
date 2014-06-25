/*------------------------ CeCILL-B HEADER ------------------------------------
    Copyright ANSSI (2013)
    Contributors : Ryad BENADJILA [ryad.benadjila@ssi.gouv.fr] and
    Thomas CALDERON [thomas.calderon@ssi.gouv.fr]

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

    This software is governed by the CeCILL-B license under French law and
    abiding by the rules of distribution of free software.  You can  use,
    modify and/ or redistribute the software under the terms of the CeCILL-B
    license as circulated by CEA, CNRS and INRIA at the following URL
    "http://www.cecill.info".

    As a counterpart to the access to the source code and  rights to copy,
    modify and redistribute granted by the license, users are provided only
    with a limited warranty  and the software's author,  the holder of the
    economic rights,  and the successive licensors  have only  limited
    liability.

    In this respect, the user's attention is drawn to the risks associated
    with loading,  using,  modifying and/or developing or reproducing the
    software by the user in light of its specific status of free software,
    that may mean  that it is complicated to manipulate,  and  that  also
    therefore means  that it is reserved for developers  and  experienced
    professionals having in-depth computer knowledge. Users are therefore
    encouraged to load and test the software's suitability as regards their
    requirements in conditions enabling the security of their systems and/or
    data to be ensured and,  more generally, to use and operate it in the
    same conditions as regards security.

    The fact that you are presently reading this means that you have had
    knowledge of the CeCILL-B license and that you accept its terms.

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
    File:    src/client-lib/modwrap_crpc.c

-------------------------- CeCILL-B HEADER ----------------------------------*/
#include "modwrap.h"

/* ------------------------------*/
/* RPC C serialization functions */

void
deserialize_rpc_ck_version(struct ck_version *out, struct rpc_ck_version *in)
{
  memcpy(&(out->major), (in->major.major_val), in->major.major_len);
  memcpy(&(out->minor), (in->minor.minor_val), in->minor.minor_len);
  custom_free((void **)&in->major.major_val);
  custom_free((void **)&in->minor.minor_val);
  return;
}

void deserialize_rpc_ck_info(struct ck_info *out, struct rpc_ck_info *in)
{
  deserialize_rpc_ck_version(&(out->cryptoki_version),
			     &(in->rpc_ck_info_cryptoki_version));
  memcpy(out->manufacturer_id,
	 in->rpc_ck_info_manufacturer_id.rpc_ck_info_manufacturer_id_val,
	 in->rpc_ck_info_manufacturer_id.rpc_ck_info_manufacturer_id_len);
  out->flags = in->rpc_ck_info_flags;
  memcpy(out->library_description,
	 in->rpc_ck_info_library_description.
	 rpc_ck_info_library_description_val,
	 in->rpc_ck_info_library_description.
	 rpc_ck_info_library_description_len);
  deserialize_rpc_ck_version(&(out->library_version),
			     &(in->rpc_ck_info_library_version));
  custom_free((void **)&in->rpc_ck_info_manufacturer_id.
	      rpc_ck_info_manufacturer_id_val);
  custom_free((void **)&in->rpc_ck_info_library_description.
	      rpc_ck_info_library_description_val);
  return;
}

void
deserialize_rpc_ck_slot_info(struct ck_slot_info *out,
			     struct rpc_ck_slot_info *in)
{
  memcpy(out->slot_description,
	 in->rpc_ck_slot_info_slot_description.
	 rpc_ck_slot_info_slot_description_val,
	 in->rpc_ck_slot_info_slot_description.
	 rpc_ck_slot_info_slot_description_len);
  memcpy(out->manufacturer_id,
	 in->rpc_ck_slot_info_manufacturer_id.
	 rpc_ck_slot_info_manufacturer_id_val,
	 in->rpc_ck_slot_info_manufacturer_id.
	 rpc_ck_slot_info_manufacturer_id_len);
  out->flags = in->rpc_ck_slot_info_flags;
  deserialize_rpc_ck_version(&(out->hardware_version),
			     &(in->rpc_ck_slot_info_hardware_version));
  deserialize_rpc_ck_version(&(out->firmware_version),
			     &(in->rpc_ck_slot_info_firmware_version));
  custom_free((void **)&in->rpc_ck_slot_info_slot_description.
	      rpc_ck_slot_info_slot_description_val);
  custom_free((void **)&in->rpc_ck_slot_info_manufacturer_id.
	      rpc_ck_slot_info_manufacturer_id_val);
  return;
}

void
deserialize_rpc_ck_token_info(struct ck_token_info *out,
			      struct rpc_ck_token_info *in)
{
  memcpy(out->label, in->rpc_ck_token_info_label.rpc_ck_token_info_label_val,
	 in->rpc_ck_token_info_label.rpc_ck_token_info_label_len);
  memcpy(out->manufacturer_id,
	 in->rpc_ck_token_info_manufacturer_id.
	 rpc_ck_token_info_manufacturer_id_val,
	 in->rpc_ck_token_info_manufacturer_id.
	 rpc_ck_token_info_manufacturer_id_len);
  memcpy(out->model, in->rpc_ck_token_info_model.rpc_ck_token_info_model_val,
	 in->rpc_ck_token_info_model.rpc_ck_token_info_model_len);
  memcpy(out->serial_number,
	 in->rpc_ck_token_info_serial_number.
	 rpc_ck_token_info_serial_number_val,
	 in->rpc_ck_token_info_serial_number.
	 rpc_ck_token_info_serial_number_len);
  out->flags = in->rpc_ck_token_info_flags;
  out->max_session_count = in->rpc_ck_token_info_max_session_count;
  out->session_count = in->rpc_ck_token_info_session_count;
  out->max_rw_session_count = in->rpc_ck_token_info_max_rw_session_count;
  out->rw_session_count = in->rpc_ck_token_info_rw_session_count;
  out->max_pin_len = in->rpc_ck_token_info_max_pin_len;
  out->min_pin_len = in->rpc_ck_token_info_min_pin_len;
  out->total_public_memory = in->rpc_ck_token_info_total_public_memory;
  out->free_public_memory = in->rpc_ck_token_info_free_public_memory;
  out->total_private_memory = in->rpc_ck_token_info_total_private_memory;
  out->free_private_memory = in->rpc_ck_token_info_free_private_memory;
  deserialize_rpc_ck_version(&(out->hardware_version),
			     &(in->rpc_ck_token_info_hardware_version));
  deserialize_rpc_ck_version(&(out->firmware_version),
			     &(in->rpc_ck_token_info_firmware_version));
  memcpy(out->utc_time,
	 in->rpc_ck_token_info_utc_time.rpc_ck_token_info_utc_time_val,
	 in->rpc_ck_token_info_utc_time.rpc_ck_token_info_utc_time_len);
  custom_free((void **)&in->rpc_ck_token_info_label.
	      rpc_ck_token_info_label_val);
  custom_free((void **)&in->rpc_ck_token_info_manufacturer_id.
	      rpc_ck_token_info_manufacturer_id_val);
  custom_free((void **)&in->rpc_ck_token_info_model.
	      rpc_ck_token_info_model_val);
  custom_free((void **)&in->rpc_ck_token_info_serial_number.
	      rpc_ck_token_info_serial_number_val);
  custom_free((void **)&in->rpc_ck_token_info_utc_time.
	      rpc_ck_token_info_utc_time_val);
  return;
}

void
deserialize_rpc_ck_mechanism(struct ck_mechanism *out,
			     struct rpc_ck_mechanism *in)
{
  out->mechanism = in->rpc_ck_mechanism_mechanism;
  memcpy(out->parameter,
	 in->rpc_ck_mechanism_parameter.rpc_ck_mechanism_parameter_val,
	 in->rpc_ck_mechanism_parameter.rpc_ck_mechanism_parameter_len);
  custom_free((void **)&in->rpc_ck_mechanism_parameter.
	      rpc_ck_mechanism_parameter_val);
  return;
}

void
deserialize_rpc_ck_session_info(struct ck_session_info *out,
				struct rpc_ck_session_info *in)
{
  out->slot_id = in->rpc_ck_session_info_slot_id;
  out->state = in->rpc_ck_session_info_state;
  out->flags = in->rpc_ck_session_info_flags;
  out->device_error = in->rpc_ck_session_info_device_error;
  return;
}

void
deserialize_rpc_ck_mechanism_info(struct ck_mechanism_info *out,
				  struct rpc_ck_mechanism_info *in)
{
  out->min_key_size = in->rpc_ck_mechanism_info_min_key_size;
  out->max_key_size = in->rpc_ck_mechanism_info_max_key_size;
  out->flags = in->rpc_ck_mechanism_info_flags;
  return;
}

void
deserialize_rpc_ck_attribute(struct ck_attribute *out,
			     struct rpc_ck_attribute *in, ck_rv_t ret)
{
  out->type_ = in->rpc_ck_attribute_type;

  out->value_len = in->rpc_ck_attribute_value_len;
  if (out->value_len != 0) {
    /* We must first check that the value is not NULL while
       the length is */
    if (out->value == NULL) {
      /* Return an error if this is the case ... */
      custom_free((void **)&in->rpc_ck_attribute_value.
		  rpc_ck_attribute_value_val);
      return;
    }
    memcpy(out->value,
	   in->rpc_ck_attribute_value.rpc_ck_attribute_value_val,
	   in->rpc_ck_attribute_value.rpc_ck_attribute_value_len);
  }
  /* Carry the ret value to update UlValueLen to be passed -1 on errors */
  else {
    if (ret != CKR_OK) {
      out->value_len = -1;
    }
  }
  custom_free((void **)&in->rpc_ck_attribute_value.rpc_ck_attribute_value_val);
  return;
}

void
deserialize_rpc_ck_attribute_array(struct ck_attribute *out,
				   rpc_ck_attribute_array * in, ck_rv_t ret)
{
  unsigned int i;
  for (i = 0; i < in->rpc_ck_attribute_array_len; i++) {
    deserialize_rpc_ck_attribute(&(out[i]),
				 &(in->rpc_ck_attribute_array_val[i]), ret);
  }
  custom_free((void **)&in->rpc_ck_attribute_array_val);
  return;
}

void deserialize_rpc_ck_date(struct ck_date *out, struct rpc_ck_date *in)
{
  memcpy(out->year, in->rpc_ck_date_year.rpc_ck_date_year_val,
	 in->rpc_ck_date_year.rpc_ck_date_year_len);
  memcpy(out->month, in->rpc_ck_date_month.rpc_ck_date_month_val,
	 in->rpc_ck_date_month.rpc_ck_date_month_len);
  memcpy(out->day, in->rpc_ck_date_day.rpc_ck_date_day_val,
	 in->rpc_ck_date_day.rpc_ck_date_day_len);
  custom_free((void **)&in->rpc_ck_date_year.rpc_ck_date_year_val);
  custom_free((void **)&in->rpc_ck_date_month.rpc_ck_date_month_val);
  custom_free((void **)&in->rpc_ck_date_day.rpc_ck_date_day_val);
  return;
}

void
serialize_rpc_ck_attribute(struct ck_attribute *in,
			   struct rpc_ck_attribute *out)
{
  out->rpc_ck_attribute_type = in->type_;
  out->rpc_ck_attribute_value_len = in->value_len;
  if ((in->value != NULL) && ((int)in->value_len >= 0)) {
    out->rpc_ck_attribute_value.rpc_ck_attribute_value_len = in->value_len;
    out->rpc_ck_attribute_value.rpc_ck_attribute_value_val =
	custom_malloc(sizeof(char) * in->value_len);
    memcpy(out->rpc_ck_attribute_value.rpc_ck_attribute_value_val,
	   in->value, in->value_len);
  } else {
    out->rpc_ck_attribute_value.rpc_ck_attribute_value_len = 0;
    out->rpc_ck_attribute_value.rpc_ck_attribute_value_val = NULL;
  }
  return;
}

void free_rpc_ck_attribute(rpc_ck_attribute * in)
{
  if (in->rpc_ck_attribute_value.rpc_ck_attribute_value_val != NULL) {
    custom_free((void **)
		&(in->rpc_ck_attribute_value.rpc_ck_attribute_value_val));
  }
  return;
}

void
serialize_rpc_ck_attribute_array(struct ck_attribute *in,
				 unsigned long in_len,
				 rpc_ck_attribute_array * out)
{
  unsigned int i;
  out->rpc_ck_attribute_array_len = in_len;
  out->rpc_ck_attribute_array_val =
      custom_malloc(sizeof(rpc_ck_attribute) * in_len);
  for (i = 0; i < in_len; i++) {
    serialize_rpc_ck_attribute(&(in[i]), &(out->rpc_ck_attribute_array_val[i]));
  }
  return;
}

void free_rpc_ck_attribute_array(rpc_ck_attribute_array * in)
{
  unsigned int i;
  for (i = 0; i < in->rpc_ck_attribute_array_len; i++) {
    free_rpc_ck_attribute(&(in->rpc_ck_attribute_array_val[i]));
  }
  if (in->rpc_ck_attribute_array_val != NULL) {
    custom_free((void **)&(in->rpc_ck_attribute_array_val));
  }
  return;
}

void
serialize_rpc_ck_mechanism(struct ck_mechanism *in,
			   struct rpc_ck_mechanism *out)
{
  out->rpc_ck_mechanism_mechanism = in->mechanism;
  out->rpc_ck_mechanism_parameter.rpc_ck_mechanism_parameter_len =
      in->parameter_len;
  out->rpc_ck_mechanism_parameter.rpc_ck_mechanism_parameter_val =
      custom_malloc(sizeof(char) * in->parameter_len);
  memcpy(out->rpc_ck_mechanism_parameter.rpc_ck_mechanism_parameter_val,
	 in->parameter, in->parameter_len);
  return;
}

void free_rpc_ck_mechanism(rpc_ck_mechanism * in)
{
  custom_free((void **)
	      &(in->rpc_ck_mechanism_parameter.rpc_ck_mechanism_parameter_val));
  return;
}

/* ------------------------------*/
/*    RPC C PKCS#11 functions    */
CLIENT *cl = NULL;

/* TCP socket type */
#ifdef TCP_SOCKET

void parse_socket_path(const char *socket_path, struct sockaddr_in *serv_addr)
{
  struct hostent *hp;
  char *token = NULL;
  char *copy;
  int i = 0;
  int port = 0;
#ifdef WIN32
  WSADATA wsaData;
  /* Initialize Winsock, version 2.2 */
  int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (iResult != 0) {
    fprintf(stderr, "WSAStartup failed: %d\n", iResult);
    WSACleanup();
    exit(-1);
  }
#endif

  /* copy input string */
  copy = custom_malloc(strnlen(socket_path, MAX_HOSTNAME_LEN) + 1);
  memset(copy, 0, strnlen(socket_path, MAX_HOSTNAME_LEN) + 1);
  strncpy(copy, socket_path, strnlen(socket_path, MAX_HOSTNAME_LEN));

  token = strtok(copy, ":");

  while (token != NULL) {
    if (i == 0) {
      if ((hp = gethostbyname(token)) == NULL) {
	fprintf(stderr, "error: can't get addr for %s\n", token);
	if (copy != NULL) {
	  custom_free((void **)&(copy));
	}
#ifdef WIN32
    WSACleanup();
#endif
	exit(-1);
      }
      /* copy the resulting host entry in socket */
      bcopy(hp->h_addr, (caddr_t) & serv_addr->sin_addr, hp->h_length);
    }
    if (i == 1) {
      /* copy the resulting host entry in socket */
      /* We cast with an unsigned short to be bound 0-65535 */
      port = (unsigned short)atoi(token);
      if (port == 0) {
	fprintf(stderr, "error: can't get port for %s\n", token);
	if (copy != NULL) {
	  custom_free((void **)&(copy));
	}
#ifdef WIN32
    WSACleanup();
#endif
	exit(-1);
      }
      serv_addr->sin_port = htons(port);
    }
    if (i > 1) {
      /* should not be here */
      fprintf(stderr, "error: can't parse socket_addr given: %s\n",
	      socket_path);
      if (copy != NULL) {
	custom_free((void **)&(copy));
      }
#ifdef WIN32
    WSACleanup();
#endif
      exit(-1);
    }
    token = strtok(NULL, ":");
    i++;
  }
  serv_addr->sin_family = AF_INET;
  if (copy != NULL) {
    custom_free((void **)&(copy));
  }
#ifdef WIN32
  if(WSACleanup()){
    fprintf(stderr, "error: WSACleanup failed %d\n", WSAGetLastError());
  }
#endif
  return;
}
#endif

ck_rv_t init_c(const char *module)
{
  ck_rv_t ret;
  /* Define RPC timeout */
  struct timeval timeout;
  /* path to socket */
  char *env_socket_path;
  /* environment variable to override default RPC timeout */
  char *env_timeout_override;
  long int timeout_value;

  /* Call C LoadModule */
  int rpc_sock = RPC_ANYSOCK;
#ifdef UNIX_SOCKET
  struct sockaddr_un *serv_addr;
  serv_addr = custom_malloc(sizeof(struct sockaddr_un));
  serv_addr->sun_family = AF_UNIX;
#ifdef FreeBSD
  /* FreeBSD sockaddr_un structure needs a sun_len */
  serv_addr->sun_len = SUN_LEN(serv_addr);
#endif
#elif TCP_SOCKET
  struct sockaddr_in serv_addr;
#endif
  /* try to find user-defined path to socket */
  env_socket_path = getenv(ENV_SOCKET_PATH_NAME);

  if (env_socket_path != NULL) {
#ifdef UNIX_SOCKET
    strncpy(serv_addr->sun_path, env_socket_path,
	    (sizeof(serv_addr->sun_path) - 1));
#elif TCP_SOCKET
    parse_socket_path(env_socket_path, &serv_addr);
#endif
  } else {
#ifdef UNIX_SOCKET
    strncpy(serv_addr->sun_path, xstr(SOCKET_PATH),
	    (sizeof(serv_addr->sun_path) - 1));
#elif TCP_SOCKET
    parse_socket_path(xstr(SOCKET_PATH), &serv_addr);
#endif
  }

#ifdef UNIX_SOCKET
  cl = clntunix_create(serv_addr, P, V, &rpc_sock, 0, 0);
#ifndef FreeBSD
  /* We have to free the pointer, FreeBSD does it in its libc ... */
  custom_free((void **)&(serv_addr));
#endif
#elif TCP_SOCKET
#ifdef WIN32
  /* This init call initialize Windows sockets */
  if(rpc_nt_init() != 0){
    fprintf(stderr, "error: could not initialize Windows sockets.\n");
  }
#endif
  cl = clnttcp_create(&serv_addr, P, V, &rpc_sock, 0, 0);
#endif

  /* Check RPC status */
  if (cl == NULL) {
    fprintf(stderr, "error: could not connect to server.\n");
    return CKR_GENERAL_ERROR;
  }

#ifdef WITH_SSL
  override_net_functions(cl);
#ifdef GNU_TLS
  ret = start_gnutls(rpc_sock);
#else
  ret = start_openssl(rpc_sock);
#endif
  if (ret != 0) {
#ifdef GNU_TLS
    fprintf(stderr, "GNUTLS Error\n");
#else
    fprintf(stderr, "OpenSSL Error\n");
#endif
	/* This is brutal but an SSL error seems worrying enough to exit()*/
    exit(-1);
  }
#endif				/* END WITH_SSL */

  /* Initialize Architecture */
  ret = myC_SetupArch_C();
  switch (ret) {
  case LITTLE_ENDIAN_64:
  case LITTLE_ENDIAN_32:
  case BIG_ENDIAN_64:
  case BIG_ENDIAN_32:
    peer_arch = ret;
    break;
  default:
    fprintf(stderr, "Unsupported architecture error EXITING\n");
    return UNSUPPORTED_ARCHITECTURE;
  }

  /* Control timeout setting */
  env_timeout_override = getenv(ENV_RPC_TIMEOUT);

  timeout.tv_sec = RPC_DEFAULT_TIMEOUT;
  timeout.tv_usec = 0;

  if (env_timeout_override != NULL) {
    timeout_value = atol(env_timeout_override);
    /* basic check, we do not want a zero timeout */
    if(timeout_value != 0){
      timeout.tv_sec = timeout_value;
    }
  }

  clnt_control(cl, CLSET_TIMEOUT, (char *)&timeout);

  ret = myC_LoadModule_C(module);
  return ret;
}

void destroy_c()
{
  if (cl != NULL) {
#if defined(WITH_SSL) && defined(GNU_TLS)
#ifdef DEBUG
    fprintf(stderr, "GNUTLS purge\n");
#endif
    purge_gnutls();
#endif
#if defined(WITH_SSL) && !defined(GNU_TLS)
#ifdef DEBUG
    fprintf(stderr, "OpenSSL purge\n");
#endif
    purge_openssl();
#endif
    clnt_destroy(cl);
  }
#ifdef WIN32
  /* This allow the Windows socket to be properly closed */
  if(rpc_nt_exit() != 0){
    fprintf(stderr, "error: could not cleanup WSA context\n");
  }
#endif
  return;
}

ck_rv_t myC_SetupArch_C(void)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  ck_rv_t rv;

  unsigned int test = 0xAABBCCDD;

  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_SetupArch calling\n");
#endif
  /* Check status of RPC
   * redundant as when RPC failed, code should not be reached.
   * We keep it to stay coherent.
   */
  check_rpc_status(C_SetupArch)

  if (((unsigned char *)&test)[0] == 0xDD) {
    /* LittleEndian */
    if (sizeof(long) == 8) {
      /* 64bit */
      my_arch = LITTLE_ENDIAN_64;
    } else {
      my_arch = LITTLE_ENDIAN_32;
    }
  } else {
    /* BigEndian */
    if (sizeof(long) == 8) {
      /* 64bit */
      my_arch = BIG_ENDIAN_64;
    } else {
      my_arch = BIG_ENDIAN_32;
    }
  }

#ifdef RPCGEN_MT
  retval = c_setuparch_3(my_arch, &ret, cl);
#else
  pret = c_setuparch_3(my_arch, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_SetupArch\n");
    rv = -1;
    return rv;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif
  rv = ret;

  return rv;
}

ck_rv_t myC_LoadModule_C(const char *libname)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  ck_rv_t rv;
  opaque_data module;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret

  /* Check status of RPC */
  check_rpc_status(C_Initialize)

  /* libnames are defined at compile time, so no need to check its length */
  module.opaque_data_len = strlen(libname);
  module.opaque_data_val = (char *)libname;

#ifdef DEBUG
  fprintf(stderr, "C_LoadModule calling for module %s to be loaded\n", libname);
#endif

#ifdef RPCGEN_MT
  retval = c_loadmodule_3(module, &ret, cl);
#else
  pret = c_loadmodule_3(module, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_LoadModule\n");
    rv = -1;
    return rv;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif
  rv = ret;

  return rv;
}

ck_rv_t myC_Initialize_C(void *init_args)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_Initialize calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_Initialize)

  /* Check for pInitArgs PTR presence */
  if (init_args != NULL) {
#ifdef DEBUG
    fprintf(stderr, "C_Initialize *pInitArgs not NULL, we won't use them\n");
#endif
  }
#ifdef RPCGEN_MT
  retval = c_initialize_3(&ret, cl);
#else
  pret = c_initialize_3(cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_Initialize\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t myC_Finalize_C(void *init_args)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_Finalize calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_Finalize)

  /* P11 Compliance */
  if (init_args != NULL) {
    return CKR_ARGUMENTS_BAD;
  }
#ifdef RPCGEN_MT
  retval = c_finalize_3(&ret, cl);
#else
  pret = c_finalize_3(cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_Finalize\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif
  return ret;
}

ck_rv_t myC_GetInfo_C(struct ck_info * output0)
{
#ifdef RPCGEN_MT
  ck_rv_c_GetInfo ret;
  enum clnt_stat retval;
#else
  ck_rv_c_GetInfo *pret = NULL;
  ck_rv_c_GetInfo ret;
#endif
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_GetInfo calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_GetInfo)
  if (output0 == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
#ifdef RPCGEN_MT
  retval = c_getinfo_3(&ret, cl);
#else
  pret = c_getinfo_3(cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_GetInfo\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif
  deserialize_rpc_ck_info(output0, &(ret.c_GetInfo_info));

  return ret.c_GetInfo_rv;
}

ck_rv_t
myC_GetSlotList_C(CK_BBOOL input0, ck_slot_id_t * output2,
		  unsigned long *output3)
{
#ifdef RPCGEN_MT
  ck_rv_c_GetSlotList ret;
  enum clnt_stat retval;
#else
  ck_rv_c_GetSlotList *pret = NULL;
  ck_rv_c_GetSlotList ret;
#endif
  pkcs11_int token_present;
  pkcs11_int count;
  unsigned int i;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_GetSlotList calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_GetSlotList)

  /* P11 compliant */
  if (output3 == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
  if (input0 == 1) {
    /* CK_TRUE */
    token_present = 1;
  } else {
    token_present = 0;
  }
  if (output2 == NULL) {
    count = 0;
  } else {
    count = *output3;
  }
#ifdef RPCGEN_MT
  retval = c_getslotlist_3(token_present, count, &ret, cl);
#else
  pret = c_getslotlist_3(token_present, count, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_GetSlotList\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  *output3 = ret.c_GetSlotList_count;
  /* Copy back only if *output2 is not NULL */
  if (output2 != NULL) {
    for (i = 0; i < *output3; i++) {
      output2[i] = ret.c_GetSlotList_slot_list.c_GetSlotList_slot_list_val[i];
    }
  }
  custom_free((void **)&ret.c_GetSlotList_slot_list.
	      c_GetSlotList_slot_list_val);
  return ret.c_GetSlotList_rv;
}

ck_rv_t myC_GetSlotInfo_C(ck_slot_id_t input0, struct ck_slot_info * output1)
{
#ifdef RPCGEN_MT
  ck_rv_c_GetSlotInfo ret;
  enum clnt_stat retval;
#else
  ck_rv_c_GetSlotInfo *pret = NULL;
  ck_rv_c_GetSlotInfo ret;
#endif
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_GetSlotInfo calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_GetSlotInfo)

  /* P11 compliant */
  if (output1 == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
#ifdef RPCGEN_MT
  retval = c_getslotinfo_3(input0, &ret, cl);
#else
  pret = c_getslotinfo_3(input0, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_GetSlotInfo\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  deserialize_rpc_ck_slot_info(output1, &(ret.c_GetSlotInfo_slot_info));
  return ret.c_GetSlotInfo_rv;
}

ck_rv_t myC_GetTokenInfo_C(ck_slot_id_t input0, struct ck_token_info * output1)
{
#ifdef RPCGEN_MT
  ck_rv_c_GetTokenInfo ret;
  enum clnt_stat retval;
#else
  ck_rv_c_GetTokenInfo *pret = NULL;
  ck_rv_c_GetTokenInfo ret;
#endif
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_GetTokenInfo calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_GetTokenInfo)

  /* P11 compliant */
  if (output1 == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
#ifdef RPCGEN_MT
  retval = c_gettokeninfo_3(input0, &ret, cl);
#else
  pret = c_gettokeninfo_3(input0, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_GetTokenInfo\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  deserialize_rpc_ck_token_info(output1, &(ret.c_GetTokenInfo_token_info));
  return ret.c_GetTokenInfo_rv;
}

ck_rv_t
myC_GetMechanismList_C(ck_slot_id_t input0, ck_mechanism_type_t * output2,
		       unsigned long *output3)
{
#ifdef RPCGEN_MT
  ck_rv_c_GetMechanismList ret;
  enum clnt_stat retval;
#else
  ck_rv_c_GetMechanismList *pret = NULL;
  ck_rv_c_GetMechanismList ret;
#endif
  pkcs11_int count;
  unsigned int i;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_GetMechanismList calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_GetMechanismList)
  /* P11 compliant */
  if (output3 == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  if (output2 == NULL) {
    count = 0;
  } else {
    count = *output3;
  }
#ifdef RPCGEN_MT
  retval = c_getmechanismlist_3(input0, count, &ret, cl);
#else
  pret = c_getmechanismlist_3(input0, count, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_GetMechanismList\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif
  /* TODO: explain P11 compliance algorithm */
  if (ret.c_GetMechanismList_rv == CKR_BUFFER_TOO_SMALL) {
    *output3 = ret.c_GetMechanismList_count;
    custom_free((void **)&ret.c_GetMechanismList_list.
		c_GetMechanismList_list_val);
    return ret.c_GetMechanismList_rv;
  } else if (ret.c_GetMechanismList_rv != CKR_OK) {
    custom_free((void **)&ret.c_GetMechanismList_list.
		c_GetMechanismList_list_val);
    return ret.c_GetMechanismList_rv;
  }

  /* P11 compliant */
  /* FIXME: For now cast to (unsigned long) because we should not recieve a huge mech_count */
  if ((output2 != NULL && *output3 == 0)
      || (*output3 < (unsigned long)ret.c_GetMechanismList_count)) {
    *output3 = ret.c_GetMechanismList_count;
    if (output2 == NULL) {
      custom_free((void **)&ret.c_GetMechanismList_list.
		  c_GetMechanismList_list_val);
      return ret.c_GetMechanismList_rv;
    }
    custom_free((void **)&ret.c_GetMechanismList_list.
		c_GetMechanismList_list_val);
    return CKR_BUFFER_TOO_SMALL;
  }

  *output3 = ret.c_GetMechanismList_count;
  if (output2 != NULL) {
    for (i = 0; i < *output3; i++) {
      output2[i] = ret.c_GetMechanismList_list.c_GetMechanismList_list_val[i];
    }
  }
  custom_free((void **)&ret.c_GetMechanismList_list.
	      c_GetMechanismList_list_val);
  return ret.c_GetMechanismList_rv;
}

ck_rv_t
myC_GetMechanismInfo_C(ck_slot_id_t input0, ck_mechanism_type_t input1,
		       struct ck_mechanism_info * output2)
{
#ifdef RPCGEN_MT
  ck_rv_c_GetMechanismInfo ret;
  enum clnt_stat retval;
#else
  ck_rv_c_GetMechanismInfo *pret = NULL;
  ck_rv_c_GetMechanismInfo ret;
#endif
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_GetMechanismInfo calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_GetMechanismInfo)
  /* P11 compliant */
  if (output2 == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
#ifdef RPCGEN_MT
  retval = c_getmechanisminfo_3(input0, input1, &ret, cl);
#else
  pret = c_getmechanisminfo_3(input0, input1, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_GetMechanismInfo\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  deserialize_rpc_ck_mechanism_info(output2, &(ret.c_GetMechanismInfo_info));
  return ret.c_GetMechanismInfo_rv;
}

ck_rv_t
myC_OpenSession_C(ck_slot_id_t input0, ck_flags_t input1, void *application,
		  ck_notify_t notify, ck_session_handle_t * output2)
{
#ifdef RPCGEN_MT
  ck_rv_c_OpenSession ret;
  enum clnt_stat retval;
#else
  ck_rv_c_OpenSession *pret = NULL;
  ck_rv_c_OpenSession ret;
#endif
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_OpenSession calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_OpenSession)
  /* P11 compliant */
  if (output2 == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
  /* Check for application/notify PTR presence */
  if ((application != NULL) || (notify != NULL)) {
#ifdef DEBUG
    fprintf(stderr,
	    "C_OpenSession *application/*notify not NULL, we won't pass them\n");
#endif
  }
#ifdef RPCGEN_MT
  retval = c_opensession_3(input0, input1, &ret, cl);
#else
  pret = c_opensession_3(input0, input1, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_OpenSession\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  *output2 = ret.c_OpenSession_handle;

  return ret.c_OpenSession_rv;
}

ck_rv_t myC_CloseSession_C(ck_session_handle_t input0)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_CloseSession calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_CloseSession)
#ifdef RPCGEN_MT
  retval = c_closesession_3(input0, &ret, cl);
#else
  pret = c_closesession_3(input0, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_CloseSession\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t myC_CloseAllSessions_C(ck_slot_id_t input0)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_CloseAllSessions calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_CloseAllSessions)
#ifdef RPCGEN_MT
  retval = c_closeallsessions_3(input0, &ret, cl);
#else
  pret = c_closeallsessions_3(input0, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_CloseAllSessions\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t
myC_GetSessionInfo_C(ck_session_handle_t input0,
		     struct ck_session_info * output1)
{
#ifdef RPCGEN_MT
  ck_rv_c_GetSessionInfo ret;
  enum clnt_stat retval;
#else
  ck_rv_c_GetSessionInfo *pret = NULL;
  ck_rv_c_GetSessionInfo ret;
#endif
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_GetSessionInfo calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_GetSessionInfo)
  /* P11 compliant */
  if (output1 == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
#ifdef RPCGEN_MT
  retval = c_getsessioninfo_3(input0, &ret, cl);
#else
  pret = c_getsessioninfo_3(input0, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_GetSessionInfo\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  deserialize_rpc_ck_session_info(output1, &(ret.c_GetSessionInfo_info));
  return ret.c_GetSessionInfo_rv;
}

ck_rv_t
myC_FindObjectsInit_C(ck_session_handle_t input0, CK_ATTRIBUTE * input1,
		      unsigned long count)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  rpc_ck_attribute_array attributes;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_FindObjectsInit calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_FindObjectsInit)
  /* P11 compliant */
  if (input1 == NULL && count > 0) {
    return CKR_ARGUMENTS_BAD;
  }

  /* If count is NULL, we pass an empty list to CAML */
  if (count == 0) {
    attributes.rpc_ck_attribute_array_len = 0;
    attributes.rpc_ck_attribute_array_val = NULL;
  } else {
    serialize_rpc_ck_attribute_array(input1, count, &attributes);
  }
#ifdef RPCGEN_MT
  retval = c_findobjectsinit_3(input0, attributes, &ret, cl);
#else
  pret = c_findobjectsinit_3(input0, attributes, cl);
#endif
  if (count != 0) {
    free_rpc_ck_attribute_array(&attributes);
  }

  assert_rpc {
    fprintf(stderr, "Error RPC with C_FindObjectsInit\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t
myC_FindObjects_C(ck_session_handle_t input0, ck_object_handle_t * output2,
		  unsigned long input1, unsigned long *output3)
{
#ifdef RPCGEN_MT
  ck_rv_c_FindObjects ret;
  enum clnt_stat retval;
#else
  ck_rv_c_FindObjects *pret = NULL;
  ck_rv_c_FindObjects ret;
#endif
  unsigned int i;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_FindObjects calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_FindObjects)

#ifdef RPCGEN_MT
  retval = c_findobjects_3(input0, input1, &ret, cl);
#else
  pret = c_findobjects_3(input0, input1, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_FindObjects\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  /* P11 compliant, return RET if was called with invalid session */
  if (ret.c_FindObjects_rv != CKR_OK) {
    custom_free((void **)&ret.c_FindObjects_objects.c_FindObjects_objects_val);
    return ret.c_FindObjects_rv;
  }

  /* P11 compliant */
  /* TODO: We avoid all possible NULL_PTR dereference, but is it compliant? */
  if (output2 == NULL || output3 == NULL) {
    custom_free((void **)&ret.c_FindObjects_objects.c_FindObjects_objects_val);
    return CKR_ARGUMENTS_BAD;
  }

  *output3 = ret.c_FindObjects_count;
  for (i = 0; i < *output3; i++) {
    output2[i] = ret.c_FindObjects_objects.c_FindObjects_objects_val[i];
  }
  custom_free((void **)&ret.c_FindObjects_objects.c_FindObjects_objects_val);
  return ret.c_FindObjects_rv;
}

ck_rv_t myC_FindObjectsFinal_C(ck_session_handle_t input0)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_FindObjectsFinal calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_FindObjectsFinal)
#ifdef RPCGEN_MT
  retval = c_findobjectsfinal_3(input0, &ret, cl);
#else
  pret = c_findobjectsfinal_3(input0, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_FindObjectsFinal\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif
  return ret;
}

ck_rv_t
myC_InitToken_C(ck_slot_id_t input0, unsigned char *input1,
		unsigned long input1_len, unsigned char *input2)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  opaque_data sopin;
  opaque_data label;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
      /* Sanitize: Check if input1 is NULL: if so, force the length to be zero */
      if ((char *)input1 == NULL) {
    sopin.opaque_data_len = 0;
  } else {
    sopin.opaque_data_len = input1_len;
  }
  sopin.opaque_data_val = (char *)input1;
  /* Fixing label_len to 32 as stated by the standard */
  label.opaque_data_len = 32;
  label.opaque_data_val = (char *)input2;

#ifdef DEBUG
  fprintf(stderr, "C_InitToken calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_InitToken)
#ifdef RPCGEN_MT
  retval = c_inittoken_3(input0, sopin, label, &ret, cl);
#else
  pret = c_inittoken_3(input0, sopin, label, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_InitToken\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif
  return ret;
}

ck_rv_t
myC_Login_C(ck_session_handle_t input0, ck_user_type_t input1,
	    unsigned char *input2, unsigned long input2_len)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  opaque_data pin;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret pin.opaque_data_len = input2_len;
  pin.opaque_data_val = (char *)input2;

#ifdef DEBUG
  fprintf(stderr, "C_Login calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_Login)
#ifdef RPCGEN_MT
  retval = c_login_3(input0, input1, pin, &ret, cl);
#else
  pret = c_login_3(input0, input1, pin, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_Login\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif
  return ret;
}

ck_rv_t myC_Logout_C(ck_session_handle_t input0)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_Logout calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_Logout)
#ifdef RPCGEN_MT
  retval = c_logout_3(input0, &ret, cl);
#else
  pret = c_logout_3(input0, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_Logout\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif
  return ret;
}

ck_rv_t
myC_InitPIN_C(ck_session_handle_t input0, unsigned char *input1,
	      unsigned long input1_len)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  opaque_data pin;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
      /* Sanitize: Check if input1 is NULL: if so, force the length to be zero */
      if ((char *)input1 == NULL) {
    pin.opaque_data_len = 0;
  } else {
    pin.opaque_data_len = input1_len;
  }
  pin.opaque_data_val = (char *)input1;

#ifdef DEBUG
  fprintf(stderr, "C_InitPIN calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_InitPIN)
#ifdef RPCGEN_MT
  retval = c_initpin_3(input0, pin, &ret, cl);
#else
  pret = c_initpin_3(input0, pin, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_InitPIN\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif
  return ret;
}

ck_rv_t
myC_SetPIN_C(ck_session_handle_t input0, unsigned char *input1,
	     unsigned long input1_len, unsigned char *input2,
	     unsigned long input2_len)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  opaque_data oldpin;
  opaque_data newpin;

  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
      /* Sanitize: Check if input1 is NULL: if so, force the length to be zero */
      if ((char *)input1 == NULL) {
    oldpin.opaque_data_len = 0;
  } else {
    oldpin.opaque_data_len = input1_len;
  }
  oldpin.opaque_data_val = (char *)input1;
  /* Sanitize: Check if input1 is NULL: if so, force the length to be zero */
  if ((char *)input2 == NULL) {
    newpin.opaque_data_len = 0;
  } else {
    newpin.opaque_data_len = input2_len;
  }
  newpin.opaque_data_val = (char *)input2;

#ifdef DEBUG
  fprintf(stderr, "C_SetPIN calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_SetPIN)
#ifdef RPCGEN_MT
  retval = c_setpin_3(input0, oldpin, newpin, &ret, cl);
#else
  pret = c_setpin_3(input0, oldpin, newpin, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_SetPIN\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif
  return ret;
}

ck_rv_t
myC_GetAttributeValue_C(ck_session_handle_t input0,
			ck_object_handle_t input1,
			struct ck_attribute * input2, unsigned long input3)
{
#ifdef RPCGEN_MT
  ck_rv_c_GetAttributeValue ret;
  enum clnt_stat retval;
#else
  ck_rv_c_GetAttributeValue *pret = NULL;
  ck_rv_c_GetAttributeValue ret;
#endif
  rpc_ck_attribute_array attributes;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_GetAttributeValue calling, size templ: %lu\n", input3);
#endif
  if (input2 == NULL) {
    return CKR_ARGUMENTS_BAD;
  } else {
    serialize_rpc_ck_attribute_array(input2, input3, &attributes);
  }

#ifdef RPCGEN_MT
  retval = c_getattributevalue_3(input0, input1, attributes, &ret, cl);
#else
  pret = c_getattributevalue_3(input0, input1, attributes, cl);
#endif
  free_rpc_ck_attribute_array(&attributes);
  assert_rpc {
    fprintf(stderr, "Error RPC with C_GetAttributeValue\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif
  deserialize_rpc_ck_attribute_array(input2,
				     &(ret.c_GetAttributeValue_value),
				     ret.c_GetAttributeValue_rv);

  return ret.c_GetAttributeValue_rv;
}

ck_rv_t
myC_DigestInit_C(ck_session_handle_t input0, struct ck_mechanism * input1)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  rpc_ck_mechanism mechanism;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_DigestInit calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_DigestInit)
  custom_sanitize_ck_mechanism(input1);

  /* Check to make sure we cannot initialize before fetching the result
   * of a previous crypto call
   */
  if (check_operation_active_in_filtering_list(input0, DIGEST_OP) != NULL) {
    return CKR_OPERATION_ACTIVE;
  }

  serialize_rpc_ck_mechanism(input1, &mechanism);

#ifdef RPCGEN_MT
  retval = c_digestinit_3(input0, mechanism, &ret, cl);
#else
  pret = c_digestinit_3(input0, mechanism, cl);
#endif
  free_rpc_ck_mechanism(&mechanism);

  assert_rpc {
    fprintf(stderr, "Error RPC with C_DigestInit\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t
myC_Digest_C(ck_session_handle_t input0, unsigned char *input1,
	     unsigned long input1_len, unsigned char *output2,
	     unsigned long *output2_len)
{
#ifdef RPCGEN_MT
  ck_rv_c_Digest ret;
  enum clnt_stat retval;
#else
  ck_rv_c_Digest *pret = NULL;
  ck_rv_c_Digest ret;
#endif
  opaque_data data;
  /* Remember previous calls */
  p11_request_struct *elem;

  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
      /* Avoid potential NULL_PTR dereference */
      if (output2_len == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
#ifdef DEBUG
  fprintf(stderr, "C_Digest calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_Digest)

  data.opaque_data_len = input1_len;
  data.opaque_data_val = (char *)input1;

  /* Remember previous calls */
  check_linked_list("Digest", DIGEST_OP, input0, input1, input1_len, output2,
		    output2_len);
#ifdef RPCGEN_MT
  retval = c_digest_3(input0, data, &ret, cl);
#else
  pret = c_digest_3(input0, data, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_Digest\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  handle_linked_list(Digest, DIGEST_OP, input0, input1, input1_len, output2,
		     output2_len);
}

ck_rv_t
myC_DigestUpdate_C(ck_session_handle_t input0, unsigned char *input1,
		   unsigned long input1_len)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  opaque_data data;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_DigestUpdate calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_DigestUpdate)

  data.opaque_data_len = input1_len;
  data.opaque_data_val = (char *)input1;

#ifdef RPCGEN_MT
  retval = c_digestupdate_3(input0, data, &ret, cl);
#else
  pret = c_digestupdate_3(input0, data, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_DigestUpdate\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t
myC_DigestFinal_C(ck_session_handle_t input0, unsigned char *output1,
		  unsigned long *output1_len)
{
#ifdef RPCGEN_MT
  ck_rv_c_DigestFinal ret;
  enum clnt_stat retval;
#else
  ck_rv_c_DigestFinal *pret = NULL;
  ck_rv_c_DigestFinal ret;
#endif
  p11_request_struct *elem;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_DigestFinal calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_DigestFinal)

  /* Avoid potential NULL_PTR dereference */
  if (output1_len == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  /* Remember previous calls */
  check_linked_list("DigestFinal", DIGEST_FINAL_OP, input0, NULL, 0, output1,
		    output1_len);

#ifdef RPCGEN_MT
  retval = c_digestfinal_3(input0, &ret, cl);
#else
  pret = c_digestfinal_3(input0, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_DigestFinal\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  handle_linked_list(DigestFinal, DIGEST_FINAL_OP, input0, NULL, 0, output1,
		     output1_len);
}

ck_rv_t myC_DigestKey_C(ck_session_handle_t input0, ck_object_handle_t input1)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_DigestKey calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_DigestKey)

#ifdef RPCGEN_MT
  retval = c_digestkey_3(input0, input1, &ret, cl);
#else
  pret = c_digestkey_3(input0, input1, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_DigestKey\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t
myC_SeedRandom_C(ck_session_handle_t input0, unsigned char *input1,
		 unsigned long input1_len)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  opaque_data data;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_SeedRandom calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_SeedRandom)

  data.opaque_data_len = input1_len;
  data.opaque_data_val = (char *)input1;

#ifdef RPCGEN_MT
  retval = c_seedrandom_3(input0, data, &ret, cl);
#else
  pret = c_seedrandom_3(input0, data, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_SeedRandom\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t
myC_GenerateRandom_C(ck_session_handle_t input0, unsigned char *output2,
		     unsigned long output2_len)
{
#ifdef RPCGEN_MT
  ck_rv_c_GenerateRandom ret;
  enum clnt_stat retval;
#else
  ck_rv_c_GenerateRandom *pret = NULL;
  ck_rv_c_GenerateRandom ret;
#endif
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_GenerateRandom calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_GenerateRandom)
  if (output2 == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
#ifdef RPCGEN_MT
  retval = c_generaterandom_3(input0, output2_len, &ret, cl);
#else
  pret = c_generaterandom_3(input0, output2_len, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_GenerateRandom\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif
  memcpy(output2, ret.c_GenerateRandom_data.c_GenerateRandom_data_val,
	 ret.c_GenerateRandom_data.c_GenerateRandom_data_len);
  custom_free((void **)&ret.c_GenerateRandom_data.c_GenerateRandom_data_val);

  return ret.c_GenerateRandom_rv;
}

ck_rv_t
myC_SignRecoverInit_C(ck_session_handle_t input0,
		      struct ck_mechanism * input1, ck_object_handle_t input2)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  rpc_ck_mechanism mechanism;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_SignRecoverInit calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_SignRecoverInit)
  custom_sanitize_ck_mechanism(input1);

  /* Check to make sure we cannot initialize before fetching the result
   * of a previous crypto call
   */
  if (check_operation_active_in_filtering_list(input0, SIGN_RECOVER_OP) != NULL) {
    return CKR_OPERATION_ACTIVE;
  }

  serialize_rpc_ck_mechanism(input1, &mechanism);

#ifdef RPCGEN_MT
  retval = c_signrecoverinit_3(input0, mechanism, input2, &ret, cl);
#else
  pret = c_signrecoverinit_3(input0, mechanism, input2, cl);
#endif
  free_rpc_ck_mechanism(&mechanism);

  assert_rpc {
    fprintf(stderr, "Error RPC with C_SignRecoverInit\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t
myC_SignInit_C(ck_session_handle_t input0, struct ck_mechanism * input1,
	       ck_object_handle_t input2)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  rpc_ck_mechanism mechanism;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_SignInit calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_SignInit)
  custom_sanitize_ck_mechanism(input1);

  /* Check to make sure we cannot initialize before fetching the result
   * of a previous crypto call
   */
  if (check_operation_active_in_filtering_list(input0, SIGN_OP) != NULL) {
    return CKR_OPERATION_ACTIVE;
  }

  serialize_rpc_ck_mechanism(input1, &mechanism);

#ifdef RPCGEN_MT
  retval = c_signinit_3(input0, mechanism, input2, &ret, cl);
#else
  pret = c_signinit_3(input0, mechanism, input2, cl);
#endif
  free_rpc_ck_mechanism(&mechanism);

  assert_rpc {
    fprintf(stderr, "Error RPC with C_SignInit\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t
myC_Sign_C(ck_session_handle_t input0, unsigned char *input1,
	   unsigned long input1_len, unsigned char *output2,
	   unsigned long *output2_len)
{
#ifdef RPCGEN_MT
  ck_rv_c_Sign ret;
  enum clnt_stat retval;
#else
  ck_rv_c_Sign *pret = NULL;
  ck_rv_c_Sign ret;
#endif
  opaque_data data;
  /* Remember previous calls */
  p11_request_struct *elem;

  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
      /* Avoid potential NULL_PTR dereference */
      if (output2_len == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
#ifdef DEBUG
  fprintf(stderr, "C_Sign calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_Sign)

  data.opaque_data_len = input1_len;
  data.opaque_data_val = (char *)input1;

  /* Remember previous calls */
  check_linked_list("Sign", SIGN_OP, input0, input1, input1_len, output2,
		    output2_len);

#ifdef RPCGEN_MT
  retval = c_sign_3(input0, data, &ret, cl);
#else
  pret = c_sign_3(input0, data, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_Sign\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  handle_linked_list(Sign, SIGN_OP, input0, input1, input1_len, output2,
		     output2_len);
}

ck_rv_t
myC_SignUpdate_C(ck_session_handle_t input0, unsigned char *input1,
		 unsigned long input1_len)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  opaque_data data;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_SignUpdate calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_SignUpdate)

  data.opaque_data_len = input1_len;
  data.opaque_data_val = (char *)input1;

#ifdef RPCGEN_MT
  retval = c_signupdate_3(input0, data, &ret, cl);
#else
  pret = c_signupdate_3(input0, data, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_SignUpdate\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t
myC_SignFinal_C(ck_session_handle_t input0, unsigned char *output1,
		unsigned long *output1_len)
{
#ifdef RPCGEN_MT
  ck_rv_c_SignFinal ret;
  enum clnt_stat retval;
#else
  ck_rv_c_SignFinal *pret = NULL;
  ck_rv_c_SignFinal ret;
#endif
  p11_request_struct *elem;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_SignFinal calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_SignFinal)

  /* Avoid potential NULL_PTR dereference */
  if (output1_len == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  /* Remember previous calls */
  check_linked_list("SignFinal", SIGN_FINAL_OP, input0, NULL, 0, output1,
		    output1_len);

#ifdef RPCGEN_MT
  retval = c_signfinal_3(input0, &ret, cl);
#else
  pret = c_signfinal_3(input0, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_SignFinal\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  handle_linked_list(SignFinal, SIGN_FINAL_OP, input0, NULL, 0, output1,
		     output1_len);
}

ck_rv_t
myC_VerifyRecoverInit_C(ck_session_handle_t input0,
			struct ck_mechanism * input1, ck_object_handle_t input2)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  rpc_ck_mechanism mechanism;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_VerifyRecoverInit calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_VerifyRecoverInit)
  custom_sanitize_ck_mechanism(input1);

  /* Check to make sure we cannot initialize before fetching the result
   * of a previous crypto call
   */
  if (check_operation_active_in_filtering_list(input0, VERIFY_RECOVER_OP) !=
      NULL) {
    return CKR_OPERATION_ACTIVE;
  }

  serialize_rpc_ck_mechanism(input1, &mechanism);

#ifdef RPCGEN_MT
  retval = c_verifyrecoverinit_3(input0, mechanism, input2, &ret, cl);
#else
  pret = c_verifyrecoverinit_3(input0, mechanism, input2, cl);
#endif
  free_rpc_ck_mechanism(&mechanism);

  assert_rpc {
    fprintf(stderr, "Error RPC with C_VerifyRecoverInit\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t
myC_VerifyInit_C(ck_session_handle_t input0, struct ck_mechanism * input1,
		 ck_object_handle_t input2)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  rpc_ck_mechanism mechanism;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_VerifyInit calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_VerifyInit)
  custom_sanitize_ck_mechanism(input1);
  serialize_rpc_ck_mechanism(input1, &mechanism);

#ifdef RPCGEN_MT
  retval = c_verifyinit_3(input0, mechanism, input2, &ret, cl);
#else
  pret = c_verifyinit_3(input0, mechanism, input2, cl);
#endif
  free_rpc_ck_mechanism(&mechanism);

  assert_rpc {
    fprintf(stderr, "Error RPC with C_VerifyInit\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t
myC_Verify_C(ck_session_handle_t input0, unsigned char *input1,
	     unsigned long input1_len, unsigned char *input2,
	     unsigned long input2_len)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  opaque_data data;
  opaque_data signature;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_Verify calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_Verify)

  data.opaque_data_len = input1_len;
  data.opaque_data_val = (char *)input1;

  signature.opaque_data_len = input2_len;
  signature.opaque_data_val = (char *)input2;

#ifdef RPCGEN_MT
  retval = c_verify_3(input0, data, signature, &ret, cl);
#else
  pret = c_verify_3(input0, data, signature, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_Verify\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t
myC_VerifyUpdate_C(ck_session_handle_t input0, unsigned char *input1,
		   unsigned long input1_len)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  opaque_data data;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_VerifyUpdate calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_VerifyUpdate)

  data.opaque_data_len = input1_len;
  data.opaque_data_val = (char *)input1;

#ifdef RPCGEN_MT
  retval = c_verifyupdate_3(input0, data, &ret, cl);
#else
  pret = c_verifyupdate_3(input0, data, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_VerifyUpdate\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t
myC_VerifyFinal_C(ck_session_handle_t input0, unsigned char *input1,
		  unsigned long input1_len)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  opaque_data signature;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_VerifyFinal calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_VerifyFinal)

  signature.opaque_data_len = input1_len;
  signature.opaque_data_val = (char *)input1;

#ifdef RPCGEN_MT
  retval = c_verifyfinal_3(input0, signature, &ret, cl);
#else
  pret = c_verifyfinal_3(input0, signature, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_VerifyFinal\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t
myC_EncryptInit_C(ck_session_handle_t input0, struct ck_mechanism * input1,
		  ck_object_handle_t input2)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  rpc_ck_mechanism mechanism;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_EncryptInit calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_EncryptInit)
  custom_sanitize_ck_mechanism(input1);

  /* Check to make sure we cannot initialize before fetching the result
   * of a previous crypto call
   */
  if (check_operation_active_in_filtering_list(input0, ENCRYPT_OP) != NULL) {
    return CKR_OPERATION_ACTIVE;
  }

  serialize_rpc_ck_mechanism(input1, &mechanism);

#ifdef RPCGEN_MT
  retval = c_encryptinit_3(input0, mechanism, input2, &ret, cl);
#else
  pret = c_encryptinit_3(input0, mechanism, input2, cl);
#endif
  free_rpc_ck_mechanism(&mechanism);

  assert_rpc {
    fprintf(stderr, "Error RPC with C_EncryptInit\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t
myC_Encrypt_C(ck_session_handle_t input0, unsigned char *input1,
	      unsigned long input1_len, unsigned char *output2,
	      unsigned long *output2_len)
{
#ifdef RPCGEN_MT
  ck_rv_c_Encrypt ret;
  enum clnt_stat retval;
#else
  ck_rv_c_Encrypt *pret = NULL;
  ck_rv_c_Encrypt ret;
#endif
  opaque_data data;
  /* Remember previous calls */
  p11_request_struct *elem;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
      /* Avoid potential NULL_PTR dereference */
      if (output2_len == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
#ifdef DEBUG
  fprintf(stderr, "C_Encrypt calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_Encrypt)

  data.opaque_data_len = input1_len;
  data.opaque_data_val = (char *)input1;

  /* Remember previous calls */
  check_linked_list("Encrypt", ENCRYPT_OP, input0, input1, input1_len, output2,
		    output2_len);

#ifdef RPCGEN_MT
  retval = c_encrypt_3(input0, data, &ret, cl);
#else
  pret = c_encrypt_3(input0, data, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_Encrypt\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  handle_linked_list(Encrypt, ENCRYPT_OP, input0, input1, input1_len, output2,
		     output2_len);
}

ck_rv_t
myC_EncryptUpdate_C(ck_session_handle_t input0, unsigned char *input1,
		    unsigned long input1_len, unsigned char *output2,
		    unsigned long *output2_len)
{
#ifdef RPCGEN_MT
  ck_rv_c_EncryptUpdate ret;
  enum clnt_stat retval;
#else
  ck_rv_c_EncryptUpdate *pret = NULL;
  ck_rv_c_EncryptUpdate ret;
#endif
  opaque_data data;
  /* Remember previous calls */
  p11_request_struct *elem;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
      /* Avoid potential NULL_PTR dereference */
      if (output2_len == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
#ifdef DEBUG
  fprintf(stderr, "C_EncryptUpdate calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_EncryptUpdate)

  data.opaque_data_len = input1_len;
  data.opaque_data_val = (char *)input1;

  /* Remember previous calls */
  check_linked_list("EncryptUpdate", ENCRYPT_UPDATE_OP, input0, input1,
		    input1_len, output2, output2_len);

#ifdef RPCGEN_MT
  retval = c_encryptupdate_3(input0, data, &ret, cl);
#else
  pret = c_encryptupdate_3(input0, data, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_EncryptUpdate\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  handle_linked_list(EncryptUpdate, ENCRYPT_UPDATE_OP, input0, input1,
		     input1_len, output2, output2_len);
}

ck_rv_t
myC_EncryptFinal_C(ck_session_handle_t input0, unsigned char *output1,
		   unsigned long *output1_len)
{
#ifdef RPCGEN_MT
  ck_rv_c_EncryptFinal ret;
  enum clnt_stat retval;
#else
  ck_rv_c_EncryptFinal *pret = NULL;
  ck_rv_c_EncryptFinal ret;
#endif
  p11_request_struct *elem;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_EncryptFinal calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_EncryptFinal)

  /* Avoid potential NULL_PTR dereference */
  if (output1_len == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  /* Remember previous calls */
  check_linked_list("EncryptFinal", ENCRYPT_FINAL_OP, input0, NULL, 0, output1,
		    output1_len);

#ifdef RPCGEN_MT
  retval = c_encryptfinal_3(input0, &ret, cl);
#else
  pret = c_encryptfinal_3(input0, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_EncryptFinal\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  handle_linked_list(EncryptFinal, ENCRYPT_FINAL_OP, input0, NULL, 0, output1,
		     output1_len);
}

ck_rv_t
myC_DecryptInit_C(ck_session_handle_t input0, struct ck_mechanism * input1,
		  ck_object_handle_t input2)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  rpc_ck_mechanism mechanism;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_DecryptInit calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_DecryptInit)
  custom_sanitize_ck_mechanism(input1);

  /* Check to make sure we cannot initialize before fetching the result
   * of a previous crypto call
   */
  if (check_operation_active_in_filtering_list(input0, DECRYPT_OP) != NULL) {
    return CKR_OPERATION_ACTIVE;
  }

  serialize_rpc_ck_mechanism(input1, &mechanism);

#ifdef RPCGEN_MT
  retval = c_decryptinit_3(input0, mechanism, input2, &ret, cl);
#else
  pret = c_decryptinit_3(input0, mechanism, input2, cl);
#endif
  free_rpc_ck_mechanism(&mechanism);

  assert_rpc {
    fprintf(stderr, "Error RPC with C_DecryptInit\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t
myC_Decrypt_C(ck_session_handle_t input0, unsigned char *input1,
	      unsigned long input1_len, unsigned char *output2,
	      unsigned long *output2_len)
{
#ifdef RPCGEN_MT
  ck_rv_c_Decrypt ret;
  enum clnt_stat retval;
#else
  ck_rv_c_Decrypt *pret = NULL;
  ck_rv_c_Decrypt ret;
#endif
  opaque_data data;
  /* Remember previous calls */
  p11_request_struct *elem;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
      /* Avoid potential NULL_PTR dereference */
      if (output2_len == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
#ifdef DEBUG
  fprintf(stderr, "C_Decrypt calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_Decrypt)

  data.opaque_data_len = input1_len;
  data.opaque_data_val = (char *)input1;

  /* Remember previous calls */
  check_linked_list("Decrypt", DECRYPT_OP, input0, input1, input1_len, output2,
		    output2_len);

#ifdef RPCGEN_MT
  retval = c_decrypt_3(input0, data, &ret, cl);
#else
  pret = c_decrypt_3(input0, data, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_Decrypt\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  handle_linked_list(Decrypt, DECRYPT_OP, input0, input1, input1_len, output2,
		     output2_len);
}

ck_rv_t
myC_DecryptUpdate_C(ck_session_handle_t input0, unsigned char *input1,
		    unsigned long input1_len, unsigned char *output2,
		    unsigned long *output2_len)
{
#ifdef RPCGEN_MT
  ck_rv_c_DecryptUpdate ret;
  enum clnt_stat retval;
#else
  ck_rv_c_DecryptUpdate *pret = NULL;
  ck_rv_c_DecryptUpdate ret;
#endif
  opaque_data data;
  /* Remember previous calls */
  p11_request_struct *elem;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
      /* Avoid potential NULL_PTR dereference */
      if (output2_len == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
#ifdef DEBUG
  fprintf(stderr, "C_DecryptUpdate calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_DecryptUpdate)

  data.opaque_data_len = input1_len;
  data.opaque_data_val = (char *)input1;

  /* Remember previous calls */
  check_linked_list("DecryptUpdate", DECRYPT_UPDATE_OP, input0, input1,
		    input1_len, output2, output2_len);
#ifdef RPCGEN_MT
  retval = c_decryptupdate_3(input0, data, &ret, cl);
#else
  pret = c_decryptupdate_3(input0, data, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_DecryptUpdate\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  handle_linked_list(DecryptUpdate, DECRYPT_UPDATE_OP, input0, input1,
		     input1_len, output2, output2_len);
}

ck_rv_t
myC_DecryptFinal_C(ck_session_handle_t input0, unsigned char *output1,
		   unsigned long *output1_len)
{
#ifdef RPCGEN_MT
  ck_rv_c_DecryptFinal ret;
  enum clnt_stat retval;
#else
  ck_rv_c_DecryptFinal *pret = NULL;
  ck_rv_c_DecryptFinal ret;
#endif
  p11_request_struct *elem;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_DecryptFinal calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_DecryptFinal)

  /* Avoid potential NULL_PTR dereference */
  if (output1_len == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  /* Remember previous calls */
  check_linked_list("DecryptFinal", DECRYPT_FINAL_OP, input0, NULL, 0, output1,
		    output1_len);

#ifdef RPCGEN_MT
  retval = c_decryptfinal_3(input0, &ret, cl);
#else
  pret = c_decryptfinal_3(input0, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_DecryptFinal\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  handle_linked_list(DecryptFinal, DECRYPT_FINAL_OP, input0, NULL, 0, output1,
		     output1_len);
}

ck_rv_t
myC_SetAttributeValue_C(ck_session_handle_t input0,
			ck_object_handle_t input1, CK_ATTRIBUTE * input2,
			unsigned long count)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  rpc_ck_attribute_array attributes;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_SetAttributeValue calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_SetAttributeValue)
  if (input2 == NULL) {
    return CKR_ARGUMENTS_BAD;
  } else {
    serialize_rpc_ck_attribute_array(input2, count, &attributes);
  }

#ifdef RPCGEN_MT
  retval = c_setattributevalue_3(input0, input1, attributes, &ret, cl);
#else
  pret = c_setattributevalue_3(input0, input1, attributes, cl);
#endif
  free_rpc_ck_attribute_array(&attributes);
  assert_rpc {
    fprintf(stderr, "Error RPC with C_SetAttributeValue\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t
myC_GetObjectSize_C(ck_session_handle_t input0, ck_object_handle_t input1,
		    unsigned long *output2)
{
#ifdef RPCGEN_MT
  ck_rv_c_GetObjectSize ret;
  enum clnt_stat retval;
#else
  ck_rv_c_GetObjectSize *pret = NULL;
  ck_rv_c_GetObjectSize ret;
#endif
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_GetObjectSize calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_GetObjectSize)

#ifdef RPCGEN_MT
  retval = c_getobjectsize_3(input0, input1, &ret, cl);
#else
  pret = c_getobjectsize_3(input0, input1, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_GetObjectSize\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif
  *output2 = ret.c_GetObjectSize_size;

  return ret.c_GetObjectSize_rv;
}

ck_rv_t
myC_GetOperationState_C(ck_session_handle_t input0, unsigned char *output1,
			unsigned long *output1_len)
{
#ifdef RPCGEN_MT
  ck_rv_c_GetOperationState ret;
  enum clnt_stat retval;
#else
  ck_rv_c_GetOperationState *pret = NULL;
  ck_rv_c_GetOperationState ret;
#endif
  p11_request_struct *elem;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_GetOperationState calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_GetOperationState)

  /* Avoid potential NULL_PTR dereference */
  if (output1_len == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  /* Remember previous calls */
  check_linked_list("GetOperationState", GETOPERATION_STATE_OP, input0, NULL, 0,
		    output1, output1_len);

#ifdef RPCGEN_MT
  retval = c_getoperationstate_3(input0, &ret, cl);
#else
  pret = c_getoperationstate_3(input0, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_GetOperationState\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  handle_linked_list(GetOperationState, GETOPERATION_STATE_OP, input0, NULL, 0,
		     output1, output1_len);
}

ck_rv_t
myC_SetOperationState_C(ck_session_handle_t input0, unsigned char *input1,
			unsigned long input1_len, ck_object_handle_t input2,
			ck_object_handle_t input3)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  opaque_data state;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_SetOperationState calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_SetOperationState)

  state.opaque_data_len = input1_len;
  state.opaque_data_val = (char *)input1;

#ifdef RPCGEN_MT
  retval = c_setoperationstate_3(input0, state, input2, input3, &ret, cl);
#else
  pret = c_setoperationstate_3(input0, state, input2, input3, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_SetOperationState\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t
myC_WrapKey_C(ck_session_handle_t input0, struct ck_mechanism * input1,
	      ck_object_handle_t input2, ck_object_handle_t input3,
	      unsigned char *output4, unsigned long *output4_len)
{
#ifdef RPCGEN_MT
  ck_rv_c_WrapKey ret;
  enum clnt_stat retval;
#else
  ck_rv_c_WrapKey *pret = NULL;
  ck_rv_c_WrapKey ret;
#endif
  rpc_ck_mechanism mechanism;
  p11_request_struct *elem;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_WrapKey calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_WrapKey)

  custom_sanitize_ck_mechanism(input1);
  serialize_rpc_ck_mechanism(input1, &mechanism);

  /* Avoid potential NULL_PTR dereference */
  if (output4_len == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  /* Remember previous calls */
  check_linked_list("WrapKey", WRAPKEY_OP, input0, NULL, 0, output4,
		    output4_len);

#ifdef RPCGEN_MT
  retval = c_wrapkey_3(input0, mechanism, input2, input3, &ret, cl);
#else
  pret = c_wrapkey_3(input0, mechanism, input2, input3, cl);
#endif
  free_rpc_ck_mechanism(&mechanism);

  assert_rpc {
    fprintf(stderr, "Error RPC with C_WrapKey\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  handle_linked_list(WrapKey, WRAPKEY_OP, input0, NULL, 0, output4,
		     output4_len);
}

ck_rv_t
myC_UnwrapKey_C(ck_session_handle_t input0, struct ck_mechanism * input1,
		ck_object_handle_t input2, unsigned char *input3,
		unsigned long input3_len, CK_ATTRIBUTE * input4,
		unsigned long count, ck_object_handle_t * output5)
{
#ifdef RPCGEN_MT
  ck_rv_c_UnwrapKey ret;
  enum clnt_stat retval;
#else
  ck_rv_c_UnwrapKey *pret = NULL;
  ck_rv_c_UnwrapKey ret;
#endif
  rpc_ck_mechanism mechanism;
  rpc_ck_attribute_array attributes;
  opaque_data wrapped_key;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_UnwrapKey calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_UnwrapKey)

  custom_sanitize_ck_mechanism(input1);
  serialize_rpc_ck_mechanism(input1, &mechanism);
  serialize_rpc_ck_attribute_array(input4, count, &attributes);
  wrapped_key.opaque_data_len = input3_len;
  wrapped_key.opaque_data_val = (char *)input3;

#ifdef RPCGEN_MT
  retval =
      c_unwrapkey_3(input0, mechanism, input2, wrapped_key, attributes, &ret,
		    cl);
#else
  pret = c_unwrapkey_3(input0, mechanism, input2, wrapped_key, attributes, cl);
#endif
  free_rpc_ck_mechanism(&mechanism);
  free_rpc_ck_attribute_array(&attributes);

  assert_rpc {
    fprintf(stderr, "Error RPC with C_WrapKey\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif
  *output5 = ret.c_UnwrapKey_handle;

  return ret.c_UnwrapKey_rv;
}

ck_rv_t
myC_DeriveKey_C(ck_session_handle_t input0, struct ck_mechanism * input1,
		ck_object_handle_t input2, CK_ATTRIBUTE * input3,
		unsigned long count, ck_object_handle_t * output4)
{
#ifdef RPCGEN_MT
  ck_rv_c_DeriveKey ret;
  enum clnt_stat retval;
#else
  ck_rv_c_DeriveKey *pret = NULL;
  ck_rv_c_DeriveKey ret;
#endif
  rpc_ck_mechanism mechanism;
  rpc_ck_attribute_array attributes;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_DeriveKey calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_DeriveKey)

  custom_sanitize_ck_mechanism(input1);
  serialize_rpc_ck_mechanism(input1, &mechanism);
  serialize_rpc_ck_attribute_array(input3, count, &attributes);

#ifdef RPCGEN_MT
  retval = c_derivekey_3(input0, mechanism, input2, attributes, &ret, cl);
#else
  pret = c_derivekey_3(input0, mechanism, input2, attributes, cl);
#endif
  free_rpc_ck_mechanism(&mechanism);
  free_rpc_ck_attribute_array(&attributes);

  assert_rpc {
    fprintf(stderr, "Error RPC with C_DeriveKey\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif
  *output4 = ret.c_DeriveKey_handle;

  return ret.c_DeriveKey_rv;
}

ck_rv_t
myC_GenerateKey_C(ck_session_handle_t input0, struct ck_mechanism * input1,
		  CK_ATTRIBUTE * input2, unsigned long count,
		  ck_object_handle_t * output3)
{
#ifdef RPCGEN_MT
  ck_rv_c_GenerateKey ret;
  enum clnt_stat retval;
#else
  ck_rv_c_GenerateKey *pret = NULL;
  ck_rv_c_GenerateKey ret;
#endif
  rpc_ck_mechanism mechanism;
  rpc_ck_attribute_array attributes;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_GenerateKey calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_GenerateKey)

  custom_sanitize_ck_mechanism(input1);
  serialize_rpc_ck_mechanism(input1, &mechanism);
  serialize_rpc_ck_attribute_array(input2, count, &attributes);

#ifdef RPCGEN_MT
  retval = c_generatekey_3(input0, mechanism, attributes, &ret, cl);
#else
  pret = c_generatekey_3(input0, mechanism, attributes, cl);
#endif
  free_rpc_ck_mechanism(&mechanism);
  free_rpc_ck_attribute_array(&attributes);

  assert_rpc {
    fprintf(stderr, "Error RPC with C_GenerateKey\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif
  *output3 = ret.c_GenerateKey_handle;

  return ret.c_GenerateKey_rv;
}

ck_rv_t
myC_GenerateKeyPair_C(ck_session_handle_t input0,
		      struct ck_mechanism * input1, CK_ATTRIBUTE * input2,
		      unsigned long count, CK_ATTRIBUTE * input3,
		      unsigned long count2, ck_object_handle_t * output4,
		      ck_object_handle_t * output5)
{
#ifdef RPCGEN_MT
  ck_rv_c_GenerateKeyPair ret;
  enum clnt_stat retval;
#else
  ck_rv_c_GenerateKeyPair *pret = NULL;
  ck_rv_c_GenerateKeyPair ret;
#endif
  rpc_ck_mechanism mechanism;
  rpc_ck_attribute_array pub_attributes;
  rpc_ck_attribute_array priv_attributes;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_GenerateKeyPairPair calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_GenerateKeyPairPair)

  custom_sanitize_ck_mechanism(input1);
  serialize_rpc_ck_mechanism(input1, &mechanism);
  serialize_rpc_ck_attribute_array(input2, count, &pub_attributes);
  serialize_rpc_ck_attribute_array(input3, count2, &priv_attributes);

#ifdef RPCGEN_MT
  retval =
      c_generatekeypair_3(input0, mechanism, pub_attributes, priv_attributes,
			  &ret, cl);
#else
  pret =
      c_generatekeypair_3(input0, mechanism, pub_attributes, priv_attributes,
			  cl);
#endif
  free_rpc_ck_mechanism(&mechanism);
  free_rpc_ck_attribute_array(&pub_attributes);
  free_rpc_ck_attribute_array(&priv_attributes);

  assert_rpc {
    fprintf(stderr, "Error RPC with C_GenerateKeyPair\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif
  *output4 = ret.c_GenerateKeyPair_pubhandle;
  *output5 = ret.c_GenerateKeyPair_privhandle;

  return ret.c_GenerateKeyPair_rv;
}

ck_rv_t
myC_CreateObject_C(ck_session_handle_t input0, CK_ATTRIBUTE * input1,
		   unsigned long count, ck_object_handle_t * output2)
{
#ifdef RPCGEN_MT
  ck_rv_c_CreateObject ret;
  enum clnt_stat retval;
#else
  ck_rv_c_CreateObject *pret = NULL;
  ck_rv_c_CreateObject ret;
#endif
  rpc_ck_attribute_array attributes;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_CreateObject calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_CreateObject)

  serialize_rpc_ck_attribute_array(input1, count, &attributes);

#ifdef RPCGEN_MT
  retval = c_createobject_3(input0, attributes, &ret, cl);
#else
  pret = c_createobject_3(input0, attributes, cl);
#endif
  free_rpc_ck_attribute_array(&attributes);

  assert_rpc {
    fprintf(stderr, "Error RPC with C_CopyObject\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif
  *output2 = ret.c_CreateObject_handle;

  return ret.c_CreateObject_rv;
}

ck_rv_t
myC_CopyObject_C(ck_session_handle_t input0, ck_object_handle_t input1,
		 CK_ATTRIBUTE * input2, unsigned long count,
		 ck_object_handle_t * output3)
{
#ifdef RPCGEN_MT
  ck_rv_c_CopyObject ret;
  enum clnt_stat retval;
#else
  ck_rv_c_CopyObject *pret = NULL;
  ck_rv_c_CopyObject ret;
#endif
  rpc_ck_attribute_array attributes;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_CopyObject calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_CopyObject)

  serialize_rpc_ck_attribute_array(input2, count, &attributes);

#ifdef RPCGEN_MT
  retval = c_copyobject_3(input0, input1, attributes, &ret, cl);
#else
  pret = c_copyobject_3(input0, input1, attributes, cl);
#endif
  free_rpc_ck_attribute_array(&attributes);

  assert_rpc {
    fprintf(stderr, "Error RPC with C_CopyObject\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif
  *output3 = ret.c_CopyObject_handle;

  return ret.c_CopyObject_rv;
}

ck_rv_t
myC_DestroyObject_C(ck_session_handle_t input0, ck_object_handle_t input1)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_DestroyObject calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_DestroyObject)

#ifdef RPCGEN_MT
  retval = c_destroyobject_3(input0, input1, &ret, cl);
#else
  pret = c_destroyobject_3(input0, input1, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_DestroyObject\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t myC_GetFunctionStatus_C(ck_session_handle_t input0)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_GetFunctionStatus calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_GetFunctionStatus)

#ifdef RPCGEN_MT
  retval = c_getfunctionstatus_3(input0, &ret, cl);
#else
  pret = c_getfunctionstatus_3(input0, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_GetFunctionStatus\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t myC_CancelFunction_C(ck_session_handle_t input0)
{
#ifdef RPCGEN_MT
  rpc_ck_rv_t ret;
  enum clnt_stat retval;
#else
  rpc_ck_rv_t ret;
  rpc_ck_rv_t *pret = NULL;
#endif
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_CancelFunction calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_CancelFunction)

#ifdef RPCGEN_MT
  retval = c_cancelfunction_3(input0, &ret, cl);
#else
  pret = c_cancelfunction_3(input0, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_CancelFunction\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  return ret;
}

ck_rv_t
myC_WaitForSlotEvent_C(ck_flags_t input0, ck_slot_id_t * output1,
		       void *reserved)
{
#ifdef RPCGEN_MT
  ck_rv_c_WaitForSlotEvent ret;
  enum clnt_stat retval;
#else
  ck_rv_c_WaitForSlotEvent *pret = NULL;
  ck_rv_c_WaitForSlotEvent ret;
#endif
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_WaitForSlotEvent calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_WaitForSlotEvent)

  /* P11 compliant */
  if (reserved != NULL) {
    return CKR_ARGUMENTS_BAD;
  }
#ifdef RPCGEN_MT
  retval = c_waitforslotevent_3(input0, &ret, cl);
#else
  pret = c_waitforslotevent_3(input0, cl);
#endif
  assert_rpc {
    fprintf(stderr, "Error RPC with C_WaitForSlotEvent\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif
  *output1 = ret.c_WaitForSlotEvent_count;

  return ret.c_WaitForSlotEvent_rv;
}

ck_rv_t
myC_VerifyRecover_C(ck_session_handle_t input0, unsigned char *input1,
		    unsigned long input1_len, unsigned char *output2,
		    unsigned long *output2_len)
{
#ifdef RPCGEN_MT
  ck_rv_c_VerifyRecover ret;
  enum clnt_stat retval;
#else
  ck_rv_c_VerifyRecover *pret = NULL;
  ck_rv_c_VerifyRecover ret;
#endif
  opaque_data data;
  p11_request_struct *elem;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_VerifyRecover calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_VerifyRecover)

  /* Avoid potential NULL_PTR dereference */
  if (output2_len == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  /* Remember previous calls */
  check_linked_list("VerifyRecover", VERIFY_RECOVER_OP, input0, input1,
		    input1_len, output2, output2_len);

  data.opaque_data_len = input1_len;
  data.opaque_data_val = (char *)input1;

#ifdef RPCGEN_MT
  retval = c_verifyrecover_3(input0, data, &ret, cl);
#else
  pret = c_verifyrecover_3(input0, data, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_VerifyRecover\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  handle_linked_list(VerifyRecover, VERIFY_RECOVER_OP, input0, input1,
		     input1_len, output2, output2_len);
}

ck_rv_t
myC_SignRecover_C(ck_session_handle_t input0, unsigned char *input1,
		  unsigned long input1_len, unsigned char *output2,
		  unsigned long *output2_len)
{
#ifdef RPCGEN_MT
  ck_rv_c_SignRecover ret;
  enum clnt_stat retval;
#else
  ck_rv_c_SignRecover *pret = NULL;
  ck_rv_c_SignRecover ret;
#endif
  opaque_data data;
  p11_request_struct *elem;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_SignRecover calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_SignRecover)

  /* Avoid potential NULL_PTR dereference */
  if (output2_len == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  /* Remember previous calls */
  check_linked_list("SignRecover", SIGN_RECOVER_OP, input0, input1, input1_len,
		    output2, output2_len);

  data.opaque_data_len = input1_len;
  data.opaque_data_val = (char *)input1;

#ifdef RPCGEN_MT
  retval = c_signrecover_3(input0, data, &ret, cl);
#else
  pret = c_signrecover_3(input0, data, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_SignRecover\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  handle_linked_list(SignRecover, SIGN_RECOVER_OP, input0, input1, input1_len,
		     output2, output2_len);
}

ck_rv_t
myC_DigestEncryptUpdate_C(ck_session_handle_t input0, unsigned char *input1,
			  unsigned long input1_len, unsigned char *output2,
			  unsigned long *output2_len)
{
#ifdef RPCGEN_MT
  ck_rv_c_DigestEncryptUpdate ret;
  enum clnt_stat retval;
#else
  ck_rv_c_DigestEncryptUpdate *pret = NULL;
  ck_rv_c_DigestEncryptUpdate ret;
#endif
  opaque_data data;
  p11_request_struct *elem;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_DigestEncryptUpdate calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_DigestEncryptUpdate)

  /* Avoid potential NULL_PTR dereference */
  if (output2_len == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  /* Remember previous calls */
  check_linked_list("DigestEncryptUpdate", DIGEST_ENCRYPT_UPDATE_OP, input0,
		    input1, input1_len, output2, output2_len);

  data.opaque_data_len = input1_len;
  data.opaque_data_val = (char *)input1;

#ifdef RPCGEN_MT
  retval = c_digestencryptupdate_3(input0, data, &ret, cl);
#else
  pret = c_digestencryptupdate_3(input0, data, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_DigestEncryptUpdate\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  handle_linked_list(DigestEncryptUpdate, DIGEST_ENCRYPT_UPDATE_OP, input0,
		     input1, input1_len, output2, output2_len);
}

ck_rv_t
myC_SignEncryptUpdate_C(ck_session_handle_t input0, unsigned char *input1,
			unsigned long input1_len, unsigned char *output2,
			unsigned long *output2_len)
{
#ifdef RPCGEN_MT
  ck_rv_c_SignEncryptUpdate ret;
  enum clnt_stat retval;
#else
  ck_rv_c_SignEncryptUpdate *pret = NULL;
  ck_rv_c_SignEncryptUpdate ret;
#endif
  opaque_data data;
  p11_request_struct *elem;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_SignEncryptUpdate calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_SignEncryptUpdate)

  /* Avoid potential NULL_PTR dereference */
  if (output2_len == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  /* Remember previous calls */
  check_linked_list("SignEncryptUpdate", SIGN_ENCRYPT_UPDATE_OP, input0, input1,
		    input1_len, output2, output2_len);

  data.opaque_data_len = input1_len;
  data.opaque_data_val = (char *)input1;

#ifdef RPCGEN_MT
  retval = c_signencryptupdate_3(input0, data, &ret, cl);
#else
  pret = c_signencryptupdate_3(input0, data, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_SignEncryptUpdate\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  handle_linked_list(SignEncryptUpdate, SIGN_ENCRYPT_UPDATE_OP, input0, input1,
		     input1_len, output2, output2_len);
}

ck_rv_t
myC_DecryptDigestUpdate_C(ck_session_handle_t input0, unsigned char *input1,
			  unsigned long input1_len, unsigned char *output2,
			  unsigned long *output2_len)
{
#ifdef RPCGEN_MT
  ck_rv_c_DecryptDigestUpdate ret;
  enum clnt_stat retval;
#else
  ck_rv_c_DecryptDigestUpdate *pret = NULL;
  ck_rv_c_DecryptDigestUpdate ret;
#endif
  opaque_data data;
  p11_request_struct *elem;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_DecryptDigestUpdate calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_DecryptDigestUpdate)

  /* Avoid potential NULL_PTR dereference */
  if (output2_len == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  /* Remember previous calls */
  check_linked_list("DecryptDigestUpdate", DECRYPT_DIGEST_UPDATE_OP, input0,
		    input1, input1_len, output2, output2_len);

  data.opaque_data_len = input1_len;
  data.opaque_data_val = (char *)input1;

#ifdef RPCGEN_MT
  retval = c_decryptdigestupdate_3(input0, data, &ret, cl);
#else
  pret = c_decryptdigestupdate_3(input0, data, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_DecryptDigestUpdate\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  handle_linked_list(DecryptDigestUpdate, DECRYPT_DIGEST_UPDATE_OP, input0,
		     input1, input1_len, output2, output2_len);
}

ck_rv_t
myC_DecryptVerifyUpdate_C(ck_session_handle_t input0, unsigned char *input1,
			  unsigned long input1_len, unsigned char *output2,
			  unsigned long *output2_len)
{
#ifdef RPCGEN_MT
  ck_rv_c_DecryptVerifyUpdate ret;
  enum clnt_stat retval;
#else
  ck_rv_c_DecryptVerifyUpdate *pret = NULL;
  ck_rv_c_DecryptVerifyUpdate ret;
#endif
  opaque_data data;
  p11_request_struct *elem;
  /* init_ret macro memset() the ret structure only in MT RPC case */
  init_ret
#ifdef DEBUG
      fprintf(stderr, "C_DecryptVerifyUpdate calling\n");
#endif
    /* Check status of RPC */
    check_rpc_status(C_DecryptVerifyUpdate)

  /* Avoid potential NULL_PTR dereference */
  if (output2_len == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  /* Remember previous calls */
  check_linked_list("DecryptVerifyUpdate", DECRYPT_VERIFY_UPDATE_OP, input0,
		    input1, input1_len, output2, output2_len);

  data.opaque_data_len = input1_len;
  data.opaque_data_val = (char *)input1;

#ifdef RPCGEN_MT
  retval = c_decryptverifyupdate_3(input0, data, &ret, cl);
#else
  pret = c_decryptverifyupdate_3(input0, data, cl);
#endif

  assert_rpc {
    fprintf(stderr, "Error RPC with C_DecryptVerifyUpdate\n");
    return -1;
  }
#ifndef RPCGEN_MT
  /* Not done in MT code because ret is already available (*pret is check by assert) */
  ret = *pret;
#endif

  handle_linked_list(DecryptVerifyUpdate, DECRYPT_VERIFY_UPDATE_OP, input0,
		     input1, input1_len, output2, output2_len);
  return ret.c_DecryptVerifyUpdate_rv;
}
