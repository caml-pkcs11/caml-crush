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

    The current source code is part of the bindings 1] source tree:
 ----------------------
| 1] PKCS#11 OCaml     |
|       bindings       |
 ----------------------
           |
           |
 { PKCS#11 INTERFACE }
           |
  REAL PKCS#11 MIDDLEWARE
     (shared library)

    Project: PKCS#11 Filtering Proxy
    File:    src/bindings-pkcs11/pkcs11_aliasing.h

-------------------------- CeCILL-B HEADER ----------------------------------*/
/* ------- Flags ------------ */
#ifdef USE_ALIASING
#include "des.h"
#warning "WARNING: using slots, sessions and objects aliasing!"
#ifdef RANDOM_ALIASING
#warning "WARNING: using RANDOM aliasing for sessions and objects handles"
#else
#warning "WARNING: using INCREMENTAL aliasing for sessions and objects handles"
#endif

/* ------- Code to handle random permutation for the handles ---------- */
/* We want to produce unique handles with high bit set to zero */
/* We use DES feistel network as a random permutation          */
unsigned char startup = 0;
des_context des_ctx;
#define RANDSOURCE "/dev/urandom"
unsigned long random_permute(unsigned long in);

unsigned long random_permute(unsigned long in)
{
  unsigned long out;
  unsigned char input[DES_BLOCK_SIZE] = { 0 };
  unsigned char output[DES_BLOCK_SIZE] = { 0 };

  /* Copy our input */
  memcpy(input, &in, sizeof(in));

  /* Initialize the DES with a random key if it is not the */
  /* first time we are here                                */
  if (startup == 0) {
    unsigned char key[DES_BLOCK_SIZE] = { 0 };
    int ret;
    /* Get the key from /dev/urandom */
    FILE *f_rand = fopen(RANDSOURCE, "r");
    if (f_rand == NULL) {
      goto NULLKEY;
    }
    ret = fread(key, DES_BLOCK_SIZE, 1, f_rand);
    if (ret != DES_BLOCK_SIZE) {
      goto NULLKEY;
    }
 NULLKEY:
    des_set_key(&des_ctx, key);
    startup = 1;
  }
  /* Encrypt */
  des_encrypt(&des_ctx, input, output);

  /* Make the output as half of the DES final state        */
  memcpy(&out, output, sizeof(out));

  return out;
}

/* ------- Code to handle aliasing ----------- */
#define ALIAS_ERROR	0xbadf00d
typedef unsigned char boolean;
typedef enum { SESSION = 0, OBJECT = 1, SLOTID = 2 } alias_type;
typedef enum { INCREMENTAL = 0, RANDOM = 1, TRANSPARENT = 2 } alias_mode;
const char *alias_type_str[] = { "SESSION", "OBJECT", "SLOTID" };
const char *alias_mode_str[] = { "INCREMENTAL", "RANDOM", "TRANSPARENT" };

/* Aliasing structure */
typedef struct alias_struct_ {
  unsigned long original;
  unsigned long alias;
  struct alias_struct_ *next;
} alias_struct;

/* We globally keep track of the last used alias */
/* We only increment the aliases                 */
alias_struct *aliases_lists[3] = { NULL };

/* Warning: for sessions and objects, 0 is not allowed */
/* as a valid handle                                   */
unsigned long last_alias[3] = { 1, 1, 0 };

/* Get a list size     */
unsigned long list_size(alias_type type);

unsigned long list_size(alias_type type)
{
  alias_struct *node;
  unsigned long size = 0;
  node = aliases_lists[type];
  while (node != NULL) {
    size++;
    node = node->next;
  }
  return size;
}

/* Helpers for aliases */
unsigned long get_original(unsigned long alias, alias_type type,
			   boolean * found);

unsigned long get_original(unsigned long alias, alias_type type,
			   boolean * found)
{
  alias_struct *node;
  *found = FALSE;
  if (aliases_lists[type] == NULL) {
    /* We have an empty list, this should not happen! We return */
    /* a failsafe                                               */
    return ALIAS_ERROR;
  }
  node = aliases_lists[type];
  while (node != NULL) {
    if (node->alias == alias) {
      *found = TRUE;
      return node->original;
    }
    node = node->next;
  }

  /* If the research didn't succed, we failsafe on ALIAS_ERROR */
  return ALIAS_ERROR;
}

unsigned long get_alias(unsigned long original, alias_type type,
			boolean * found);

unsigned long get_alias(unsigned long original, alias_type type,
			boolean * found)
{
  alias_struct *node;
  *found = FALSE;
  if (aliases_lists[type] == NULL) {
    /* We have an empty list, this should not happen! We return */
    /* a failsafe                                               */
    return ALIAS_ERROR;
  }
  node = aliases_lists[type];
  while (node != NULL) {
    if (node->original == original) {
      *found = TRUE;
      return node->alias;
    }
    node = node->next;
  }

  /* If the research didn't succed, we failsafe on ALIAS_ERROR */
  return ALIAS_ERROR;
}

unsigned long add_alias(unsigned long original, alias_type type,
			alias_mode mode);

unsigned long add_alias(unsigned long original, alias_type type,
			alias_mode mode)
{
  alias_struct *node, *newnode;
  boolean found;
  /* If there is already an alias, we don't add it! */
  unsigned long found_alias = get_alias(original, type, &found);
  if (found == TRUE) {
    return found_alias;
  }
  /* Else, we really add the alias */
  newnode = (alias_struct *) custom_malloc(sizeof(alias_struct));
  newnode->original = original;
  if (mode == INCREMENTAL) {
    /* If we are adding a new slotid, we might have used transparent         */
    /* creation ... Let's try to find if we can still use current last alias */
    if (type == SLOTID) {
#ifdef __GNUC__
      __attribute__ ((unused)) unsigned long found_original;
#else
      unsigned long found_original;
#endif
      found_original = get_original(last_alias[type], type, &found);
      while (found == TRUE) {
	(last_alias[type])++;
	found_original = get_original(last_alias[type], type, &found);
      }
    }
    newnode->alias = last_alias[type];
    (last_alias[type])++;
  } else if (mode == RANDOM) {
    /* RANDOM mode                                           */
    /* Pick up a random number with 32th bit not positionned */
    /* We probably *don't* want to randomize the slot ids    */
    if (type == SLOTID) {
#ifdef __GNUC__
      __attribute__ ((unused)) unsigned long found_original;
#else
      unsigned long found_original;
#endif
      found_original = get_original(last_alias[type], type, &found);
      while (found == TRUE) {
	(last_alias[type])++;
	found_original = get_original(last_alias[type], type, &found);
      }
      newnode->alias = last_alias[type];
      (last_alias[type])++;
    } else {
      /* For the slot ids, we only use the incremental mode */
      newnode->alias = random_permute(original);
    }
  } else {
    /* TRANSPARENT passthrough mode */
    newnode->alias = original;
  }
  newnode->next = NULL;

  if (aliases_lists[type] == NULL) {
    aliases_lists[type] = newnode;
  } else {
    /* Reach the end */
    node = aliases_lists[type];
    while (node->next != NULL) {
      node = node->next;
    }
    node->next = newnode;
  }

  return newnode->alias;
}

boolean remove_original(unsigned long original, alias_type type);

boolean remove_original(unsigned long original, alias_type type)
{
  alias_struct *node, *prevnode;
  boolean found = FALSE;
#ifdef __GNUC__
  __attribute__ ((unused)) unsigned long alias = ALIAS_ERROR;
#else
  unsigned long alias = ALIAS_ERROR;
#endif
  node = aliases_lists[type];
  prevnode = NULL;
  while (node != NULL) {
    if (node->original == original) {
      alias = node->alias;
      if (prevnode == NULL) {
	/* Head case */
	aliases_lists[type] = node->next;
	custom_free((void **)&node);
	node = aliases_lists[type];
      } else {
	/* Non head case */
	prevnode->next = node->next;
	custom_free((void **)&node);
	node = prevnode->next;
      }
      found = TRUE;
    } else {
      prevnode = node;
      node = node->next;
    }
  }

#ifdef DEBUG
  if (found == TRUE) {
    printf("Removing original %s: 0x%lx -> 0x%lx\n", alias_type_str[type],
	   original, alias);
  } else {
    printf("Removing original %s: error when searching for 0x%lx\n",
	   alias_type_str[type], original);
  }
#endif

  return found;
}

boolean remove_alias(unsigned long alias, alias_type type);

boolean remove_alias(unsigned long alias, alias_type type)
{
  alias_struct *node, *prevnode;
  boolean found = FALSE;
#ifdef __GNUC__
  __attribute__ ((unused)) unsigned long original = ALIAS_ERROR;
#else
  unsigned long original = ALIAS_ERROR;
#endif
  node = aliases_lists[type];
  prevnode = NULL;
  while (node != NULL) {
    if (node->alias == alias) {
      original = node->original;
      if (prevnode == NULL) {
	/* Head case */
	aliases_lists[type] = node->next;
	custom_free((void **)&node);
	node = aliases_lists[type];
      } else {
	/* Non head case */
	prevnode->next = node->next;
	custom_free((void **)&node);
	node = prevnode->next;
      }
      found = TRUE;
    } else {
      prevnode = node;
      node = node->next;
    }
  }

#ifdef DEBUG
  if (found == TRUE) {
    printf("Removing alias %s: 0x%lx -> 0x%lx\n", alias_type_str[type],
	   original, alias);
  } else {
    printf("Removing alias %s: error when searching for alias 0x%lx\n",
	   alias_type_str[type], alias);
  }
#endif

  return found;
}

void destroy_list(alias_type type);

void destroy_list(alias_type type)
{
  /* Free all the nodes of the list */
  alias_struct *node, *currnode;

  node = aliases_lists[type];

  while (node != NULL) {
    currnode = node;
    node = node->next;
    custom_free((void **)&currnode);
  }
  aliases_lists[type] = NULL;
  last_alias[type] = 0;

  return;
}

/* Aliasing main functions layer to deal with 32-bit handles */
/* This is here to deal with OCaml 31-bit integer limitation */
unsigned long alias(unsigned long in, alias_type type);

unsigned long alias(unsigned long in, alias_type type)
{
  unsigned long out;
#ifdef RANDOM_ALIASING
  out = add_alias(in, type, RANDOM);
#ifdef DEBUG
  if (type != SLOTID) {
    printf("Aliasing %s: 0x%lx -> 0x%lx (RANDOM)\n", alias_type_str[type], in,
	   out);
  } else {
    printf("Aliasing %s: 0x%lx -> 0x%lx (INCREMENTAL)\n", alias_type_str[type],
	   in, out);
  }
#endif
#else
  out = add_alias(in, type, INCREMENTAL);
#ifdef DEBUG
  printf("Aliasing %s: 0x%lx -> 0x%lx (INCREMENTAL)\n", alias_type_str[type],
	 in, out);
#endif
#endif

  return out;
}

unsigned long unalias(unsigned long in, alias_type type);

unsigned long unalias(unsigned long in, alias_type type)
{
  unsigned long out;
  boolean found;

  out = get_original(in, type, &found);
  if (found == TRUE) {
#ifdef DEBUG
    printf("Unaliasing %s: 0x%lx -> 0x%lx\n", alias_type_str[type], out, in);
#endif
  } else {
    /* For the slot ids, since there is no creation "per se", we force the */
    /* alias creation whenever we need it                                  */
    if (type == SLOTID) {
#ifdef DEBUG
      printf
	  ("Unaliasing %s: 0x%lx error! New TRANSPATENT alias creation forced\n",
	   alias_type_str[type], in);
#endif
      add_alias(in, SLOTID, TRANSPARENT);
    } else {
      out = in;
#ifdef DEBUG
      printf("Unaliasing %s: 0x%lx error! (falling back)\n",
	     alias_type_str[type], in);
#endif
    }
  }
  return out;
}
#endif
