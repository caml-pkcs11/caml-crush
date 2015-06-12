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

-------------------------- MIT License HEADER ----------------------------------*/
/* ------- Flags ------------ */
#ifdef USE_ALIASING
#include "PRESENT_tables.h"
#warning "WARNING: using slots, sessions and objects aliasing!"
#ifdef RANDOM_ALIASING
#warning "WARNING: using RANDOM aliasing for sessions and objects handles"
#else
#warning "WARNING: using INCREMENTAL aliasing for sessions and objects handles"
#endif

/* ------- Code to handle random permutation for the handles ---------- */
/* We want to produce unique handles with high bit set to zero */
/* We use PRESENT128 as a random permutation          */
unsigned char startup = 0;
#define RANDSOURCE "/dev/urandom"
unsigned long random_permute(unsigned long in);

#define PRESENT128_KEY_SIZE (sizeof(u16) * KEY128)

unsigned long random_permute(unsigned long in)
{
  unsigned long out;
  unsigned char input[sizeof(u64)] = { 0 };
  unsigned char output[sizeof(u64)] = { 0 };
  u8 subkeys[TABLE_P * PRESENT128_SUBKEYS_SIZE] = {0};

  /* Copy our input */
  memcpy(input, &in, sizeof(in));

  /* Initialize the PRESENT algo with a random key if it is not the */
  /* first time we are here                                */
  if (startup == 0) {
    unsigned char key[PRESENT128_KEY_SIZE] = { 0 };
    int ret;
    /* Get the key from /dev/urandom */
    FILE *f_rand = fopen(RANDSOURCE, "r");
    if (f_rand == NULL) {
      goto NULLKEY;
    }
    ret = fread(key, PRESENT128_KEY_SIZE, 1, f_rand);
    if (ret != PRESENT128_KEY_SIZE) {
      goto NULLKEY;
    }
 NULLKEY:
    /* Compute the subkeys */
    PRESENT128table_key_schedule((const u8*)key, subkeys);
    startup = 1;
  }
  /* Encrypt */
  PRESENT128table_core((const u8*)input, subkeys, (u8*)output);

  /* Make the output as half of the PRESENT final state        */
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

/* Purge a list */
void purge_list(alias_type type);

void purge_list(alias_type type)
{
  alias_struct *node, *next;
  node = aliases_lists[type];
  while (node != NULL) {
    next = node->next;
    custom_free((void**)&node);
    node = next;
  }
  return;
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
    newnode->alias = last_alias[type];
    (last_alias[type])++;
  } else if (mode == RANDOM) {
    /* RANDOM mode                                           */
    /* Pick up a random number with 32th bit not positionned */
    /* We probably *don't* want to randomize the slot ids    */
    if (type == SLOTID) {
      /* For the slot ids, we only use the incremental mode */
      /* since we do not want to mess up with the absolute  */
      /* slot id numbers                                    */
      newnode->alias = last_alias[type];
      (last_alias[type])++;
    } else {
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
/* as well as 32/64-bit cross architectures where a 32-bit   */
/* client interacts with a 64-bit server                     */
unsigned long alias(unsigned long in, alias_type type);

unsigned long alias(unsigned long in, alias_type type)
{
  unsigned long out;
  alias_mode mode;

#ifdef RANDOM_ALIASING
  mode = RANDOM;
#else
  mode = INCREMENTAL;
#endif
  out = add_alias(in, type, mode);
#ifdef DEBUG
  printf("Aliasing %s: 0x%lx -> 0x%lx (%s)\n", alias_type_str[type], in, out, alias_mode_str[mode]);
#endif

  return out;
}

unsigned long unalias(unsigned long in, alias_type type, boolean *found);

unsigned long unalias(unsigned long in, alias_type type, boolean *found)
{
  unsigned long out;

  out = get_original(in, type, found);
  if (*found == TRUE) {
#ifdef DEBUG
    printf("Unaliasing %s: 0x%lx -> 0x%lx\n", alias_type_str[type], out, in);
#endif
  } else {
    out = in;
#ifdef DEBUG
    printf("Unaliasing %s: 0x%lx error! (falling back)\n",
	     alias_type_str[type], in);
#endif
  }
  return out;
}

/* Function to handle slot id list refresh */
/* in case of slot status           update */
void refresh_slot_id_list(CK_FUNCTION_LIST *pkcs11);

void refresh_slot_id_list(CK_FUNCTION_LIST *pkcs11){
  /* Handle the SLOTID aliasing */
  CK_SLOT_ID* slot_id_list;
  CK_RV rv_slot_list;
  unsigned long i;
  unsigned long count = 0;

#ifdef DEBUG
    printf("Aliasing refresh SLOTID list (purge the list)\n");
#endif
 
  /* If we are not initialized, return */
  if(pkcs11 == NULL){
    return;
  }
  /* Purge the existing list */
  purge_list(SLOTID); 
  /* List all the slots and alias them in our */
  /* local list                               */
  rv_slot_list = pkcs11->C_GetSlotList(CK_FALSE, NULL, &count);
  slot_id_list = (CK_SLOT_ID*)custom_malloc(count * sizeof(CK_SLOT_ID));
  rv_slot_list = pkcs11->C_GetSlotList(CK_FALSE, slot_id_list, &count);
  for(i=0; i < count; i++){
#ifdef DEBUG
    printf("Aliasing refresh SLOTID list, adding 0x%lx\n", slot_id_list[i]);
#endif
    alias(slot_id_list[i], SLOTID);
  }
  custom_free((void**)&slot_id_list);

  return;
}

#endif
