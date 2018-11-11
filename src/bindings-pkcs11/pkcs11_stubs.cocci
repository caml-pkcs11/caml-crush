@rule_find_object@
expression session, object, max_object_count, object_count;
expression _res, _vres, _c2, _v3, _ctx;
@@

  _res = ML_CK_C_FindObjects(session, object, max_object_count, object_count);
  <...
- _vres[1] = camlidl_alloc(max_object_count, 0);
-    Begin_root(_vres[1]);
-      for (_c2 = 0; _c2 < max_object_count; _c2++) {
-        _v3 = camlidl_c2ml_pkcs11_ck_object_handle_t(&object[_c2], _ctx);
-        modify(&Field(_vres[1], _c2), _v3);
-      }
-    End_roots();
- _vres[2] = Val_long(*object_count);
+ if(max_object_count > *object_count){
+   _vres[1] = camlidl_alloc(*object_count, 0);
+    Begin_root(_vres[1]);
+      for (_c2 = 0; _c2 < *object_count; _c2++) {
+        _v3 = camlidl_c2ml_pkcs11_ck_object_handle_t(&object[_c2], _ctx);
+        modify(&Field(_vres[1], _c2), _v3);
+      }
+    End_roots();
+ }
+ else{
+   _vres[1] = camlidl_alloc(max_object_count, 0);
+    Begin_root(_vres[1]);
+      for (_c2 = 0; _c2 < max_object_count; _c2++) {
+        _v3 = camlidl_c2ml_pkcs11_ck_object_handle_t(&object[_c2], _ctx);
+        modify(&Field(_vres[1], _c2), _v3);
+      }
+    End_roots();
+ }
+ _vres[2] = copy_nativeint(*object_count);
  ...>


@rule_get_slot_list@
identifier token_present, slot_list, count, real_count, _ctx, _ctxs, _res, _c1, _c2, _v3, _vres;
@@
  camlidl_pkcs11_ML_CK_C_GetSlotList(...){
  <...
+ unsigned long slots_to_cpy = 0;
  unsigned int token_present;   /*in */
  ck_slot_id_t *slot_list;  /*out */
  unsigned long count;      /*in */
  unsigned long *real_count;    /*out */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  unsigned long _c1;
  mlsize_t _c2;
  ...
- _vres[1] = camlidl_alloc(count, 0);
-   Begin_root(_vres[1]);
-      for (...; ...; ...){
-        _v3 = camlidl_c2ml_pkcs11_ck_slot_id_t(&slot_list[_c2], _ctx);
-        modify(&Field(_vres[1], _c2), _v3);
-    }
+ /* If we have got an error from PKCS#11 functions */
+ /* we return an empty array to the caml side      */
+ if(_res != CKR_OK){
+   count = 0;
+ }
+ if(count > *real_count){
+   _vres[1] = camlidl_alloc(*real_count, 0);
+   slots_to_cpy = *real_count;
+ }
+ else{
+   _vres[1] = camlidl_alloc(count, 0);
+   slots_to_cpy = count;
+ }
+   Begin_root(_vres[1]);
+    for (_c2 = 0; _c2 < slots_to_cpy; _c2++) {
+       _v3 = camlidl_c2ml_pkcs11_ck_slot_id_t(&slot_list[_c2], _ctx);
+       modify(&Field(_vres[1], _c2), _v3);
+     }
  ...
- _vres[2] = Val_long(*real_count);
+ _vres[2] = copy_nativeint(*real_count);
  ...>
}

@rule_get_mech_list@
identifier slot_id, mechanism_list, count, real_count, _res, _vres;
@@

  camlidl_pkcs11_ML_CK_C_GetMechanismList(...){
  <...
+ unsigned long mech_to_cpy = 0;
  ck_slot_id_t slot_id;     /*in */
  ck_mechanism_type_t *mechanism_list;  /*out */
  unsigned long count;      /*in */
  unsigned long *real_count;    /*out */
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  unsigned long _c1;
  mlsize_t _c2;
  ...
- _vres[1] = camlidl_alloc(count, 0);
- Begin_root(_vres[1]);
-   for (...; ...; ...){
-     _v3 = camlidl_c2ml_pkcs11_ck_mechanism_type_t(&mechanism_list[_c2], _ctx);
-     modify(&Field(_vres[1], _c2), _v3);
- }
+ /* If we have got an error from PKCS#11 functions */
+ /* we return an empty array to the caml side      */
+ if(_res != CKR_OK){
+   count = 0;
+ }
+ if(count > *real_count){
+   _vres[1] = camlidl_alloc(*real_count, 0);
+   mech_to_cpy = *real_count;
+ }
+ else{
+   _vres[1] = camlidl_alloc(count, 0);
+   mech_to_cpy = count;
+ }
+ Begin_root(_vres[1]);
+ for (_c2 = 0; _c2 < mech_to_cpy; _c2++) {
+   _v3 = camlidl_c2ml_pkcs11_ck_mechanism_type_t(&mechanism_list[_c2], _ctx);
+   modify(&Field(_vres[1], _c2), _v3);
+ }
  ...
- _vres[2] = Val_long(*real_count);
+ _vres[2] = copy_nativeint(*real_count);
  ...>
}

@rule_get_object_size@
expression session, hobject, object_size;
expression _res, _vres;
@@

  _res = ML_CK_C_GetObjectSize(session, hobject, object_size);
  <...
- _vres[1] = Val_long(*object_size);
+ _vres[1] = copy_nativeint(*object_size);
  ...>


@rule_camlidl_pkcs11_ML_CK_C_SetupArch@
identifier _res;
@@
  camlidl_pkcs11_ML_CK_C_SetupArch(...){
  <...
+ /* Check if SetupArch was previously called, if so, return -1 */
+  if(peer_arch != NOT_INITIALIZED){
+#ifdef DEBUG
+      fprintf(stderr, "Multiple C_SetupArch calls is invalid, ignoring\n");
+#endif
+     _res = -1;
+     _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
+     camlidl_free(_ctx);
+     return _vres;
+  }
 _res = ML_CK_C_SetupArch(...);
+ /* Initialize local architecture */
+  if(_res != UNSUPPORTED_ARCHITECTURE){
+     peer_arch = arch;
+     my_arch = _res;
+  }
  ...>
}

@rule_camlidl_pkcs11_ML_CK_C_LoadModule@
identifier _res;
@@
  camlidl_pkcs11_ML_CK_C_LoadModule(...){
  <...
+#ifdef SERVER_ROLE
+ /* Check if LoadModule was previously called, if so, return -1 */
+  if(module_loaded != NOT_INITIALIZED){
+#ifdef DEBUG
+      fprintf(stderr, "Multiple C_LoadModule calls is invalid, ignoring\n");
+#endif
+     _res = -1;
+     _vres = camlidl_c2ml_pkcs11_ck_rv_t(&_res, _ctx);
+     camlidl_free(_ctx);
+     return _vres;
+  }
+#endif
 _res = ML_CK_C_LoadModule(...);
+#ifdef SERVER_ROLE
+  if(_res == CKR_OK){
+     module_loaded = CKR_OK;
+  }
+#endif
  ...>
}

@rule_camlidl_c2ml_pkcs11_struct_ck_attribute@
identifier _v3, _v5, _c1, _c4;
@@
  camlidl_c2ml_pkcs11_struct_ck_attribute(...){
  <...
+  unsigned char buff[sizeof(uint64_t)];
+  struct ck_attribute temp_;
+  struct ck_attribute *temp;
  _v3[0] = _v3[1] = 0;
  ...
-      _v3[1] = camlidl_alloc((*_c1).value_len, 0);
-      for (...; ...; ...){
-      _v5 = Val_int((unsigned char)((*_c1).value[_c4]));
-      modify(&Field(_v3[1], _c4), _v5);
-    }
+  memset(buff, 0, sizeof(uint64_t));
+  temp_.type_     = 0;
+  temp_.value     = (void*)buff;
+  temp_.value_len = sizeof(uint64_t);
+  temp = &temp_;
+
+  *temp = *_c1;
+
+    if ((long)(*temp).value_len >= 0) {
+    /* Endianness transformations for 
+    CKA_CLASS, CKA_CERTIFICATE_TYPE, CKA_KEY_TYPE,
+    CKA_KEY_GEN_MECHANISM, CKA_AUTH_PIN_FLAGS, CKA_VALUE_LEN,
+    CKA_MECHANISM_TYPE */
+
+#ifdef SERVER_ROLE
+      switch ((*temp).type_) {
+        case 0x0: 
+        case 0x80: 
+        case 0x88: 
+        case 0x100: 
+        case 0x121: 
+        case 0x161: 
+        case 0x166: 
+        case 0x201: 
+        case 0x400: 
+        case 0x401: 
+        case 0x402: 
+        case 0x403: 
+        case 0x404: 
+        case 0x405: 
+        case 0x406: 
+        case 0x500:  {
+            int encode_ret = 1;
+            /* We override the pointer to temp->value */
+            temp->value = (void*)buff;
+            encode_ret = encode_ck_attribute_arch(_c1, temp);
+            if(encode_ret == -1){
+               /* FIXME: Something went wrong with encode_ck_attribute_arch
+                * we exit (thus terminating the child process), is there a
+                * better way to handle it.
+                */
+                exit(-1);
+            }
+        }
+        }
+#endif
+      if ((*temp).value != NULL) {
+
+        _v3[1] = camlidl_alloc((*temp).value_len, 0);
+
+        for(_c4 = 0;_c4 < (*temp).value_len;_c4++) {
+          _v5 = Val_int((unsigned char)((*temp).value[_c4]));
+          modify(&Field(_v3[1], _c4), _v5);
+        }
+      }
+      else {
+        _v3[1] = camlidl_alloc((*temp).value_len, 0);
+        for(_c4 = 0;_c4 < (*temp).value_len;_c4++) {
+          _v5 = Val_int(0);
+          modify(&Field(_v3[1], _c4), _v5);
+        }
+        /*
+        int i = 0;
+        char output_size[sizeof(unsigned long)];
+        *((unsigned long*)output_size) = (*temp).value_len;
+        _v3[1] = camlidl_alloc(sizeof(unsigned long), 0);
+        for (i = 0 ; i< sizeof(unsigned long); i++){
+            modify(&Field(_v3[1], i), output_size[i]);
+        }
+        */
+      }
+    }
+    else {
+      (*temp).value_len = -1;
+      _v3[1] = camlidl_alloc(0, 0);
+    }
  ...>
  }

@rule_camlidl_ml2c_pkcs11_struct_ck_attribute@
identifier _ctx, _c2, _v4, _c5, _c6, _v7;
@@
  camlidl_ml2c_pkcs11_struct_ck_attribute(...){
  <...
   _c5 = Wosize_val(_v4);
-  (*_c2).value = camlidl_malloc(_c5 * sizeof(char ), _ctx);
-  for (...; ...; ...){
-    _v7 = Field(_v4, _c6);
-    (*_c2).value[_c6] = Int_val(_v7);
-  }
-  (*_c2).value_len = _c5;
+  /* Endianness transformations for 
+    CKA_CLASS, CKA_CERTIFICATE_TYPE, CKA_KEY_TYPE, 
+    CKA_KEY_GEN_MECHANISM, CKA_AUTH_PIN_FLAGS, CKA_VALUE_LEN,
+    CKA_MECHANISM_TYPE */
+  switch ((*_c2).type_) {
+    case 0x0: 
+    case 0x80: 
+    case 0x88: 
+    case 0x100: 
+    case 0x121: 
+    case 0x161: 
+    case 0x166: 
+    case 0x201: 
+    case 0x400: 
+    case 0x401: 
+    case 0x402: 
+    case 0x403: 
+    case 0x404: 
+    case 0x405: 
+    case 0x406: 
+    case 0x500:  {
+#ifdef SERVER_ROLE
+      int decode_ret = 1;
+      if ((long)_c5 > 0) {
+           decode_ret = decode_ck_attribute_arch(_v4, _c2, _ctx);
+      }
+      /* We come from OCaml cannot be negative, allocate a zero pointer */
+      else {
+          (*_c2).value = camlidl_malloc(_c5 * sizeof(char), _ctx);
+          (*_c2).value_len = _c5;
+      }
+      /* Break ONLY if decode_ck_attribute_arch succeeded
+       * otherwise, we want to go to the default case */
+      if(decode_ret != -1){
+          break;
+      }
+#endif
+    }
+    /* Fallthrough */
+    default:  {
+      if ((long)_c5 >= 0) {
+        (*_c2).value = camlidl_malloc(_c5 * sizeof(char), _ctx);
+        for(_c6 = 0;_c6 < _c5;_c6++) {
+          _v7 = Field(_v4, _c6);
+          (*_c2).value[_c6] = Int_val(_v7);
+        }
+      }
+      (*_c2).value_len = _c5;
+      break;
+    }
+    
+  }
  ...>
  }

@rule_camlidl_pkcs11_ML_CK_C_WrapKey@
identifier _ctx, _ctxs, _res, _c1, _v2, _vresult, _vres, wrapped_key, wrapped_key_len;
@@
  camlidl_pkcs11_ML_CK_C_WrapKey(...){
  <...
- unsigned long *wrapped_key_len; /*in*/
+ unsigned long tmp_wrapped_key_len = MAX_BUFF_LEN;
+ unsigned long *wrapped_key_len = &tmp_wrapped_key_len; /*in*/
+ unsigned char tmp_buff[MAX_BUFF_LEN];
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  value _v2;
  value _vresult;
  value _vres[2] = { 0, 0, };
+ wrapped_key = tmp_buff;
  ...
- wrapped_key = camlidl_malloc(*wrapped_key_len * sizeof(unsigned char ), _ctx);
  ...>
}

@rule_camlidl_pkcs11_ML_CK_C_Digest@
identifier _ctx, _ctxs, _res, _c1, _c2, _v3, _c4, _v5, _vresult, _vres, digest_len, digest, data_len ;
@@
  camlidl_pkcs11_ML_CK_C_Digest(...){
  <...
- unsigned long *digest_len; /*in*/
+ unsigned char tmp_buff[MAX_BUFF_LEN];
+ unsigned long tmp_digest_len = MAX_BUFF_LEN;
+ unsigned long *digest_len = &tmp_digest_len; /*in*/
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  mlsize_t _c4;
  value _v5;
  value _vresult;
  value _vres[2] = { 0, 0, };
+ digest = tmp_buff;
  ...
  data_len = _c1;
- digest = camlidl_malloc(*digest_len * sizeof(unsigned char ), _ctx);
  ...>
}

@rule_camlidl_pkcs11_ML_CK_C_DigestFinal@
identifier _ctx, _ctxs, _res, _c1, _v2, _v_session, _vresult, _vres, session, digest_len, digest ;
@@
  camlidl_pkcs11_ML_CK_C_DigestFinal(...){
  <...
- unsigned long *digest_len; /*in*/
+ unsigned long tmp_digest_len = MAX_BUFF_LEN;
+ unsigned long *digest_len = &tmp_digest_len; /*in*/
+ unsigned char tmp_buff[MAX_BUFF_LEN];
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  value _v2;
  value _vresult;
  value _vres[2] = { 0, 0, };
+ digest = tmp_buff;
  ...
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
- digest = camlidl_malloc(*digest_len * sizeof(unsigned char ), _ctx);
  ...>
}

@rule_camlidl_pkcs11_ML_CK_C_Sign@
identifier _ctx, _ctxs, _res, _c1, _c2, _v3, _c4, _v5, _vresult, _vres, signed_len, signature, data_len ;
@@
  camlidl_pkcs11_ML_CK_C_Sign(...){
  <...
- unsigned long *signed_len; /*in*/
+ unsigned long tmp_signed_len = MAX_BUFF_LEN;
+ unsigned long *signed_len = &tmp_signed_len; /*in*/
+ unsigned char tmp_buff[MAX_BUFF_LEN];
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  mlsize_t _c4;
  value _v5;
  value _vresult;
  value _vres[2] = { 0, 0, };
+ signature = tmp_buff;
  ...
  data_len = _c1;
- signature = camlidl_malloc(*signed_len * sizeof(unsigned char ), _ctx);
  ...>
}

@rule_camlidl_pkcs11_ML_CK_C_SignRecover@
identifier _ctx, _ctxs, _res, _c1, _c2, _v3, _c4, _v5, _vresult, _vres, signed_len, signature, data_len ;
@@
  camlidl_pkcs11_ML_CK_C_SignRecover(...){
  <...
- unsigned long *signed_len; /*in*/
+ unsigned long tmp_signed_len = MAX_BUFF_LEN;
+ unsigned long *signed_len = &tmp_signed_len; /*in*/
+ unsigned char tmp_buff[MAX_BUFF_LEN];
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  mlsize_t _c2;
  value _v3;
  mlsize_t _c4;
  value _v5;
  value _vresult;
  value _vres[2] = { 0, 0, };
+ signature = tmp_buff;
  ...
  data_len = _c1;
- signature = camlidl_malloc(*signed_len * sizeof(unsigned char ), _ctx);
  ...>
}

@rule_camlidl_pkcs11_ML_CK_C_Encrypt@
identifier _ctx, _res, _c1, session, data, data_len, encrypted, encrypted_len;
@@
  camlidl_pkcs11_ML_CK_C_Encrypt(...){
  <...
- unsigned long *encrypted_len; /*in*/
+ unsigned long tmp_encrypted_len;
+ unsigned long *encrypted_len = &tmp_encrypted_len; /*in*/
  ...
  data_len = _c1;
- encrypted = camlidl_malloc(*encrypted_len * sizeof(unsigned char ), _ctx);
- _res = ML_CK_C_Encrypt(session, data, data_len, encrypted, encrypted_len);
+ _res = ML_CK_C_Encrypt(session, data, data_len, &encrypted, encrypted_len);
  ...
  camlidl_free(_ctx);
+ if (_res == CKR_OK) {
+    custom_free ((void**)&encrypted);
+ }
  ...>
}

@rule_camlidl_pkcs11_ML_CK_C_EncryptUpdate@
identifier _ctx, _res, _c1, session, data, data_len, encrypted, encrypted_len;
@@
  camlidl_pkcs11_ML_CK_C_EncryptUpdate(...){
  <...
- unsigned long *encrypted_len; /*in*/
+ unsigned long tmp_encrypted_len;
+ unsigned long *encrypted_len = &tmp_encrypted_len; /*in*/
  ...
  data_len = _c1;
- encrypted = camlidl_malloc(*encrypted_len * sizeof(unsigned char ), _ctx);
- _res = ML_CK_C_EncryptUpdate(session, data, data_len, encrypted, encrypted_len);
+ _res = ML_CK_C_EncryptUpdate(session, data, data_len, &encrypted, encrypted_len);
  ...
  camlidl_free(_ctx);
+ if (_res == CKR_OK) {
+    custom_free ((void**)&encrypted);
+ }
  ...>
}

@rule_camlidl_pkcs11_ML_CK_C_DigestEncryptUpdate@
identifier _ctx, _res, _c1, session, data, data_len, encrypted, encrypted_len;
@@
  camlidl_pkcs11_ML_CK_C_DigestEncryptUpdate(...){
  <...
- unsigned long *encrypted_len; /*in*/
+ unsigned long tmp_encrypted_len;
+ unsigned long *encrypted_len = &tmp_encrypted_len; /*in*/
  ...
  data_len = _c1;
- encrypted = camlidl_malloc(*encrypted_len * sizeof(unsigned char ), _ctx);
- _res = ML_CK_C_DigestEncryptUpdate(session, data, data_len, encrypted, encrypted_len);
+ _res = ML_CK_C_DigestEncryptUpdate(session, data, data_len, &encrypted, encrypted_len);
  ...
  camlidl_free(_ctx);
+ if (_res == CKR_OK) {
+    custom_free ((void**)&encrypted);
+ }
  ...>
}

@rule_camlidl_pkcs11_ML_CK_C_SignEncryptUpdate@
identifier _ctx, _res, _c1, session, data, data_len, encrypted, encrypted_len;
@@
  camlidl_pkcs11_ML_CK_C_SignEncryptUpdate(...){
  <...
- unsigned long *encrypted_len; /*in*/
+ unsigned long tmp_encrypted_len;
+ unsigned long *encrypted_len = &tmp_encrypted_len; /*in*/
  ...
  data_len = _c1;
- encrypted = camlidl_malloc(*encrypted_len * sizeof(unsigned char ), _ctx);
- _res = ML_CK_C_SignEncryptUpdate(session, data, data_len, encrypted, encrypted_len);
+ _res = ML_CK_C_SignEncryptUpdate(session, data, data_len, &encrypted, encrypted_len);
  ...
  camlidl_free(_ctx);
+ if (_res == CKR_OK) {
+    custom_free ((void**)&encrypted);
+ }
  ...>
}

@rule_camlidl_pkcs11_ML_CK_C_EncryptFinal@
identifier _ctx, _res, _v_session, session, encrypted, encrypted_len;
@@
  camlidl_pkcs11_ML_CK_C_EncryptFinal(...){
  <...
- unsigned long *encrypted_len; /*in*/
+ unsigned long tmp_encrypted_len;
+ unsigned long *encrypted_len = &tmp_encrypted_len; /*in*/
  ...
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
- encrypted = camlidl_malloc(*encrypted_len * sizeof(unsigned char ), _ctx);
- _res = ML_CK_C_EncryptFinal(session, encrypted, encrypted_len);
+ _res = ML_CK_C_EncryptFinal(session, &encrypted, encrypted_len);
  ...
  camlidl_free(_ctx);
+ if (_res == CKR_OK) {
+    custom_free ((void**)&encrypted);
+ }
  ...>
}

@rule_camlidl_pkcs11_ML_CK_C_Decrypt@
identifier _ctx, _res, _c1, session, encrypted, encrypted_len, decrypted, decrypted_len;
@@
  camlidl_pkcs11_ML_CK_C_Decrypt(...){
  <...
- unsigned long *decrypted_len; /*in*/
+ unsigned long tmp_decrypted_len;
+ unsigned long *decrypted_len = &tmp_decrypted_len; /*in*/
  ...
  encrypted_len = _c1;
- decrypted = camlidl_malloc(*decrypted_len * sizeof(unsigned char ), _ctx);
- _res = ML_CK_C_Decrypt(session, encrypted, encrypted_len, decrypted, decrypted_len);
+ _res = ML_CK_C_Decrypt(session, encrypted, encrypted_len, &decrypted, decrypted_len);
  ...
  camlidl_free(_ctx);
+ if (_res == CKR_OK) {
+    custom_free ((void**)&decrypted);
+ }
  ...>
}

@rule_camlidl_pkcs11_ML_CK_C_VerifyRecover@
identifier _ctx, _res, _c1, session, signature, signature_len, data, data_len;
@@
  camlidl_pkcs11_ML_CK_C_VerifyRecover(...){
  <...
- unsigned long *data_len; /*in*/
+ unsigned long tmp_data_len;
+ unsigned long *data_len = &tmp_data_len; /*in*/
  ...
  signature_len = _c1;
- data = camlidl_malloc(*data_len * sizeof(unsigned char ), _ctx);
- _res = ML_CK_C_VerifyRecover(session, signature, signature_len, data, data_len);
+ _res = ML_CK_C_VerifyRecover(session, signature, signature_len, &data, data_len);
  ...
  camlidl_free(_ctx);
+ if (_res == CKR_OK) {
+    custom_free ((void**)&data);
+ }
  ...>
}

@rule_camlidl_pkcs11_ML_CK_C_DecryptUpdate@
identifier _ctx, _res, _c1, session, encrypted, encrypted_len, data, data_len;
@@
  camlidl_pkcs11_ML_CK_C_DecryptUpdate(...){
  <...
- unsigned long *data_len; /*in*/
+ unsigned long tmp_data_len;
+ unsigned long *data_len = &tmp_data_len; /*in*/
  ...
  encrypted_len = _c1;
- data = camlidl_malloc(*data_len * sizeof(unsigned char ), _ctx);
- _res = ML_CK_C_DecryptUpdate(session, encrypted, encrypted_len, data, data_len);
+ _res = ML_CK_C_DecryptUpdate(session, encrypted, encrypted_len, &data, data_len);
  ...
  camlidl_free(_ctx);
+ if (_res == CKR_OK) {
+    custom_free ((void**)&data);
+ }
  ...>
}

@rule_camlidl_pkcs11_ML_CK_C_DecryptDigestUpdate@
identifier _ctx, _res, _c1, session, encrypted, encrypted_len, data, data_len;
@@
  camlidl_pkcs11_ML_CK_C_DecryptDigestUpdate(...){
  <...
- unsigned long *data_len; /*in*/
+ unsigned long tmp_data_len;
+ unsigned long *data_len = &tmp_data_len; /*in*/
  ...
  encrypted_len = _c1;
- data = camlidl_malloc(*data_len * sizeof(unsigned char ), _ctx);
- _res = ML_CK_C_DecryptDigestUpdate(session, encrypted, encrypted_len, data, data_len);
+ _res = ML_CK_C_DecryptDigestUpdate(session, encrypted, encrypted_len, &data, data_len);
  ...
  camlidl_free(_ctx);
+ if (_res == CKR_OK) {
+    custom_free ((void**)&data);
+ }
  ...>
}

@rule_camlidl_pkcs11_ML_CK_C_DecryptVerifyUpdate@
identifier _ctx, _res, _c1, session, encrypted, encrypted_len, data, data_len;
@@
  camlidl_pkcs11_ML_CK_C_DecryptVerifyUpdate(...){
  <...
- unsigned long *data_len; /*in*/
+ unsigned long tmp_data_len;
+ unsigned long *data_len = &tmp_data_len; /*in*/
  ...
  encrypted_len = _c1;
- data = camlidl_malloc(*data_len * sizeof(unsigned char ), _ctx);
- _res = ML_CK_C_DecryptVerifyUpdate(session, encrypted, encrypted_len, data, data_len);
+ _res = ML_CK_C_DecryptVerifyUpdate(session, encrypted, encrypted_len, &data, data_len);
  ...
  camlidl_free(_ctx);
+ if (_res == CKR_OK) {
+    custom_free ((void**)&data);
+ }
  ...>
}

@rule_camlidl_pkcs11_ML_CK_C_DecryptFinal@
identifier _ctx, _v_session, _res, session, decrypted, decrypted_len;
@@
  camlidl_pkcs11_ML_CK_C_DecryptFinal(...){
  <...
- unsigned long *decrypted_len; /*in*/
+ unsigned long tmp_decrypted_len;
+ unsigned long *decrypted_len = &tmp_decrypted_len; /*in*/
  ...
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
- decrypted = camlidl_malloc(*decrypted_len * sizeof(unsigned char ), _ctx);
- _res = ML_CK_C_DecryptFinal(session, decrypted, decrypted_len);
+ _res = ML_CK_C_DecryptFinal(session, &decrypted, decrypted_len);
  ...
  camlidl_free(_ctx);
+ if (_res == CKR_OK) {
+    custom_free ((void**)&decrypted);
+ }
  ...>
}

@rule_camlidl_pkcs11_ML_CK_C_SignFinal@
identifier _ctx, _ctxs, _vres, _vresult, _c1, _v2, _v_session, _res, session, signature, signed_len;
@@
  camlidl_pkcs11_ML_CK_C_SignFinal(...){
  <...
- unsigned long *signed_len; /*in*/
+ unsigned long tmp_signed_len = MAX_BUFF_LEN;
+ unsigned long *signed_len = &tmp_signed_len; /*in*/
+ unsigned char tmp_buff[MAX_BUFF_LEN];
  ck_rv_t _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mlsize_t _c1;
  value _v2;
  value _vresult;
  value _vres[2] = { 0, 0, };
+ signature = tmp_buff;
  ...
  camlidl_ml2c_pkcs11_ck_session_handle_t(_v_session, &session, _ctx);
- signature = camlidl_malloc(*signed_len * sizeof(unsigned char ), _ctx);
  ...>
}

@rule_camlidl_pkcs11_ML_CK_C_GenerateRandom@
identifier _res, session, rand_value, rand_len;
@@
  camlidl_pkcs11_ML_CK_C_GenerateRandom(...){
  <...
  _res = ML_CK_C_GenerateRandom(session, rand_value, rand_len);
+ /* If for some reason the function fails, return an empty array */
+ if(_res != CKR_OK){
+   rand_len = 0;
+ }
 ...>
}

@rule_camlidl_pkcs11_ML_CK_C_GetOperationState@
identifier session, data, data_len, _res, _ctx;
@@
  camlidl_pkcs11_ML_CK_C_GetOperationState(...){
  <...
- unsigned long *data_len; /*in*/
+ unsigned long tmp_data_len;
+ unsigned long *data_len = &tmp_data_len; /*in*/
  ...
- data = camlidl_malloc(*data_len * sizeof(unsigned char ), _ctx);
- _res = ML_CK_C_GetOperationState(session, data, data_len);
+ _res = ML_CK_C_GetOperationState(session, &data, data_len);
  ...
  camlidl_free(_ctx);
+ if (_res == CKR_OK) {
+    custom_free ((void**)&data);
+ }
  ...>
}

@rule_copy_nativeint@
expression out, in;
@@
- out = copy_nativeint(in);
+ /* To handle OCaml client RPC layer int64 format */
+ out = custom_copy_int(in);

@rule_Nativeint_val@
expression out, in;
@@
- out = Nativeint_val(in);
+ /* To handle OCaml client RPC layer int64 format */
+ out = custom_int_val(in);

@rule_custom_alloc@
@@
- #include "pkcs11.h"
+ #define CUSTOM_ALLOC
+ #include "pkcs11.h"

@rule_camlidl_pkcs11_char_array_to_ulong@
identifier data, output;
@@
  camlidl_pkcs11_char_array_to_ulong(...){
  <...
- char_array_to_ulong(data, output);
+ char_array_to_ulong(data, _c1, &output);
  ...>
}

@rule_camlidl_pkcs11_ntoh_char_array@
identifier in, out, _vres, out_len, _ctx;
@@
  camlidl_pkcs11_ntoh_char_array(...){
  <...
  value _vres;
+ unsigned char tmp[8];
+ unsigned long tmp_out_len;
  ...
  camlidl_ctx _ctx = &_ctxs;
+ out = (unsigned char*)tmp;
+ out_len = &tmp_out_len;
  ...
- out = camlidl_malloc(*out_len * sizeof(unsigned char ), _ctx);
- ntoh_char_array(in, out, out_len);
+ ntoh_char_array(in, _c1, out, out_len);
  ...>
}

@rule_camlidl_pkcs11_hton_char_array@
identifier in, out, _vres, out_len, _ctx;
@@
  camlidl_pkcs11_hton_char_array(...){
  <...
  value _vres;
+ unsigned char tmp[8];
+ unsigned long tmp_out_len;
  ...
  camlidl_ctx _ctx = &_ctxs;
+ out = (unsigned char*)tmp;
+ out_len = &tmp_out_len;
  ...
- out = camlidl_malloc(*out_len * sizeof(unsigned char ), _ctx);
- hton_char_array(in, out, out_len);
+ hton_char_array(in, _c1, out, out_len);
  ...>
}
