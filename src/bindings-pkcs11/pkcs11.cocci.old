@@
typedef ck_rv_t;
typedef ck_session_handle_t;
identifier session, encrypted, encrypted_len, data, data_len;
@@
- ck_rv_t ML_CK_C_Encrypt(/*in*/ ck_session_handle_t session, /*in*/ unsigned char *data, /*in*/ unsigned long data_len, /*out*/ unsigned char *encrypted, /*in*/ unsigned long *encrypted_len);
+ ck_rv_t ML_CK_C_Encrypt(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char **encrypted, unsigned long *encrypted_len);

@@
identifier session, encrypted, encrypted_len, data, data_len;
@@
- ck_rv_t ML_CK_C_EncryptUpdate(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *encrypted, unsigned long *encrypted_len);
+ ck_rv_t ML_CK_C_EncryptUpdate(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char **encrypted, unsigned long *encrypted_len);

@@
identifier session, encrypted, encrypted_len, data, data_len;
@@
- ck_rv_t ML_CK_C_DigestEncryptUpdate(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *encrypted, unsigned long *encrypted_len);
+ ck_rv_t ML_CK_C_DigestEncryptUpdate(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char **encrypted, unsigned long *encrypted_len);

@@
identifier session, encrypted, encrypted_len, data, data_len;
@@
- ck_rv_t ML_CK_C_SignEncryptUpdate(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *encrypted, unsigned long *encrypted_len);
+ ck_rv_t ML_CK_C_SignEncryptUpdate(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char **encrypted, unsigned long *encrypted_len);

@@
identifier session, encrypted, encrypted_len;
@@
- ck_rv_t ML_CK_C_EncryptFinal(ck_session_handle_t session, unsigned char *encrypted, unsigned long *encrypted_len);
+ ck_rv_t ML_CK_C_EncryptFinal(ck_session_handle_t session, unsigned char **encrypted, unsigned long *encrypted_len);

@@
identifier session, encrypted, encrypted_len, decrypted, decrypted_len;
@@
- ck_rv_t ML_CK_C_Decrypt(ck_session_handle_t session, unsigned char *encrypted, unsigned long encrypted_len, unsigned char *decrypted, unsigned long *decrypted_len);
+ ck_rv_t ML_CK_C_Decrypt(ck_session_handle_t session, unsigned char *encrypted, unsigned long encrypted_len, unsigned char **decrypted, unsigned long *decrypted_len);

@@
identifier session, signature, signature_len, data, data_len;
@@
- ck_rv_t ML_CK_C_VerifyRecover(ck_session_handle_t session, unsigned char *signature, unsigned long signature_len, unsigned char *data, unsigned long *data_len);
+ ck_rv_t ML_CK_C_VerifyRecover(ck_session_handle_t session, unsigned char *signature, unsigned long signature_len, unsigned char **data, unsigned long *data_len);

@@
identifier session, encrypted, encrypted_len, data, data_len;
@@
- ck_rv_t ML_CK_C_DecryptUpdate(ck_session_handle_t session, unsigned char *encrypted, unsigned long encrypted_len, unsigned char *data, unsigned long *data_len);
+ ck_rv_t ML_CK_C_DecryptUpdate(ck_session_handle_t session, unsigned char *encrypted, unsigned long encrypted_len, unsigned char **data, unsigned long *data_len);

@@
identifier session, encrypted, encrypted_len, data, data_len;
@@
- ck_rv_t ML_CK_C_DecryptDigestUpdate(ck_session_handle_t session, unsigned char *encrypted, unsigned long encrypted_len, unsigned char *data, unsigned long *data_len);
+ ck_rv_t ML_CK_C_DecryptDigestUpdate(ck_session_handle_t session, unsigned char *encrypted, unsigned long encrypted_len, unsigned char **data, unsigned long *data_len);

@@
identifier session, encrypted, encrypted_len, data, data_len;
@@
- ck_rv_t ML_CK_C_DecryptVerifyUpdate(ck_session_handle_t session, unsigned char *encrypted, unsigned long encrypted_len, unsigned char *data, unsigned long *data_len);
+ ck_rv_t ML_CK_C_DecryptVerifyUpdate(ck_session_handle_t session, unsigned char *encrypted, unsigned long encrypted_len, unsigned char **data, unsigned long *data_len);

@@
identifier session, decrypted, decrypted_len;
@@
- ck_rv_t ML_CK_C_DecryptFinal(ck_session_handle_t session, unsigned char *decrypted, unsigned long *decrypted_len);
+ ck_rv_t ML_CK_C_DecryptFinal(ck_session_handle_t session, unsigned char **decrypted, unsigned long *decrypted_len);

@@
identifier session, data, data_len;
@@
- ck_rv_t ML_CK_C_GetOperationState(ck_session_handle_t session, unsigned char *data, unsigned long *data_len);
+ ck_rv_t ML_CK_C_GetOperationState(ck_session_handle_t session, unsigned char **data, unsigned long *data_len);

@@
identifier data, output;
@@
- void char_array_to_ulong(/*in*/ unsigned char *data, /*out*/ unsigned long output);
+ void char_array_to_ulong(/*in*/ unsigned char *data, /*in*/ size_t data_size, /*out*/ unsigned long *output);

@@
identifier in, out, out_len;
@@
- void hton_char_array(/*in*/ unsigned char *in, /*out*/ unsigned char *out, /*in*/ unsigned long *out_len);
+ void hton_char_array(/*in*/ unsigned char *in, unsigned long in_len, /*out*/ unsigned char *out, /*in*/ unsigned long *out_len); 

@@
identifier in, out, out_len;
@@
- void ntoh_char_array(/*in*/ unsigned char *in, /*out*/ unsigned char *out, /*in*/ unsigned long *out_len);
+ void ntoh_char_array(/*in*/ unsigned char *in, unsigned long in_len, /*out*/ unsigned char *out, /*in*/ unsigned long *out_len); 

