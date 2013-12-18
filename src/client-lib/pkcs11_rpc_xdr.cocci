@remove_useless_buf@
identifier func;
typedef int32_t;
identifier buf;
@@
  func(...){
  <...
-  register int32_t *buf;
  ...>
}
