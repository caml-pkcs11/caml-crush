# Caml Crush: an OCaml PKCS#11 filtering proxy

## PKCS#11 proxy filter module details


The following documentation is about the PKCS#11 filter logics 
and the filtering rules syntax.

The PKCS#11 filter is written in OCaml, and the rules syntax 
also use OCaml style expressions (the configuration module 
uses the OCaml [config-file][] package).

Back to [INDEX.md](INDEX.md).

## Disclaimer: on the filter possible side effects

Though the filter has been designed to be as transparent as possible regarding 
the PKCS#11 standard as well as the underlying PKCS#11 middleware, some side 
effects might appear due to the filtering implementation choices. If you use PKCS#11 
conforming tests with ot without the filter (for example with the --without-filter 
option in the configure script), you will most likely see some minor differences.

This is mainly due to the fact that some PKCS#11 functions in the filter use **local caches** to 
check mechanisms and objects when they are listed. This can interfere with what the genuine underlying 
middleware would normally respond, especially when PKCS#11 **tricky cases** are 
tested (trying to use non existant mechanisms, ...). 

However, one should keep in mind that in "normal" cases (meaning with standard 
PKCS#11 applications), the filter should not introduce glitches. If it does, 
please report the issue.

## The filter architecture
<pre>
         ----------------------  
        |  PKCS#11 RPC server  |
         ----------------------                   The PKCS#11 filter  
                   |                                 source tree
              --------------          _
             | 1] FRONTEND  |          |--- 1] /src/filter/fontend/frontend.ml
     ------------------------------    |
    |      PKCS#11 filter          |   |--- /src/filter/filter 
    |------------------------------|   |             [2] |- filter_common.ml
    |  --------------------------  |   |             [3] |- filter_configuration.ml
    | | user defined extensions  | |   |             [4] |- filter.ml
    | |            [5]           | |   |             [5] |- filter_actions.ml
    |  --------------------------  |   |             
    | | common  | parse  | core  | |   | 
    | | helpers | config | engine| |   |
    | |  [2]    |  [3]   |  [4]  | |   |
     ------------------------------    |
             | 6] BACKEND  |          _|--- 6] /src/filter/backend/backend.ml
              -------------            
                   |             
         ----------------------  
        |    PKCS#11 OCaml     | 
        |       bindings       | 
         ----------------------  
                   |
         { PKCS#11 INTERFACE }
                   |
         REAL PKCS#11 MIDDLEWARE
            (shared library)
</pre>

The filter has a modular design in the project, and is composed of four main parts:

1] **Frontend**: this module is an isolation layer between the filter and the proxy server. It mainly 
consists in passthrough PKCS#11 calls.

2] **Common helpers**: the helpers define common logging and exceptions.

3] **Configuration parser**: the parser is in charge of reading the filter configuration file 
using [config-file][] engine and rules. Some sanity checks are performed on the options.

[config-file]: http://config-file.forge.ocamlcore.org/

4] **Filter core engine**: this is the main filtering engine, where the rules are enforced. It mainly 
consists in passthrough PKCS#11 calls for all the functions, with "hook" calls to filtering routines 
positionned where necessary.

5] **User defined extensions**: this module contains user defined extensions that will be called on some 
triggers during the filtering phase. It can be seen as a "plugins" system allowing custom routines to be 
applied in the filtering chain (with some restrictions though, see below).

6] **Backend**: this module is an isolation layer between the filter and the OCaml/C PKCS#11 bindings that talk 
to the "real" PKCS#11 library. It mainly consists in passthrough PKCS#11 calls.


> Please note that the Frontend and Backend modules main purpose is to make it very easy to change the filter 
> without touching to the other parts of the project. Changing the filter core is as easy as writing functions using 
> an API conforming to what the Fontend/Backend expose.

## The filter options syntax

The filter configuration is parsed through the OCaml [config-file][] module. It uses OCaml style strings, integers, 
lists of tuples and regular expressions.

The accepted options keywords, with their OCaml style syntax, are:

  * **debug** = integer between 0 and 3
  * **modules** = [(a1, b1), (a2, b2) ...] is a **list** of **couples** of strings (a, b) with 'a' being an alias, and 'b' 
being a PATH to the aliased PKCS#11 module
  * **log_subchannel** = **string** representing the filter log subchannel in the server
  * **forbidden\_mechanisms** = [(a1, b1), (a2, b2) ...] is a **list** of **couples** where 'a' is a regular expression string 
representing modules and 'b' is a list of PKCS#11 mechanisms with the PKCS#11 definition syntax (CKM\_RSA\_PKCS for instance)
  * **allowed\_labels** = [(a1, b1), (a2, b2) ...] is a **list** of **couples** where 'a1', 'a2', ... are regular expression strings 
representing module names, and 'b1', 'b2', ... are regular expressions representing labels
  * **allowed_ids** = [(a1, b1), (a2, b2) ...] is a **list** of **couples** where 'a1', 'a2', ... are regular expression strings 
representing module names, and 'b1', 'b2', ... are regular expressions representing ids
  * **forbidden\_functions** = [(a1, b1), (a2, b2) ...] is a **list** of **couples** where 'a1', 'a2', ... are regular expression strings 
representing module names, and 'b1', 'b2', ... are **lists** of PKCS#11 functions with the PKCS#11 naming convention (C\_Login, 
C\_Logout ...)
  * **enforce\_ro\_sessions** = [(a1, b1), (a2, b2) ...] is a **list** of **couples** where 'a' is a regular expression string representing
module names, and 'b1', 'b2', ... are booleans that can take 'true', 'false', 'yes' and 'no' as possible values
  * **forbid\_admin\_operations** = [(a1, b1), (a2, b2) ...] is a **list** of **couples** where 'a' is a regular expression string representing
module names, and 'b1', 'b2', ... are booleans that can take 'true', 'false', 'yes' and 'no' as possible values 
  * **remove\_padding\_oracles** = [(a1, b1), (a2, b2) ...] is a **list** of **couples** where 'a' is a regular expression string representing
module names, and 'b1', 'b2', ... are a **lists** of cryptographic operations type that can take as possible values 'wrap', 'unwrap', 
'encrypt', 'sign' and 'all' (this last one represents the sum of all the values)
  * **filter\_actions_pre** =  [(a1, b1), (a2, b2) ...] is a **list** of **couples** where 'a' is a regular expression string representing 
module names, and 'b1', 'b2', ... are **lists** of **couples** (c, d) where 'c' is a PKCS#11 function following the PKCS#11 
naming convention (C\_Login, C\_Logout ...) and 'd' is an OCaml function name defined in /src/filter/filter/filter\_actions.ml 
(it is a user defined action to be triggered when the PKCS#11 function 'c' is called as a 'pre action', see below for more details)
  * **filter\_actions_post** =  [(a1, b1), (a2, b2) ...] is a **list** of **couples** where 'a' is a regular expression string representing 
module names, and 'b1', 'b2', ... are **lists** of **couples** (c, d) where 'c' is a PKCS#11 function following the PKCS#11 
naming convention (C\_Login, C\_Logout ...) and 'd' is an OCaml function name defined in /src/filter/filter/filter\_actions.ml 
(it is a user defined action to be triggered when the PKCS#11 function 'c' is called as a 'post action', see below for more details)

The meaning of each key word is detailed in the following sections.

## Logging and debugging options

  * **debug** (*integer*) can be used to increase the verbosity level:
    * 0 = merely no log at all, except critical errors and printing the debug level itself
    * 1 = level 0 + positive filtering matches (i.e. when the filter detects something to block)
    * 2 = level 1 + negative filtering matches (i.e. when the filter detects that it must not block something)
    * 3 = level 2 + print all the fetched configuration variables in the filter configuration file (modules aliasing, 
filtered labels, filtered ids, ...)
> default is debug = 0

Syntax example:

```ocaml
debug = 3
```

  * **log\_subchanel** (*string*):
    * Netplex allows the use of **subchannels** to split the logging file.
      You can specify a subchannel (also defined in pkcs11proxyd.conf) to
      send the log stream from the filter to an alternative output.
> default is log\_subchanel = the main pkcs11proxyd server channel

Syntax example:

    log_subchanel = mylogsubchannel
> Please note that the subchannel must indeed exist in the Netplex server context (meaning that it has 
> been declared in the server configuration file). If this is not the case, the filter logs will fallback to 
> the standard Netplex server output.

## PKCS#11 modules options

  * **modules** (*list of couples of [string_regexp x string_path_to_lib]*):
    * As mentionned previously, the client asks for a specific module name.
      The "modules" parameter binds module "names" and the path to the corresponding PKCS#11 library.

> This option is **mandatory**: if no module is defined, an error is triggered.

Syntax example:
 
```ocaml
modules = [ ("softhsm", "/usr/lib/libsofthsm.so"), 
            ("opensc", "/usr/lib/opensc-pkcs11.so") ]
```

> This will alias "softhsm" to the library "/usr/lib/libsofthsm.so", and "opensc" to "/usr/lib/opensc-pkcs11.so".
> Please note that you can also use an empty string "" as an alias. On the client side, the compiled client library 
> libp11clientsofthsm.so will send the string "softhsm", while libp11client.so will send the empty string (the alias 
> sent by the client library is hardcoded inside the binary at compilation time).


## Filtering PKCS#11 objects options

The following two options are used to filter what objects the client application will be able to manipulate. 
It uses the PKCS#11 CKA\_LABEL and CKA\_ID attributes to filter objects.

The purpose is to define a list of objects you want to match for each module regarding their label and/or id, 
objects not matching will **not** be visible to the application.


  * **allowed\_labels** (*list of couples of [string_regexp x list of string_regexp]*):
    * The allowed CKA\_LABEL labels for the defined modules 

> There is no default value for this option: if no allowed\_label option is defined, there is no filtering enforced on 
> labels. The modules aliases regular expressions **must** however match an existing alias defined in the **modules** 
> option: an error is triggered if this is not the case.

Syntax example:

```ocaml
allowed_labels = [ ("\\(sofths.*\\|opencryptoki\\)", ["MYLABEL.*", "LABEL_EXACT"]), 
                   ("softhsm", [".*THE_LABEL", "mytes.*"]) ]
```

> The first rule of the above example will allow any "MYLABEL.\*" regular expression, or a "LABEL\_EXACT" for any module 
> alias matching the "(sofths.\*|opencryptoki)" regular expression (please note the escaping characters for regexps). 
> For example, an object in a module related to the alias "softhsm" with a "MYLABEL1" label is allowed, but would not be allowed 
> with a "1MYLABEL" label. Following the same rule, an object in a module related to the alias "softhsm111" with a label 
> "MYLABEL" is allowed. If a module alias is not covered at all by any regexp rule in allowed\_labels, it is **not** filtered.
> Finally, whenever a module alias is conerned by more than one rule, a logical **OR** is applied on the filtered labels: the "softhsm" 
> alias accepts objects with the regexps "MYLABEL.\*" **OR** "LABEL\_EXACT" **OR** ".\*THE\_LABEL" **OR** "mytes.\*" in the previous example.

  * **allowed\_ids** (*list of couples of [string_regexp x list of string_regexp]*):
    * The allowed CKA\_ID values for the defined modules (these are **hexadecimal** encoded values, since the ID is generally in 
a raw binary format)

Syntax example:

```ocaml
allowed_ids = [ ("softhsm.*", ["0123.*"]) ]
```

> The allowed\_ids filtering patterns follow the same rules as the one explained in the allowed\_labels section.


## Filtering PKCS#11 mechanisms options

This section describe the filtering of PKCS#11 mechanisms. The two options can
be used to restrict the mechanisms that will be available to client
applications and block some known attacks that use the properties of bad
encryption padding to perform [padding oracle attaks][wiki] (with PKCS#1 v1.5 or CBC paddings for 
instance) or [Wrap/Decrypt style attacks][wrap]. These attacks are inherent 
to the PKCS#11 standard, and preventing the usage of the dangerous associated mechanisms 
will inhibit them (though it might be a too coarse and limiting solution, since the Wrap/Unwrap mechanism might 
be necessary in some use cases). A fine grained approach to prevent these attacks would require a **"stateful"**
filter (i.e. memorizing the past PKCS#11 calls and conditionnally decide whether to filter a call or not): this 
is not the case of the current filter, but there is some work in progress regarding this issue.

[wiki]: http://en.wikipedia.org/wiki/Padding_oracle_attack
[wrap]: http://www.lsv.ens-cachan.fr/~steel/slides/Tookan.pdf

  * **forbidden\_mechanisms** (*list of couples of [string_regexp x list of PKCS#11_mechanism]*):
    * This option sets up a black list of forbidden PKCS#11 mechanisms using the PKCS#11 syntax. Whenever a client 
lists the mechanisms of a token, these mechanisms are transparently removed from the "real" mechanisms list exposed 
by the "real" PKCS#11 module. In addition, if the client tries to use these mechanisms through any of the cryptographic 
"Init" functions (C\_Encrypt\_Init, C\_Decrypt\_Init, ...), the filter blocks the call with a CKR\_MECHANISM\_INVALID.
Each couple of the list contains a module alias regexp as a first element, and a list of mechanisms as a second 
element.

Syntax example:

```ocaml
forbidden_mechanisms = [ ("sof.*", [CKM_RSA_PKCS, CKM_MD5_RSA_PKCS]), 
                         ("softhsm", [CKM_DES_ECB]) ]
```

> There is no default value for forbidden\_mechanisms. Please note that the mechanisms **are not** regexps, they 
> must correspond to **exact** PKCS#11 mechanism names as they are listed in the standard. If a module alias name 
> is covered by two rules, a logical **AND** is applied: the rule given in the previous example will inhibit 
> CKM\_RSA\_PKCS **AND** CKM\_MD5\_RSA\_PKCS **AND** CKM\_DES\_ECB.


  * **remove\_padding\_oracles** (*list of couples of [string_regexp x list of (wrap|unwrap|encrypt|sign|all)]*):
    * This option blocks all the mechanisms that are considered dangerous because they can introduce a padding oracle. 
For now, such mechanisms are hardcoded in the filter (see their list below). For these mechanisms, one can define  
if a **wrap**, **unwrap**, **encrypt**, **sign** is forbidden: the operations will be forbidden for all the 
mechanisms. The special value **all** is a short key word for "wrap and unwrap and encrypt and sign". These rules are 
implemented in the filter by blocking C\_Wrap, C\_Unwrap, C\_Encrypt\_Init, C\_Sign\_Init for the dangerous mechanisms, 
with a CKR\_MECHANISM\_INVALID as error value. One should notice that remove\_padding\_oracles overlaps the 
forbidden\_mechanisms option, as well as the forbidden\_functions option (see below for a detailed description of 
this option). However, we find it more straightforward to give the user the opportunity to easily block known PKCS#11 
weaknesses.

The potentially dangerous mechanisms (with PKCS#1 v1.5 or CBC paddings) that are harcoded inside the filter are:

```ocaml
[CKM_RSA_PKCS; CKM_MD2_RSA_PKCS; CKM_MD5_RSA_PKCS; CKM_SHA1_RSA_PKCS; CKM_RIPEMD128_RSA_PKCS; 
 CKM_RIPEMD160_RSA_PKCS; CKM_SHA256_RSA_PKCS; CKM_SHA384_RSA_PKCS; CKM_SHA512_RSA_PKCS; CKM_RC2_CBC_PAD; 
 CKM_DES_CBC_PAD; CKM_DES3_CBC_PAD; CKM_CDMF_CBC_PAD; CKM_CAST_CBC_PAD; CKM_CAST3_CBC_PAD; 
 CKM_CAST5_CBC_PAD; CKM_CAST128_CBC_PAD; CKM_RC5_CBC_PAD; CKM_IDEA_CBC_PAD; CKM_AES_CBC_PAD; 
 CKM_RSA_X_509]
```

Syntax example:

```ocaml
remove_padding_oracles = [ (".*", [wrap, unwrap, encrypt]), 
                           ("softhsm", [sign]) ]
```

> There is no default value for remove\_padding\_oracles. As for the forbidden\_mechanisms option, a logical 
> **AND** is applied when a module is covered by different rules: the "softhsm" module will have "wrap", "unwrap" 
> and "encrypt" forbidden because of the first rule, and "sign" forbidden with the second rule.


## Filtering PKCS#11 functions options
  * **forbidden\_functions** (*list of couples of [string_regexp x list of PKCS#11_function]*):
    * This option blocks any PKCS#11 function defined in the standard by returning CKR\_FUNCTION\_NOT\_SUPPORTED. 
The PKCS#11 function names must **exactly correspond** to the ones used in the standard API, such as C\_Login, C\_Wrap, ...

Syntax example:

```ocaml
forbidden_functions  = [ ("soft.*", [C_Login, C_Logout]), 
                         ("softhsm", [C_Sign]) ]
```

> There is no default value for forbidden\_functions. As for the forbidden\_mechanisms option, a logical 
> **AND** is applied when a module is covered by different rules: the "softhsm" module will have C\_Login and 
> C\_Logout blocked by the first rule, and C\_Sign blocked by the second rule.


## Filtering sessions options
  * **enforce\_ro\_sessions** (*list of couples of [string_regexp x boolean]*):
    * This option will enforce all the sessions to be **Read Only**, even if the user positions the RW flag 
when opening them. This option will preserve the **token objects** against any modification, and can be useful 
when the user is only intented to use the token as a cryptographic ressource with *existing objects* that an 
"administrator" has provisionned in the token. As for many other options, the RO sessions can be enforced 
per module alias. The possible values to express the boolean decision of enforcing or not RO sessions are: 
**yes** and **no** or **true** and **false**.

Syntax example:

```ocaml
enforce_ro_sessions  = [ ("soft.*", no), 
                         ("opencryptoki", yes) ]
```

> The default value for enforce\_ro\_sessions is "no" (meaning that if there is no rule associated to a module, 
> the RO sessions are **not** enforced). The previous rule will **not enforce** RO sessions for "softhsm", but 
> **will enforce** them for the opencryptoki module alias.
 
  * **forbid\_admin\_operations** (*list of couples of [string_regexp x boolean]*):
    * This option will block **administration operations** on the token associated to a module alias by refusing any SO 
(Security Officer) C\_Login. The purpose is to prevent "normal" users to perform administrative tasks on the tokens. 
Please note that the PKCS#11 way of segregating normal users and SO users is to use two different PINs. However, if the 
SO PIN can be bruteforced (for example if there is no bad PIN counter as this can be the case on some Hardware Security 
Modules), a normal user would be able to perform SO operations by guessing the SO PIN. This filter option can be seen 
as a "barrier" blocking such attacks whenever one is sure that a token has no reason to be administrated. The possible 
values to express the boolean decision of enforcing or not admin blocking are: **yes** and **no** or **true** and **false**.

Syntax example:

```ocaml    
forbid_admin_operations = [ (".*", yes) ]
```

> The default value for forbid\_admin\_operations is "no" (meaning that if there is no rule associated to a module,
> the SO operations are **allowed**). The previous rule enforces **blocking the SO operations** on all the modules 
> (thanks to the regexp ".\*" matching all the modules).

## Adding user defined actions
### The filter\_actions option syntax and usage
  * **filter\_actions** (*list of couples of [string_regexp x list of couples of [PKCS#11_function x custom_function]]*):
    * This option is a way to **extend** the filter features as the user can provide its own hooks on every PKCS#11 
function. In order to apply an action "Action" triggered by a call to a PKCS#11 function, say C\_Login for example, 
a couple (C\_Login, Action) is defined in the filter\_actions option. For the sake of simplicity, these hooks have been 
gathered inside one file in the filter source tree [src/filter/filter/filter_actions.ml](../src/filter/filter/filter_actions.ml).

Syntax example:
    
```ocaml
filter_actions = [ (".*", [(C_Login, c_Login_hook), (C_Initialize, c_Initialize_hook)]),
                   ("soft.*", [(C_CloseSession, identity), (C_Login, c_Login_hook2)]) ]
```

> There is no default value for filter\_actions: if **no rule** is defined for a given PKCS#11 function, **no hook** will be 
> executed for this function. If **many rules** concern the same PKCS#11 function, the hooks are executed **in the order they are declared**. 
> The previous rule will execute the user defined c\_Login\_hook and then c\_Login\_hook2 when 
> C\_Login is called for all the modules, the identity user defined function when C\_CloseSession is called for 
> "soft.\*" regexp module aliases ("softhsm" for instance), and so on ... Please beware that the user defined hooks are 
> executed **prior** to any other filtering rule. In addition, depending on the hooking function return value, the other 
> filtering rule might or might not be enforced: this is a way to **override** the original filtering rules and replace 
> them with custom ones (see below for details on how this works).

### Adding a new user defined action in the code

In order to add a new defined action, the user must edit the [src/filter/filter/filter_actions.ml](../src/filter/filter/filter_actions.ml) 
file where there are already some very simple examples of hooking functions:
 
  * `identity` is designed to hook pretty much anything: it prints " ######### Identity hook called!"
  * `c_Initialize_hook` is designed to hook C\_Initialize, it prints the " ########## Hooking C_Initialize!" string at log level 1
  * `c_Login_hook` is designed to hook C\_Login, it prints the " ######### Passthrough C_Login with pin %s!" string with the C\_Login 
given PIN. If PIN is "1234", the hooks returns and lets C\_Login continue its normal execution. If PIN is not "1234", C\_Login 
is interrupted and the PKCS#11 error CKR\_PIN\_LOCKED is returned. Though this action is kind of useless, it shows the main advantage 
of user defined routines: one can completely customize the filter since input and output values can be handled here. One can also 
make "real" PKCS#11 calls to the Backend and decide of the filtering action depending on the result.

The PKCS#11 functions hooking system uses the OCaml [marshaling module](http://caml.inria.fr/pub/docs/manual-ocaml/libref/Marshal.html).
The user defined functions **must take exactly one argument** that corresponds to the marshaled string of the original PKCS#11 function 
original arguments tuple (this argument is therefore of type string). Similarly, the output values of custom hooks are strings that are 
the **marshaled versions** of couples whose first element is a boolean value, and the second element is a PKCS#11 return value. If the 
first element is "false", then the hooked PKCS#11 function will **continue its execution** after the hook execution, ignoring 
the second element of the couple. This means that in this case, all the other filtering options are applied after the hook execution. 
On the contrary, if the first element of the couple is "true", the second element of the couple is considered to be the hooked function 
**return value**: this means that the hooked PKCS#11 function will return with this value just after the hook execution.

If more than one hooking routine are defined for the same PKCS#11 function, the hooks are executed **in the order they are defined** inside 
the filter\_actions option. In this case, **the first hooking routine that returns something with (true, ...)** will stop the other hooks 
execution and makes the hooked function return with this value. This means that the other hooks and their return values are discarded.

If a "state" is necessary to keep track of actions of different hooks on the same PKCS#11 function, one will have to implement it through 
global variables for instance.

Two kind of user defined actions have been implemented:

  * **Early actions**: they are defined through the `filter_actions_pre` option. They are called **before** any filtering action at the 
very beginning of each hooked PKCS#11 function. This means that a user can, through early actions, **completely replace** the filter 
action on any given function with his defined actions, thus bypassing the genuine core engine process.
  * **Late actions**: they are defined through the `filter_actions_post` option. They are called **at the end** of filtering actions, generally 
just before the _real call_ to the backend. This means that other filtering actions (such as functions blocking, label and id filtering ...) 
have been processed when these user defined actions are executed. Hence, late actions are meant to define actions extending (i.e. complementing 
and 'living with') the actions that are already performed in the filter core engine.

### Code example

In order to add a custom hook, say `c_Login_hook`, one must first add the name of the hook in the **two custom action wrappers** 
defined in [src/filter/filter/filter_actions.ml](../src/filter/filter/filter_actions.ml):

```ocaml
(********* CUSTOM actions wrappers for the configuration file ******)
let execute_action action argument = match action with
  "c_Initialize_hook" -> c_Initialize_hook argument
| "c_Login_hook" -> c_Login_hook argument
| "identity" -> identity argument
| _ -> identity argument

let string_check_action a = match a with
  "c_Initialize_hook" -> a
| "c_Login_hook" -> a
| "identity" -> a
| _ -> let error_string = Printf.sprintf "Error: unknown action option '%s'!" a in 
                          netplex_log_critical error_string; raise Config_file_wrong_type
```

Then, the user must define the `c_Login_hook` **above** these custom wrappers so that it is define at this point of the 
source file. One could also add the custom hooks inside another OCaml module that would be included in 
[filter\_actions.ml](../src/filter/filter/filter_actions.ml).

```ocaml
let c_Login_hook arg =
  let (cksessionhandlet_, ckusertypet_, pin) = (deserialize arg) in
  if compare (Pkcs11.byte_array_to_string pin) "1234" = 0 then
    (* Passtrhough if pin is 1234 *)
    let s = Printf.sprintf " ######### Passthrough C_Login with pin %s!" 
            (Pkcs11.byte_array_to_string pin) in print_debug s 1;
    (serialize (false, ()))
  else
  begin
    (* Hook the call if pin != 1234 *)
    let s = Printf.sprintf " ######### Hooking C_Login with pin %s!" 
            (Pkcs11.byte_array_to_string pin) in print_debug s 1;
    let return_value = serialize (true, Pkcs11.cKR_PIN_LOCKED) in
    (return_value)
  end
```

Here are the important parts to notice for `c_Login_hook`:

  * It has exactly **one argument** `arg` that is unmarshaled through the `deserialize` function
  * The unmarshaled `arg` is then affected to the tuple `(cksessionhandlet_, ckusertypet_, pin)` whose elements 
exactly correspond to what the hooked PKCS#11 function C\_Login expects as arguments. These are the raw (meaning 
untouched) arguments received from the filter Frontend
  * Then, depending on the value of the PIN, either the couple `(false, ())` or the couple `(true, Pkcs11.cKR_PIN_LOCKED)`
are returned:
      * The couple `(false, ())` means that we do not want to override C\_Login return value: the PKCS#11 function will 
continue its execution and execute other elements of the filter
      * The couple `(true, Pkcs11.cKR_PIN_LOCKED)` means that we want C\_Login to stop its execution at the hook call 
while returning `Pkcs11.cKR_PIN_LOCKED` 

### The user defined actions limitations

Though the custom hooks system has been designed to be very flexible, its main issues come from this flexibility. The OCaml 
[marshaling module](http://caml.inria.fr/pub/docs/manual-ocaml/libref/Marshal.html) is indeed very powerful since it provides 
an easy way to define general purpose functions where the arguments and return values are evaluated at runtime. The two 
drawbacks are that:

  * The default OCaml marshaling module  is **not type-safe** since no type is carried with the marshaled data, meaning that 
no type-checking is performed during the unmarshaling. This can lead to uncaught exceptions during the unmarshal.
  * The user defined functions input and output values **must be handled with care**: there is no safety net if 
the user fails to properly write his function. The program might compile, but the function will - eventually silently - 
fail at runtime since it overrides OCaml's type inference at compile time. This is usually not the expected behaviour 
for OCaml written programs!

Improving the user defined hooks to be type-safe and avoid the use of marshaling is a **work in pogress**.


### Advanced examples of user defined actions

In order to illustrate the flexibility of the user extension system implemented in the filter, we provide 
patches that **fix the PKCS#11 API**. The API has been deeply analyzed during the last few years, leading 
to a formal model, an automated attack tool [Tookan](http://secgroup.dais.unive.it/projects/security-apis/tookan/) 
as well as a patched token reference implementation with [CryptokiX](http://secgroup.dais.unive.it/projects/security-apis/cryptokix/). 

Bortolozzo *et al.*, in their [ACM CCS 2010 paper](http://www.sigsac.org/ccs/CCS2010/paper_list.shtml), give a good overview of 
why PKCS#11 is not safe as is and how to properly fix it regarding their attacker model: see 
[here](http://secgroup.dais.unive.it/wp-content/uploads/2010/10/Tookan-CCS10.pdf) for more details on this.

We provide in [src/filter/filter/p11fix_patches](../src/filter/filter/p11fix_patches) patches that should enhance 
the security of the existing middlewares by using, among other patches, those implemented in [CryptokiX](http://secgroup.dais.unive.it/projects/security-apis/cryptokix/). These patches are defined as `filter_actions_post` functions since we want them to live with the other filter actions. **We will provide a detailed description of their action very soon**.

Please note that these patches are still in "beta test": they might evolve/be fixed in the future. They have only been 
tested with OpenCryptoki, but we plan to extend this soon.
