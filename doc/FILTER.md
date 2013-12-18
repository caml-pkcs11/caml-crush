# Caml Crush: an OCaml PKCS#11 filtering proxy

## PKCS#11 proxy filter module details


The following documentation is about the PKCS#11 filter logics 
and the filtering rules syntax.

The PKCS#11 filter is written in OCaml, and the rules syntax 
also use OCaml style expressions (the configuration module 
uses the OCaml [config-file][] package).

Back to [INDEX.md](INDEX.md).

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
  * **filter\_actions** =  [(a1, b1), (a2, b2) ...] is a **list** of **couples** where 'a' is a regular expression string representing 
module names, and 'b1', 'b2', ... are **lists** of **couples** (c, d) where 'c' is a PKCS#11 function following the PKCS#11 
naming convention (C\_Login, C\_Logout ...) and 'd' is an OCaml function name defined in /src/filter/filter/filter\_actions.ml 
(it is a user defined action to be triggered when the PKCS#11 function 'c' is called, see below for more details)

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

    debug = 3

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
 
    modules = [ ("softhsm", "/usr/lib/libsofthsm.so"), 
                ("opensc", "/usr/lib/opensc-pkcs11.so") ]

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

    allowed_labels = [ ("\\(sofths.*\\|opencryptoki\\)", ["MYLABEL.*", "LABEL_EXACT"]), 
                       ("softhsm", [".*THE_LABEL", "mytes.*"]) ]

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

    allowed_ids = [ ("softhsm.*", ["0123.*"]) ]

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

    forbidden_mechanisms = [ ("sof.*", [CKM_RSA_PKCS, CKM_MD5_RSA_PKCS]), 
                             ("softhsm", [CKM_DES_ECB]) ]

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

    [CKM_RSA_PKCS; CKM_MD2_RSA_PKCS; CKM_MD5_RSA_PKCS; CKM_SHA1_RSA_PKCS; CKM_RIPEMD128_RSA_PKCS; 
     CKM_RIPEMD160_RSA_PKCS; CKM_SHA256_RSA_PKCS; CKM_SHA384_RSA_PKCS; CKM_SHA512_RSA_PKCS; CKM_RC2_CBC_PAD; 
     CKM_DES_CBC_PAD; CKM_DES3_CBC_PAD; CKM_CDMF_CBC_PAD; CKM_CAST_CBC_PAD; CKM_CAST3_CBC_PAD; 
     CKM_CAST5_CBC_PAD; CKM_CAST128_CBC_PAD; CKM_RC5_CBC_PAD; CKM_IDEA_CBC_PAD; CKM_AES_CBC_PAD]

Syntax example:

    remove_padding_oracles = [ (".*", [wrap, unwrap, encrypt]), 
                               ("softhsm", [sign]) ]

> There is no default value for remove\_padding\_oracles. As for the forbidden\_mechanisms option, a logical 
> **AND** is applied when a module is covered by different rules: the "softhsm" module will have "wrap", "unwrap" 
> and "encrypt" forbidden because of the first rule, and "sign" forbidden with the second rule.


## Filtering PKCS#11 functions options
  * **forbidden\_functions** (*list of couples of [string_regexp x list of PKCS#11_function]*):
    * This option blocks any PKCS#11 function defined in the standard by returning CKR\_FUNCTION\_NOT\_SUPPORTED. 
The PKCS#11 function names must **exactly correspond** to the ones used in the standard API, such as C\_Login, C\_Wrap, ...

Syntax example:

    forbidden_functions  = [ ("soft.*", [C_Login, C_Logout]), 
                             ("softhsm", [C_Sign]) ]

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

    enforce_ro_sessions  = [ ("soft.*", no), 
                             ("opencryptoki", yes) ]

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
values to express the boolean decision of enforcing or not RO sessions are: **yes** and **no** or **true** and **false**.

Syntax example:
    
    forbid_admin_operations = [ (".*", yes) ]

> The default value for forbid\_admin\_operations is "no" (meaning that if there is no rule associated to a module,
> the SO operations are **allowed**). The previous rule enforces **blocking the SO operations** on all the modules 
> (thanks to the regexp ".\*" matching all the modules).

## Adding user defined actions
  * **filter\_actions** (*list of couples of [string_regexp x list of couples of [PKCS#11_function x custom_function]]*):
    * This option is a way to **extend** the filter features as the user can provide its own hooks on every PKCS#11 
function. In order to apply an action "Action" triggered by a call to a PKCS#11 function, says C\_Login, a couple 
(C\_Login, Action) is defined in the filter\_actions option. For the sake of simplicity, these hooks have been 
gathered inside one file in the filter source tree (*src/filter/filter/filter_actions.ml*).

Syntax example:
    
    filter_actions = [ (".*", [(C_Login, c_Login_hook), (C_Initialize, c_Initialize_hook)]),
                       ("soft.*", [(C_CloseSession, identity)]) ]

> There is no default value for filter\_actions. The previous rule will execute the user defined c\_Login\_hook when 
> C\_Login is called for all the modules, the identity user defined function when C\_CloseSession is called for 
> "soft.\*" regexp module aliases ("softhsm" for instance), and so on ...

**TODO**: explain the details of how to add a custom function.
