# Performing tests
We provide a few ways to manually validate the behavior of a library implementing the
PKCS#11 standard. In particular, it allows to check that the proxy actually
performs the filtering actions that it is meant to implement.

## Contents of directory src/tests/ocaml

In this directory one can find : 
> 1 ] a configuration file pkcs11.conf allowing to configure which library to use to carry out the tests;

> 2 ] a few programs for testings general functionalities of the token :
	 
>- destroy.ml allows to destroy all objetcs on the token
>- digest_test.ml, encdec_test.ml, test_pkcs11.ml and wrap_unwrap.ml allow to perform various cryptographic operations

> 3 ] a quite generic way of testing a sequence of operations, and in particular
to 'manually' carry out tests of the token resilience to well-known API-level vulnerabilities.
Classic scenarios are already encoded, the details follow.

## Quickstart 

> 0 ] To test the proxy, get a daemon running in foreground mode : 

	/usr/local/bin/pkcs11proxyd -fg -conf /usr/local/etc/pkcs11proxyd/pkcs11proxyd.conf

Hence, you can observe which calls and tests are filtered and why. 


> 1 ] Open the file pkcs11.conf and set the variable Libname to
> the library you want to test, and the PIN code as appropriate.
> E.g. to test the client library for the proxy, and it is named /usr/local/lib/libp11clientfoo.so
> then you should set :

	Libname = "../../client-lib/libp11clientfoo.so"	

> 2 ] Build the tests by typing:

	make

> 3 ]  Execute the generic scenario parser on one of the test scenarios listed below by typing :

	./generic_scenario.opt < name_of_the_test_scenario >

e.g. if your test scenario is encoded in the file get_sensitive_key.ml

	./generic_scenario.opt get_sensitive_key

Choices of scenarios are amongst : get_sensitive_key, wrap_and_decrypt_1 to wrap_and_decrypt_4, 
encrypt_and_unwrap, sensitive_is_sticky, extractable_is_sticky, create_object_1 and create_object_2,
double_unwrap, misc_scenario.

Each scenario file, which is named as the test scenario and suffixed by .ml, contains
as a commentary an explanation of the test carried out.

> 4 ] You can destroy the objects created on your token by the tests by using

	./destroy.opt

## Understanding the generic test scenarios 


### A ] Constituents 
- File p11_for_generic.ml contains all the material to carry out
test scenarios written in other files. 
- File generic_scenario.ml contains the code related to the generation
of a key_to_leak and the mechanisms to test. 
- Files containing test scenarios (and only that) are : 

	* get_sensitive_key.ml
	* wrap_and_decrypt_1.ml to wrap_and_decrypt_4.ml
	* encrypt_and_unwrap.ml
	* sensitive_is_sticky.ml
	* extractable_is_sticky.ml
	* create_object_1.ml and create_object_2.ml 
	* double_unwrap.ml
	* misc_scenario.ml

- Usage : 

	./generic_scenario.opt < name_of_the_test_scenario >

e.g. if your test scenario is encoded in the file get_sensitive_key.ml

	 ./generic_scenario.opt get_sensitive_key

### B ] The pseudo-language used to describe test scenarios.

A little "encoding language" for test scenarios
can be used to put to test different strategies. 
It can be extended at will. 

A test scenario is executed given two global parameter : a key_to_leak
and a mechanism mech. When beginning the execution of a test scenario, 
we suppose the token is initialized, supports mechanism mech, and that
key_to_leak is a key usable with this mechanism mech. 
For the time being, only symmetric mechanisms are supported.
 
**TO CHANGE MECHANISMS INVOLVED, UPDATE VARIABLE symmetric_mechs_tested IN p11_for_generic.ml.
By default, it contains all the mechanisms that can be tested for the time being.
HOWEVER, ONLY THE LAST MECHANISM FOR WHICH THE GENERATION SUCCEEDED WILL BE TESTED.
The test scenario is processed using the last mechanism for which the key generation
of key_to_leak succeeds.**

In the mini-language, a test scenario
is encoded as a sequence of pairs of a named template and an opcode, where : 

- a **named template** is a pair of a name
and a template, which is an array of attributes (types and values).
Namely, the name is of type string, and is just featured
to be concatenated to labels for keys potentially created in the token
with attributes matching the template. 
Examples of valid named templates : 

		1- ("token_wd",  [|{ Pkcs11.type_ =Pkcs11.cKA_TOKEN ; Pkcs11.value = Pkcs11.true_ }|])
	
		2- ("empty", [||] )

- an **opcode** is a code of one of the following forms :
	
		type opcode =  W | D | G |  E | GKTL | 
	 		U of (Pkcs11.ck_attribute array) | C of (Pkcs11.ck_attribute array) | 
		 	DoubleU of (Pkcs11.ck_attribute array * Pkcs11.ck_attribute array) | S | F | WW

An opcode is encoding a particular PKCS#11 operation, which is applied to a local state carrying 
along our scenario the elements that we might need.

Before detailing the operations performed by each opcode, let us define these local "states",
which are of the type scenario_state defined below. 

	type previous_result_needed = Empty | Hdl of Pkcs11.ck_object_handle_t | Bitstring of char array 

	type scenario_state = previous_result_needed * Pkcs11.ck_object_handle_t * (Pkcs11.ck_attribute list)
	(* ck_object_handle contains the key generated at the beginning of the scenario
	to perform crypto afterwards *)

Hence, a scenario_state is a triple of : 

- the result of the previous operations (which can be nothing (Empty),
a handle (encoded as Hdl(<some_handle_value>)) or a bitstring (encoded
as Bitstring(<some char array here>)).
- the handle of the 'operative' key, which is (generally) used in the operation
encoded by the opcode
- an attribute list possibly useful to carry through our computations.

### C ] Execution of the scenario 

Now that we know what info is carried along in a state, let us
see how a scenario is processed. 


####I - Initialisation : 
  the init_action function is meant to create and initialize a scenario state to use in the
  test scenario. Indeed, it aims at creating a handle to a key with 
  the attributes set to values as specified by attr_templates. 
  In other words, the first named template in a scenario will result in the creation
  of a key conforming to this template, and a handle to this key is stored in
  the 'middle' component of the output scenario state. 
  The key is meant for the mechanism 'mech' (globally used as a parameter of the scenario_parser
  function).
  To perform the key generation, two strategies are tried : generating the key 
  with the right attributes in one step, or setting them progressively.


####II - Processing of one step : 
-1/ given as input a scenario state, we try to set one by one 
   the attributes in attr_template on the key refered by the handle
   obj_hdl.

2/ the operation encoded by the opcode is carried out.

- the W opcode : 
  Input : (prev_res, obj_hdl, _)
  corresponds to a wrap operation of key_to_leak,carried out
  using the mechanism mech (with null parameter of the right size)
  passed a global argument to the scenario_parser.
  --> if prev_res is a handle, this latter is used to wrap;
  --> otherwise, the handle obj_hdl (middle component of scenario state)
  is used. 
  Output : (wrapped value, obj_hdl, [])  

- the D opcode : 
  Input : (prev_res, obj_hdl, ck_attr_list)
  --> if prev_res of the form Bitstring(bs), decrypts bs and prints it out.
  Output : None

- the GKTL opcode : 
  prints out the valueof key_to_leak (the global argument of scenario_parser); 
  leaves myscenariostate unchanged 

- the G opcode : 
  Input : Some(Hdl(other_hdl),obj_hdl,ck_attr_list)
  prints out the value of (the key refered to by) other_hdl,  
  leaves the scenario state unchanged.

- the E opcode : 
  Input : Some(prev_res, obj_hdl, ck_attr_list))
  encrypts (the right number of) zeroes with 
  --> if prev_res is of the form Hdl(other_hdl), other_hdl 
  --> obj_hdl otherwise
  Stores the resulting bitstring in the "previous result" filed of the state, 
  and sets the second component of the state to obj_hdl.	  

- the U(attr_template) opcode : 
  Input : Some(Bitstring(bs), obj_hdl, ck_attr_list)) 	
  unwraps ciphertext with obj_hdl and attributes attr_template.
  In case of success, the resulting handle is stored in the first component of the scenario state,
  second component is the obj_hdl used to unwrap.

- the C(attr_template) opcode : 
  Creates a secret key worth (an adequate number of) zeroes, corresponding 
to the mechanism 'mech'. In case of success, the resulting handle is 
is stored in the first component of the scenario state output. Rest
of the state remains unchanged.  

- the DoubleU(attr_template, attr_template2) opcode : 
  Input : Some(Bitstring(bs), obj_hdl, ck_attr_list)) 	
  unwraps *twice* ciphertext with obj_hdl, firstly with attributes in attr_template, 
  secondly with attributes in attr_template2.
  In case of success, the handle resulting from the first (resp.second) 
  unwrap is stored in the first (resp. second) 
  component of the resulting scenario state.

- S opcode : skips (useful if the named template associated is non-empty)

- F opcode : 
  "forwards" a handle in the first component of the scenario state to the second component.
  Namely, turns Some(Hdl(hdl), obj_hdl, ck_attr_list) into  Some(Empty, hdl, ck_attr_list).

- WW opcode : 
  input : Some(Hdl(other_hdl), obj_hdl, ck_attr_array)
  wraps the (key refered to by) handle other_hdl (first component of the state) 
  using obj_hdl (second component of the state).  

