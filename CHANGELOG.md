# ChangeLog

## [Unreleased][unreleased]

## [1.0.9] - 2020-05-22
* Fix compilation for recent coccinelle versions
* MinGW fixes
* Travis-CI is now used
* Docker can be used to compile recent/older targets

## [1.0.8] - 2016-07-05
* OpenSSL 1.1.0 support (#23)
* Fix some Win32 compilation issues
* Improved support for TLS mutual auth when using Ocamlnet 4.x

## [1.0.7] - 2015-11-23
* Merge support for OCamlnet 4.x (#13)
* Fix uninstall target (#18), credits to louis@louisroche.net

## [1.0.6] - 2015-05-28
* Switch to MIT license for the project.

## [1.0.5] - 2015-04-17

### Security
* Ability to configure your own wrapping format key.

### Added
* Add key escrow filter to the engine.
* pkcs11proxyd can use PFS ciphersuites (#12).
* OCaml PKCS#11 bindings can be compiled separately with `--without-caml-crush`.
* Documentation of PKCS#11 patchsets.

### Changed
* Modify erroneous LICENSE.txt file to CeCILL-B.
* Switch back to GPLv2 pkcs11.h file.
* Remove dependency on des.h file, use CeCILL-B feature instead.
* TLS is now restricted to TLS1.2.
* ocaml-ssl 0.4.7 is required for TLS support.

### Fixed
* Various fixup to configure script.
* More robust slot aliasing.
* Do not exit when pkcs11proxyd cannot be reached (#4, contrib from Nikos Mavrogiannopoulos).

## [1.0.4] - 2014-12-02
### Changed
* Move debian directory to dedicated branch.

### Fixed
* Support installing client library in dedicated directory.

## [1.0.3] - 2014-11-20
### Added
* Various documentation improvements.
* Initial Debian package support.
* Improved Win32 support.
* Client library can fetch module alias from file.
* Add support for PKCS#11 v2.20 amendment 3.
* Add support for white listing of SSL clients on the server-side.
* Add support for setting multiple SSL server certificates on the client-side.
* Add support for using a custom RPC timeout value.

### Fixed
* Fix potential overflow in C to OCaml functions.
* correct conflicting attribute patch regarding.
* GnuTLS ressource deallocation issue.

[unreleased]: https://github.com/caml-pkcs11/caml-crush/compare/v1.0.9...HEAD
[1.0.9]: https://github.com/caml-pkcs11/caml-crush/compare/v1.0.8...v1.0.9
[1.0.8]: https://github.com/caml-pkcs11/caml-crush/compare/v1.0.7...v1.0.8
[1.0.7]: https://github.com/caml-pkcs11/caml-crush/compare/v1.0.6...v1.0.7
[1.0.6]: https://github.com/caml-pkcs11/caml-crush/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/caml-pkcs11/caml-crush/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/caml-pkcs11/caml-crush/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/caml-pkcs11/caml-crush/compare/v1.0.2...v1.0.3
