# lib_mysqludf_crypt

#### Description

This is a library for mysql or mariadb that provides cryptographic functions base64 en- and decoding.
This is done by loading the library and registering the function names as UDFs (User Defined Functions).
Those are then wrapped in small SQL functions to handle input and output.

The following hashing algorithms are provided:
* sha256
* sha384
* sha512
* sha3
* BLAKE2b

The following utility functions are provided:
* a function to get a variable amount of bytes from a CRNG in the botan library
* base64 encoding
* base64 decoding
* a function to print the library version
* a function for a constant time compare

The cryptographic library that is used is botan in version 2.0 or higher.
The library is built with GNU automake.

TODO:
* Implement ARGON2
* Implement SCRYPT

ARGON2 and SCRYPT are not provided by botan, so external libraries have to be used.

In the future, support for OpenSSL will probably be added at some point. The API to it is difficult to use from a UDF though, because there is no memory section passed between invocations of the UDFs, so everything would need to be done using gobal variables and that sucks.

#### Example Database

The library ships with an example database that shows the usage of the functions in a scenario where hashing and password authentication is done by the SQL server in order to prevent any other application from reading the secrets.

It can be found in the `sql-example-db` directory.

##### Functions

###### C functions provided directly to the SQL server


* lib_mysqludf_crypt_sha256
* lib_mysqludf_crypt_sha384
* lib_mysqludf_crypt_sha512
* lib_mysqludf_crypt_sha3
* lib_mysqludf_crypt_blake2b
* lib_mysqludf_crypt_constant_time_compare
* lib_mysqludf_crypt_base64_encode
* lib_mysqludf_crypt_base64_decode