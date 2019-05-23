USE mysql;

DROP FUNCTION IF EXISTS lib_mysqludf_crypt_info;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_sha256;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_sha384;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_sha512;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_sha3;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_blake2;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_argon2;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_scrypt;

CREATE FUNCTION lib_mysqludf_crypt_sha256 RETURNS STRING SONAME 'lib_mysqludf_crypt.so';
CREATE FUNCTION lib_mysqludf_crypt_sha384 RETURNS STRING SONAME 'lib_mysqludf_crypt.so';
CREATE FUNCTION lib_mysqludf_crypt_sha512 RETURNS STRING SONAME 'lib_mysqludf_crypt.so';
CREATE FUNCTION lib_mysqludf_crypt_sha3   RETURNS STRING SONAME 'lib_mysqludf_crypt.so';
CREATE FUNCTION lib_mysqludf_crypt_blake2 RETURNS STRING SONAME 'lib_mysqludf_crypt.so';
CREATE FUNCTION lib_mysqludf_crypt_argon2 RETURNS STRING SONAME 'lib_mysqludf_crypt.so';
CREATE FUNCTION lib_mysqludf_crypt_scrypt RETURNS STRING SONAME 'lib_mysqludf_crypt.so';
CREATE FUNCTION lib_mysqludf_crypt_constant_time_compare RETURNS INT SONAME 'lib_mysqludf_crypt.so';