USE mysql;
START TRANSACTION;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_info;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_sha1;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_sha256;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_sha384;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_sha512;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_sha3;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_blake2b;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_argon2;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_scrypt;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_constant_time_compare;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_random;

CREATE FUNCTION lib_mysqludf_crypt_sha1 RETURNS STRING SONAME 'lib_mysqludf_crypt.so';
CREATE FUNCTION lib_mysqludf_crypt_sha256 RETURNS STRING SONAME 'lib_mysqludf_crypt.so';
CREATE FUNCTION lib_mysqludf_crypt_sha384 RETURNS STRING SONAME 'lib_mysqludf_crypt.so';
CREATE FUNCTION lib_mysqludf_crypt_sha512 RETURNS STRING SONAME 'lib_mysqludf_crypt.so';
CREATE FUNCTION lib_mysqludf_crypt_sha3   RETURNS STRING SONAME 'lib_mysqludf_crypt.so';
CREATE FUNCTION lib_mysqludf_crypt_blake2b RETURNS STRING SONAME 'lib_mysqludf_crypt.so';
CREATE FUNCTION lib_mysqludf_crypt_argon2 RETURNS STRING SONAME 'lib_mysqludf_crypt.so';
CREATE FUNCTION lib_mysqludf_crypt_scrypt RETURNS STRING SONAME 'lib_mysqludf_crypt.so';
CREATE FUNCTION lib_mysqludf_crypt_constant_time_compare RETURNS INT SONAME 'lib_mysqludf_crypt.so';
CREATE FUNCTION lib_mysqludf_crypt_random RETURNS INT SONAME 'lib_mysqludf_crypt.so';
CREATE OR REPLACE FUNCTION lib_mysqludf_crypt_base64_encode RETURNS STRING SONAME 'lib_mysqludf_crypt.so';
CREATE OR REPLACE FUNCTION lib_mysqludf_crypt_base64_decode RETURNS STRING SONAME 'lib_mysqludf_crypt.so';
COMMIT;