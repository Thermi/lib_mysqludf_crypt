USE mysql;

DROP FUNCTION IF EXISTS lib_mysqludf_crypt_info;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_sha1;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_sha256;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_sha384;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_sha512;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_sha3;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_blake2;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_argon2;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_scrypt;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_constant_time_compare;
DROP FUNCTION IF EXISTS lib_mysqludf_crypt_random;