USE mysql;

DROP FUNCTION IF EXISTS lib_mysqludf_crypt_info;
CREATE FUNCTION lib_mysqludf_crypt_info RETURNS STRING SONAME 'lib_mysqludf_crypt.so';
