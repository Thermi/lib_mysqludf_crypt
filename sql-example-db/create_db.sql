DROP DATABASE IF EXISTS MYSQLUDF_CRYPT_DB;
CREATE DATABASE 'mysqludf_crypt_db' DEFAULT CHARACTER SET 'utf8';
CREATE TABLE 'users' (PRIMARY KEY BIGINT 'user_id', UNIQUE KEY 'user_name' VARCHAR NOT NULL);
CREATE TABLE 'email_addresses' (PRIMARY KEY BIGINT 'email_id', VARCHAR email_address);
CREATE TABLE 'passwords' (PRIMARY KEY BIGINT 'user_id', VARCHAR 'salt' NOT NULL, VARCHAR 'password_hash' NOT NULL, VARCHAR 'algorithm' NOT NULL,
);

CREATE TABLE 'secret_data' (PRIMARY KEY BIGINT 'data_id', FOREIGN KEY BIGINT 'user_id', 'secret_data' VARCHAR NOT NULL);

DELIMITER //;
CREATE DEFINER=admin_user FUNCTION change_password (VARCHAR 'user_name', VARCHAR 'old_password', VARCHAR 'new_password') RETURNS BOOLEAN NOT DETERMINISTIC MODIFIES SQL DATA SQL SECURITY DEFINER RETURN
SET autocommit=0;
START TRANSACTION;

SELECT passwords.password_hash, passwords.salt, passwords.algorithm
    INTO old_hash, salt, algo
    FROM passwords LEFT JOIN users ON users.user_id = passwords.user_id
    WHERE users.user_name = user_name LIMIT 1;

SELECT MYSQLUDF_CRYPT_MULTIHASH(algo, salt, old_password)() INTO new_hash;

if algo = "sha256"
IF MYSQLUDF_CRYPT_CONSTANT_TIME_COMPARE(old_hash, new_hash)
THEN
    # set new password, return true
    SET_PASSWORD(algo, user_id, new_password);
    COMMIT;
    RETURN TRUE;
END IF;
# fail, return false
BAR
BALL
ROLLBACK;
RETURN FALSE;
END
//

DELIMITER //
CREATE DEFINER=admin_user FUNCTION change_password(VARCHAR2 algo, BIGINT user_id, VARCHAR password) RETURNS BOOLEAN NOT DETERMINISTIC SQL SECURITY DEFINER RETURN
# Get new salt from CRNG (botan lib function)
# calculate new hash, ...
# UPDATE and so on
//

DELIMITER //
CREATE FUNCTION MYSQLUDF_CRYPT_MULTIHASH(VARCHAR algo, VARCHAR salt, VARCHAR password) RETURNS STRING NOT DETERMINISTIC RETURN
IF      algo == "SHA-256"
THEN
    RETURN UDF_SHA256(salt, password);
ELSE IF algo == "SHA-384"
THEN
    RETURN UDF_SHA384(salt, password);
ELSE IF algo == "SHA-512"
THEN
    RETURN UDF_SHA512(salt, password);
ELSE IF algo == "BLAKE2b"
THEN
    RETURN UDF_BLAKE2B(salt, password);
ELSE IF algo == "ARGON2"
THEN
    RETURN UDF_ARGON2(salt, password);
ELSE IF algo == "SCRYPT"
THEN
    RETURN UDF_SCRYPT(salt, password);
END IF;
END
//

DELIMITER //;
CREATE DEFINER=admin_user FUNCTION check_password(VARCHAR user_name, VARCHAR password) RETURNS BOOLEAN NOT DETERMINISTIC SQL SECURITY DEFINER RETURN
SELECT passwords.password_hash, passwords.salt, passwords.algorithm
    INTO old_hash, salt, algo
    FROM passwords LEFT JOIN users ON users.user_id = passwords.user_id
    WHERE users.user_name = user_name LIMIT 1;
SELECT MYSQLUDF_CRYPT_MULTIHASH(algo, password, salt)() INTO new_hash;
IF MYSQLUDF_CRYPT_CONSTANT_TIME_COMPARE(old_hash, new_hash)
THEN
    RETURN TRUE;
END IF;
RETURN FALSE;
END
//

DELIMITER //
CREATE DEFINER=admin_user FUNCTION add_email(VARCHAR user_name, VARCHAR email_address RETURNS BOOLEAN NOT DETERMINISTIC SQL SECURITY DEFINER RETURN
# join users and email_addresses
SELECT user_id INTO user_id
    FROM users
    WHERE user_name = user_name LIMIT 1;

SELECT email_address INTO email_addresses
    FROM email_addresses
    WHERE user_id = user_id;

# 
# add email_address
# COMMIT
RETURN FALSE;
END
//

DELIMITER //
CREATE FUNCTION UDF_SHA256(VARCHAR salt, VARCHAR password) RETURNS VARCHAR DETERMINISTIC RETURN
RETURN lib_mysqludf_crypt_sha256(CONCAT(salt, password));
END
//
DELIMITER //
CREATE FUNCTION UDF_SHA384(VARCHAR salt, VARCHAR password) RETURNS VARCHAR DETERMINISTIC RETURN
RETURN lib_mysqludf_crypt_sha384(CONCAT(salt, password));
END
//
DELIMITER //
CREATE FUNCTION UDF_SHA512(VARCHAR salt, VARCHAR password) RETURNS VARCHAR DETERMINISTIC RETURN
RETURN lib_mysqludf_crypt_sha512(CONCAT(salt, password));
END
//
DELIMITER //
CREATE FUNCTION UDF_SHA3(VARCHAR salt, VARCHAR password) RETURNS VARCHAR DETERMINISTIC RETURN
RETURN lib_mysqludf_crypt_sha3(CONCAT(salt, password));
END
//
DELIMITER //
CREATE FUNCTION UDF_BLAKE2B(VARCHAR salt, VARCHAR password) RETURNS VARCHAR DETERMINISTIC RETURN
RETURN lib_mysqludf_crypt_blake2b(CONCAT(salt, password));
END
//
DELIMITER //
CREATE FUNCTION UDF_ARGON2(VARCHAR salt, VARCHAR password) RETURNS VARCHAR DETERMINISTIC RETURN
RETURN lib_mysqludf_crypt_argon2(CONCAT(salt, password));
END
//
DELIMITER //
CREATE FUNCTION UDF_SCRYPT(VARCHAR salt, VARCHAR password) RETURNS VARCHAR DETERMINISTIC RETURN
RETURN lib_mysqludf_crypt_scrypt(CONCAT(salt, password));
END
//
DELIMITER //
CREATE FUNCTION UDF_RAND(INT random_bytes_number) RETURNS VARCHAR NOT DETERMINISTIC RETURN
RETURN lib_mysqludf_crypt_rand(random_bytes_number);
END
//
DELIMITER //
CREATE FUNCTION UDF_BASE64_ENCODE(VARCHAR input) RETURNS VARCHAR DETERMINISTIC RETURN
RETURN lib_mysqludf_crypt_base64_encode(input);
END
//
DELIMITER //
CREATE FUNCTION UDF_BASE64_DECODE(VARCHAR input) RETURNS VARCHAR DETERMINISTIC RETURN
RETURN lib_mysqludf_crypt_base64_decode(input);
END
//