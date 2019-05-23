DROP DATABASE IF EXISTS MYSQLUDF_CRYPT_DB;
CREATE DATABASE 'mysqludf_crypt_db' DEFAULT CHARACTER SET 'utf8';
CREATE TABLE 'users' (PRIMARY KEY BIGINT 'user_id', UNIQUE KEY 'user_name' VARCHAR2 NOT NULL);
CREATE TABLE 'email_addresses' (PRIMARY KEY BIGINT 'email_id', VARCHAR2 email_address);
CREATE TABLE 'passwords' (PRIMARY KEY BIGINT 'user_id', VARCHAR2 'salt' NOT NULL, VARCHAR2 'password_hash' NOT NULL, VARCHAR2 'algorithm' NOT NULL,
);

CREATE TABLE 'secret_data' (PRIMARY KEY BIGINT 'data_id', FOREIGN KEY BIGINT 'user_id', 'secret_data' VARCHAR2 NOT NULL);

DELIMITER //;
CREATE DEFINER=admin_user FUNCTION change_password (VARCHAR2 'user_name', VARCHAR2 'old_password', VARCHAR2 'new_password') RETURNS BOOLEAN NOT DETERMINISTIC MODIFIES SQL DATA SQL SECURITY DEFINER RETURN
SET autocommit=0;
START TRANSACTION;

SELECT passwords.password_hash, passwords.salt, passwords.algorithm
    INTO old_hash, salt, algo
    FROM passwords LEFT JOIN users ON users.user_id = passwords.user_id
    WHERE users.user_name = user_name LIMIT 1;

SELECT MYSQLUDF_CRYPT_MULTIHASH(algo, old_password, salt)() INTO new_hash;

if algo = "sha256"
IF MYSQLUDF_CRYPT_CONSTANT_TIME_COMPARE(old_hash, new_hash)
THEN
    # set new password, return true
    SET_PASSWORD(algo, user_id, new_password, );
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


DELIMITER //;
CREATE DEFINER=admin_user FUNCTION check_password(VARCHAR2 user_name, VARCHAR2 password) RETURNS BOOLEAN NOT DETERMINISTIC SQL SECURITY DEFINER RETURN
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
CREATE DEFINER=admin_user FUNCTION add_email(VARCHAR2 user_name, VARCHAR2 email_address RETURNS BOOLEAN NOT DETERMINISTIC SQL SECURITY DEFINER RETURN
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
CREATE FUNCTION UDF_SHA256(VARCHAR2 salt, VARCHAR2 password) RETURNS VARCHAR2 DETERMINISTIC RETURN
RETURN lib_mysqludf_crypt_sha256(CONCAT(salt, password));
END
//
DELIMITER //
CREATE FUNCTION UDF_SHA384(VARCHAR2 salt, VARCHAR2 password) RETURNS VARCHAR2 DETERMINISTIC RETURN
RETURN lib_mysqludf_crypt_sha384(CONCAT(salt, password));
END
//
DELIMITER //
CREATE FUNCTION UDF_SHA512(VARCHAR2 salt, VARCHAR2 password) RETURNS VARCHAR2 DETERMINISTIC RETURN
RETURN lib_mysqludf_crypt_sha512(CONCAT(salt, password));
END
//
DELIMITER //
CREATE FUNCTION UDF_SHA3(VARCHAR2 salt, VARCHAR2 password) RETURNS VARCHAR2 DETERMINISTIC RETURN
RETURN lib_mysqludf_crypt_sha3(CONCAT(salt, password));
END
//
DELIMITER //
CREATE FUNCTION UDF_BLAKE2(VARCHAR2 salt, VARCHAR2 password) RETURNS VARCHAR2 DETERMINISTIC RETURN
RETURN lib_mysqludf_crypt_blake2(CONCAT(salt, password));
END
//
DELIMITER //
CREATE FUNCTION UDF_ARGON2(VARCHAR2 salt, VARCHAR2 password) RETURNS VARCHAR2 DETERMINISTIC RETURN
RETURN lib_mysqludf_crypt_argon2(CONCAT(salt, password));
END
//
DELIMITER //
CREATE FUNCTION UDF_SCRYPT(VARCHAR2 salt, VARCHAR2 password) RETURNS VARCHAR2 DETERMINISTIC RETURN
RETURN lib_mysqludf_crypt_scrypt(CONCAT(salt, password));
END
//
