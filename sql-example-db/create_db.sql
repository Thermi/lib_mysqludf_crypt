SET @@SQL_MODE = CONCAT(@@SQL_MODE, ',STRICT_ALL_TABLES');

CREATE OR REPLACE DATABASE mysqludf_crypt_db DEFAULT CHARACTER SET = 'utf8' DEFAULT COLLATE = 'utf8_general_ci';

USE mysqludf_crypt_db;

CREATE TABLE users (user_id BIGINT UNSIGNED AUTO_INCREMENT, user_name VARCHAR(256) NOT NULL, PRIMARY KEY (user_id), UNIQUE KEY (user_name));
CREATE TABLE email_addresses (email_id BIGINT PRIMARY KEY AUTO_INCREMENT NOT NULL , user_id BIGINT UNSIGNED, email_address VARCHAR(256),
    CONSTRAINT fk_email_addresses_user_id FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE ON UPDATE RESTRICT);

CREATE TABLE passwords (user_id BIGINT UNSIGNED, salt VARCHAR(1024) NOT NULL, password_hash VARCHAR(1024) NOT NULL, algorithm VARCHAR(64) NOT NULL, PRIMARY KEY (user_id),
    CONSTRAINT fk_passwords_user_id FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE ON UPDATE RESTRICT);

CREATE TABLE secret_data (data_id BIGINT UNSIGNED AUTO_INCREMENT, user_id BIGINT UNSIGNED, secret_data VARCHAR(1024) NOT NULL, PRIMARY KEY (data_id),
    CONSTRAINT fk_secret_data_user_id FOREIGN KEY (user_id) REFERENCES users (user_id));

CREATE OR REPLACE USER 'application'@'localhost' IDENTIFIED BY 'abcde';
#CREATE USER 'admin_user'@'localhost' ACCOUNT LOCK;
CREATE OR REPLACE USER 'admin_user'@'localhost' IDENTIFIED BY PASSWORD '11111111111111111111111111111111111111111';

DELIMITER //
CREATE OR REPLACE FUNCTION UDF_SHA256 (salt VARCHAR, password VARCHAR) RETURNS VARCHAR(256) DETERMINISTIC
RETURN lib_mysqludf_crypt_sha256(CONCAT(salt, password));
END //

CREATE OR REPLACE FUNCTION UDF_SHA384 (VARCHAR salt, VARCHAR password) RETURNS VARCHAR DETERMINISTIC
RETURN lib_mysqludf_crypt_sha384(CONCAT(salt, password));
END
//

CREATE OR REPLACE FUNCTION UDF_SHA512 (VARCHAR salt, VARCHAR password) RETURNS VARCHAR DETERMINISTIC
RETURN lib_mysqludf_crypt_sha512(CONCAT(salt, password));
END
//

CREATE OR REPLACE FUNCTION UDF_SHA3 (VARCHAR salt, VARCHAR password) RETURNS VARCHAR DETERMINISTIC
RETURN lib_mysqludf_crypt_sha3(CONCAT(salt, password));
END
//

CREATE OR REPLACE FUNCTION UDF_BLAKE2B (VARCHAR salt, VARCHAR password) RETURNS VARCHAR DETERMINISTIC
RETURN lib_mysqludf_crypt_blake2b(CONCAT(salt, password));
END
//

CREATE OR REPLACE FUNCTION UDF_ARGON2 (VARCHAR salt, VARCHAR password) RETURNS VARCHAR DETERMINISTIC
RETURN lib_mysqludf_crypt_argon2(CONCAT(salt, password));
END
//

CREATE OR REPLACE FUNCTION UDF_SCRYPT (VARCHAR salt, VARCHAR password) RETURNS VARCHAR DETERMINISTIC
RETURN lib_mysqludf_crypt_scrypt(CONCAT(salt, password));
END
//

CREATE OR REPLACE FUNCTION UDF_RAND (INT random_bytes_number) RETURNS VARCHAR NOT DETERMINISTIC
RETURN lib_mysqludf_crypt_rand(random_bytes_number);
END
//

CREATE OR REPLACE FUNCTION UDF_BASE64_ENCODE (VARCHAR input) RETURNS VARCHAR DETERMINISTIC
RETURN lib_mysqludf_crypt_base64_encode(input);
END
//

CREATE OR REPLACE FUNCTION UDF_BASE64_DECODE (VARCHAR input) RETURNS VARCHAR DETERMINISTIC
RETURN lib_mysqludf_crypt_base64_decode(input);
END
//
DELIMITER ;

# application user can only use predefined functions to interact with sensitive data

GRANT EXECUTE ON change_password TO application;
GRANT EXECUTE ON check_password TO application;
GRANT EXECUTE ON add_mail TO application;

# admin_user needs the privileges that the functions that are run as this user need
GRANT SELECT,DELETE,INSERT,UPDATE ON users TO admin_user;
GRANT SELECT,DELETE,INSERT ON email_addresses TO admin_user;
GRANT SELECT,INSERT,UPDATE ON passwords TO admin_user;
GRANT EXECUTE ON UDF_SHA256 TO admin_user;
GRANT EXECUTE ON UDF_SHA384 TO admin_user;
GRANT EXECUTE ON UDF_SHA512 TO admin_user;
GRANT EXECUTE ON UDF_SHA3 TO admin_user;
GRANT EXECUTE ON UDF_BLAKE2b TO admin_user;
GRANT EXECUTE ON UDF_ARGON2 TO admin_user;
GRANT EXECUTE ON UDF_SCRYPT TO admin_user;
GRANT EXECUTE ON UDF_RAND TO admin_user;
GRANT EXECUTE ON UDF_BASE64_ENCODE TO admin_user;
GRANT EXECUTE ON UDF_BASE64_DECODE TO admin_user;
GRANT EXECUTE ON lib_mysqludf_crypt_sha256;
GRANT EXECUTE ON lib_mysqludf_crypt_sha384;
GRANT EXECUTE ON lib_mysqludf_crypt_sha512;
GRANT EXECUTE ON lib_mysqludf_crypt_sha3;
GRANT EXECUTE ON lib_mysqludf_crypt_blake2b;
GRANT EXECUTE ON lib_mysqludf_crypt_argon2;
GRANT EXECUTE ON lib_mysqludf_crypt_scrypt;
GRANT EXECUTE ON lib_mysqludf_crypt_rand;
GRANT EXECUTE ON lib_mysqludf_crypt_base64_encode;
GRANT EXECUTE ON lib_mysqludf_crypt_base64_decode;

DELIMITER //;
CREATE DEFINER=admin_user FUNCTION change_password (VARCHAR 'user_name', VARCHAR 'old_password', VARCHAR 'new_password') RETURNS BOOLEAN NOT DETERMINISTIC MODIFIES SQL DATA SQL SECURITY DEFINER RETURN
SET autocommit=0;
START TRANSACTION;

SELECT passwords.password_hash, passwords.salt, passwords.algorithm
    INTO old_hash, salt, algo
    FROM passwords LEFT JOIN users ON users.user_id = passwords.user_id
    WHERE users.user_name = user_name LIMIT 1;

SELECT MYSQLUDF_CRYPT_MULTIHASH(algo, salt, old_password) INTO new_hash;

if algo = "sha256"
IF MYSQLUDF_CRYPT_CONSTANT_TIME_COMPARE(old_hash, new_hash)
THEN
    # set new password, return true
    SET_PASSWORD(algo, user_id, new_password);
    COMMIT;
    RETURN TRUE;
END IF;
SIGNAL SQLSTATE '45000' MESSAGE_TEXT='Given password does not match.';
# fail, return false

ROLLBACK;
RETURN FALSE;
END
//

DELIMITER //
CREATE DEFINER=admin_user FUNCTION set_password(VARCHAR2 algo, BIGINT user_id, VARCHAR password) RETURNS BOOLEAN NOT DETERMINISTIC SQL SECURITY DEFINER RETURN
SELECT INTO salt UDF_RAND(128);
SELECT INTO hash MYSQLUDF_CRYPT_MULTIHASH(algo, salt, password);
UPDATE passwords SET salt = salt, password_hash = hash, algo = algo WHERE user_id = user_id;
//

DELIMITER //
CREATE OR REPLACE FUNCTION MYSQLUDF_CRYPT_MULTIHASH(VARCHAR algo, VARCHAR salt, VARCHAR password) RETURNS STRING NOT DETERMINISTIC RETURN
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

SIGNAL SQLSTATE '45000' MESSAGE_TEXT 'Given hash method is not supported';
RETURN NULL;
END
//

DELIMITER //
CREATE DEFINER=admin_user FUNCTION check_user_exists(VARCHAR user_name) RETURNS BOOLEAN SQL SECURITY DEFINER RETUZRN
IF COUNT(SELECT COUNT(*) FROM users WHERE username = user_name;) == 1;
THEN
    RETURN TRUE;
ELSE
    RETURN FALSE;
END IF;
//

DELIMITER //;
CREATE DEFINER=admin_user FUNCTION check_password(VARCHAR user_name, VARCHAR password) RETURNS BOOLEAN NOT DETERMINISTIC SQL SECURITY DEFINER RETURN
IF ! check_user_exists(user_name)
THEN
    RETURN FALSE;
END IF;

SELECT passwords.password_hash, passwords.salt, passwords.algorithm
    INTO old_hash, salt, algo
    FROM passwords LEFT JOIN users ON users.user_id = passwords.user_id
    WHERE users.user_name = user_name LIMIT 1;

SELECT MYSQLUDF_CRYPT_MULTIHASH(algo, password, salt) INTO new_hash;
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

IF COUNT(user_id) < 0;
THEN
    RETURN FALSE;
END IF;

# Check if email address already exists
IF COUNT(SELECT email_address INTO email_addresses
    FROM email_addresses
    WHERE user_id = user_id AND email_address = email_address) > 0
THEN
    SIGNAL SQLSTATE '45000' MESSAGE_TEXT='You can not add an existing email.';
    RETURN FALSE;
END IF;

INSERT INTO email_addresses (,user_id,);
# add email_address
# COMMIT
RETURN FALSE;
END
//