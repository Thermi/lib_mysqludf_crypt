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
#CREATE USER ''admin_user'@'localhost''@'localhost' ACCOUNT LOCK;
CREATE OR REPLACE USER 'admin_user'@'localhost' IDENTIFIED BY PASSWORD '11111111111111111111111111111111111111111';


DELIMITER //;
CREATE OR REPLACE FUNCTION UDF_SHA256 (salt VARCHAR(21844), password VARCHAR(21844)) RETURNS VARCHAR(21844) DETERMINISTIC
RETURN lib_mysqludf_crypt_sha256(CONCAT(salt, password));
//

CREATE OR REPLACE FUNCTION UDF_SHA384 (salt VARCHAR(21844), password VARCHAR(21844)) RETURNS VARCHAR(21844) DETERMINISTIC
RETURN lib_mysqludf_crypt_sha384(CONCAT(salt, password));
//

CREATE OR REPLACE FUNCTION UDF_SHA512 (salt VARCHAR(21844), password VARCHAR(21844)) RETURNS VARCHAR(21844) DETERMINISTIC
RETURN lib_mysqludf_crypt_sha512(CONCAT(salt, password));
//

CREATE OR REPLACE FUNCTION UDF_SHA3 (salt VARCHAR(21844), password VARCHAR(21844)) RETURNS VARCHAR(21844) DETERMINISTIC
RETURN lib_mysqludf_crypt_sha3(CONCAT(salt, password));
//

CREATE OR REPLACE FUNCTION UDF_BLAKE2B (salt VARCHAR(21844), password VARCHAR(21844)) RETURNS VARCHAR(21844) DETERMINISTIC
RETURN lib_mysqludf_crypt_blake2b(CONCAT(salt, password));
//

CREATE OR REPLACE FUNCTION UDF_ARGON2 (salt VARCHAR(21844), password VARCHAR(21844)) RETURNS VARCHAR(21844) DETERMINISTIC
RETURN lib_mysqludf_crypt_argon2(CONCAT(salt, password));
//

CREATE OR REPLACE FUNCTION UDF_SCRYPT (salt VARCHAR(21844), password VARCHAR(21844)) RETURNS VARCHAR(21844) DETERMINISTIC
RETURN lib_mysqludf_crypt_scrypt(CONCAT(salt, password));
//

CREATE OR REPLACE FUNCTION UDF_RAND (random_bytes_number INT UNSIGNED) RETURNS VARCHAR(21844) NOT DETERMINISTIC READS SQL DATA
RETURN lib_mysqludf_crypt_rand(random_bytes_number);
//

CREATE OR REPLACE FUNCTION UDF_BASE64_ENCODE (input VARCHAR(21844)) RETURNS VARCHAR(21844) DETERMINISTIC
RETURN lib_mysqludf_crypt_base64_encode(input);
//

CREATE OR REPLACE FUNCTION UDF_BASE64_DECODE (input VARCHAR(21844)) RETURNS VARCHAR(21844) DETERMINISTIC
RETURN lib_mysqludf_crypt_base64_decode(input);
//

CREATE OR REPLACE DEFINER='admin_user'@'localhost' FUNCTION change_password (user_name VARCHAR(21844), old_password VARCHAR(21844), new_password VARCHAR(21844)) RETURNS BOOLEAN DETERMINISTIC MODIFIES SQL DATA SQL SECURITY DEFINER
BEGIN
DECLARE old_hash TYPE OF passwords.password_hash;
DECLARE new_hash TYPE OF passwords.password_hash;
DECLARE salt TYPE OF passwords.salt;
DECLARE algo TYPE OF passwords.algorithm;

SELECT passwords.password_hash, passwords.salt, passwords.algorithm
    INTO old_hash, salt, algo
    FROM passwords LEFT JOIN users ON users.user_id = passwords.user_id
    WHERE users.user_name = user_name LIMIT 1;

SELECT MYSQLUDF_CRYPT_MULTIHASH(algo, salt, old_password) INTO new_hash;

IF MYSQLUDF_CRYPT_CONSTANT_TIME_COMPARE(old_hash, new_hash)
THEN
    # set new password, return true
    CALL SET_PASSWORD (algo, user_id, new_password);
    RETURN TRUE;
END IF;
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Given password does not match.';
# fail, return false

RETURN FALSE;
END //

# it makes no sense that even with binlog_format=mixed, such functions couldn't be safely binlogged. With a simple row based
# logging in this case, this should work just fine?
CREATE OR REPLACE DEFINER='admin_user'@'localhost' FUNCTION set_password (algo VARCHAR(21844), user_id BIGINT UNSIGNED, password VARCHAR(21844)) RETURNS BOOLEAN DETERMINISTIC MODIFIES SQL DATA SQL SECURITY DEFINER
BEGIN
DECLARE salt TYPE OF passwords.salt;
DECLARE hash TYPE OF passwords.password_hash; 
DECLARE existing_user BIGINT UNSIGNED;

SELECT UDF_RAND(128) INTO salt;
SELECT MYSQLUDF_CRYPT_MULTIHASH(algo, salt, password) INTO hash;
SELECT COUNT(*) INTO existing_user FROM users WHERE user_id = user_id LIMIT 1;
IF existing_user = 1
THEN
    INSERT INTO passwords (salt, password_hash, algo, user_id) VALUES (salt, hash, algo, user_id);
ELSE
    UPDATE passwords SET salt = salt, password_hash = hash, algo = algo WHERE user_id = user_id;
END IF;
RETURN TRUE;
END //

CREATE OR REPLACE FUNCTION MYSQLUDF_CRYPT_MULTIHASH(algo VARCHAR(21844), salt VARCHAR(21844), password VARCHAR(21844)) RETURNS VARCHAR(21844) DETERMINISTIC 
BEGIN
CASE algo
    WHEN "SHA-256" THEN RETURN UDF_SHA256(salt, password);
    WHEN "SHA-384" THEN RETURN UDF_SHA384(salt, password);
    WHEN "SHA-512" THEN RETURN UDF_SHA512(salt, password);
    WHEN "BLAKE2b" THEN RETURN UDF_BLAKE2B(salt, password);
    WHEN "ARGON2"  THEN RETURN UDF_ARGON2(salt, password);
    WHEN "SCRYTP" THEN RETURN UDF_SCRYPT(salt, password);
    ELSE BEGIN
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Given hash method is not supported';
            RETURN NULL;
        END;
RETURN NULL;
END CASE;
END //

CREATE DEFINER='admin_user'@'localhost' FUNCTION check_user_exists(user_name VARCHAR(21844)) RETURNS BOOLEAN SQL SECURITY DEFINER DETERMINISTIC
BEGIN
DECLARE count_matching_users TYPE OF users.username;
SELECT COUNT(*) INTO count_matching_users FROM users WHERE username = user_name;

IF count_matching_users = 1
THEN
    RETURN TRUE;
ELSE
    RETURN FALSE;
END IF;
END //

CREATE OR REPLACE  DEFINER='admin_user'@'localhost' FUNCTION check_password(user_name VARCHAR(21844), password VARCHAR(21844)) RETURNS BOOLEAN DETERMINISTIC SQL SECURITY DEFINER
BEGIN
DECLARE old_hash TYPE OF passwords.password_hash;
DECLARE new_hash TYPE OF passwords.password_hash;
DECLARE salt TYPE OF passwords.salt;
DECLARE algo TYPE OF passwords.algorithm;

IF check_user_exists(user_name) = false
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
END //

CREATE OR REPLACE  DEFINER='admin_user'@'localhost' FUNCTION add_email(user_name VARCHAR(21844), email_address VARCHAR(21844)) RETURNS BOOLEAN DETERMINISTIC SQL SECURITY DEFINER
BEGIN
DECLARE user_id TYPE OF users.user_id;
DECLARE email_addresses TYPE OF users.user_id;

# join users and email_addresses
SELECT user_id INTO user_id
    FROM users
    WHERE user_name = user_name LIMIT 1;

IF COUNT(user_id) < 0
THEN
    RETURN FALSE;
END IF;

# Check if email address already exists
SELECT COUNT(email_address) INTO email_addresses
    FROM email_addresses
    WHERE user_id = user_id AND email_address = email_address;
IF email_addresses > 0
THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='You can not add an existing email.';
    RETURN FALSE;
END IF;

INSERT INTO email_addresses (user_id, email_address) VALUES (user_id, email_address);
# add email_address
# COMMIT
RETURN FALSE;
END //

CREATE OR REPLACE DEFINER='admin_user'@'localhost' FUNCTION add_user(user_name VARCHAR(21844), password VARCHAR(21844), email_address VARCHAR(21844)) RETURNS BOOLEAN DETERMINISTIC SQL SECURITY DEFINER
BEGIN
DECLARE user_id TYPE OF users.user_id;
IF check_user_exists(user_name)
THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='This user name is already used.';
    RETURN FALSE;
END IF;
INSERT INTO users (user_name) VALUES (user_name);
SELECT user_id INTO user_id FROM users WHERE user_name = user_name LIMIT 1;
CALL set_password("BLAKE2b", user_id, password);
CALL add_email(user_name, email_address);
RETURN TRUE;
END; //

DELIMITER ;//
#'application'@'localhost' user can only use predefined functions to interact with sensitive data

GRANT EXECUTE ON FUNCTION add_user TO 'application'@'localhost';
GRANT EXECUTE ON FUNCTION change_password TO 'application'@'localhost';
GRANT EXECUTE ON FUNCTION check_password TO 'application'@'localhost';
GRANT EXECUTE ON FUNCTION add_email TO 'application'@'localhost';

#'admin_user'@'localhost' needs the privileges that the functions that are run as this user need
GRANT SELECT,DELETE,INSERT,UPDATE ON users TO 'admin_user'@'localhost';
GRANT SELECT,DELETE,INSERT ON email_addresses TO 'admin_user'@'localhost';
GRANT SELECT,INSERT,UPDATE ON passwords TO 'admin_user'@'localhost';
GRANT EXECUTE ON FUNCTION UDF_SHA256 TO 'admin_user'@'localhost';
GRANT EXECUTE ON FUNCTION UDF_SHA384 TO 'admin_user'@'localhost';
GRANT EXECUTE ON FUNCTION UDF_SHA512 TO 'admin_user'@'localhost';
GRANT EXECUTE ON FUNCTION UDF_SHA3 TO 'admin_user'@'localhost';
GRANT EXECUTE ON FUNCTION UDF_BLAKE2b TO 'admin_user'@'localhost';
GRANT EXECUTE ON FUNCTION UDF_ARGON2 TO 'admin_user'@'localhost';
GRANT EXECUTE ON FUNCTION UDF_SCRYPT TO 'admin_user'@'localhost';
GRANT EXECUTE ON FUNCTION UDF_RAND TO 'admin_user'@'localhost';
GRANT EXECUTE ON FUNCTION UDF_BASE64_ENCODE TO 'admin_user'@'localhost';
GRANT EXECUTE ON FUNCTION UDF_BASE64_DECODE TO 'admin_user'@'localhost';
