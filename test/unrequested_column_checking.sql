# test case for unrequested column privilege checking

DROP DATABASE IF EXISTS unrequested_column_checking;
CREATE DATABASE unrequested_column_checking;

USE unrequested_column_checking;

CREATE TABLE `table1` (
  `column1` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `column2` varchar(256) NOT NULL,
  PRIMARY KEY (`column1`),
  UNIQUE KEY `column2` (`column2`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `table2` (
  `column1` bigint(20) unsigned NOT NULL,
  `column2` varchar(1024) NOT NULL,
  `column3` varchar(64) NOT NULL,
  PRIMARY KEY (`column1`),
  CONSTRAINT `fk_table2_column1` FOREIGN KEY (`column1`) REFERENCES `table1` (`column1`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

DELIMITER //;

CREATE OR REPLACE DEFINER='admin_user'@'localhost' FUNCTION test_function (column2 VARCHAR(16383), password VARCHAR(16383)) RETURNS BOOLEAN DETERMINISTIC SQL SECURITY DEFINER
BEGIN
DECLARE var_a TYPE OF table2.column2;
DECLARE var_b TYPE OF table2.column3;

SELECT table2.column2, table2.column3 INTO var_a, var_b
    FROM table2 LEFT JOIN table1 ON table1.column1 = table2.column1
    WHERE table1.column2 = column2 LIMIT 1;
RETURN TRUE;
END //

DELIMITER ;//

CREATE OR REPLACE USER 'application'@'localhost' IDENTIFIED BY 'abcde';
#CREATE USER ''admin_user'@'localhost''@'localhost' ACCOUNT LOCK;
CREATE OR REPLACE USER 'admin_user'@'localhost' IDENTIFIED BY PASSWORD '11111111111111111111111111111111111111111';

GRANT SELECT,DELETE,INSERT,UPDATE ON table1 TO 'admin_user'@'localhost';
GRANT SELECT,INSERT,UPDATE ON table2 TO 'admin_user'@'localhost';

GRANT EXECUTE ON FUNCTION unrequested_column_checking.test_function TO 'application'@'localhost';
GRANT EXECUTE ON FUNCTION unrequested_column_checking.test_function TO 'admin_user'@'localhost';

SELECT test_function('a', 'b');
