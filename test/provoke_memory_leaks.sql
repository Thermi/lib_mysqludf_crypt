USE mysqludf_crypt_db;
DELIMITER //;
FOR count IN 0 .. 1000000
DO
    DO UDF_SHA256("foobar");
END FOR;
DELIMITER ; //