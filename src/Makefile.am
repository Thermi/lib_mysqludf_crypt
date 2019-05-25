lib_LTLIBRARIES = lib_mysqludf_crypt.la

lib_mysqludf_crypt_la_SOURCES = \
	lib_mysqludf_crypt.c lib_mysqludf_crypt.h mysqludf.c mysqludf.h

lib_mysqludf_crypt_la_LDFLAGS = -version-info 0:0:0

AM_CFLAGS = -DSTANDARD -DMYSQL_SERVER @MYSQL_CFLAGS@ @botan_CFLAGS@ @botan_LIBS@

# all: $(CC) $(lib_mysqludf_crypt_la_CFLAGS) $(lib_mysqludf_crypt_la_LDFLAGS) -o %.c