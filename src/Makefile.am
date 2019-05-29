lib_LTLIBRARIES = lib_mysqludf_crypt.la

AM_CFLAGS = $(CFLAGS) -march=x86-64 -mtune=generic -pipe -fstack-protector-strong \
			-fno-plt -O2 -g3 -Wall -Werror -Wno-format-extra-args -DSTANDARD -DMYSQL_SERVER @MYSQL_CFLAGS@ \
			-Wl,-O1,--sort-common,--as-needed,-z,relro,-z,now -fvar-tracking-assignments
AM_CXXFLAGS = -DSTANDARD -DMYSQL_SERVER @MYSQL_CFLAGS@
AM_LDFLAGS = -module -avoid-version -no-undefined -rpath @MYSQL_PLUGINDIR@


lib_mysqludf_crypt_la_SOURCES = \
	lib_mysqludf_crypt.c lib_mysqludf_crypt.h mysqludf.c mysqludf.h

lib_mysqludf_crypt_la_LDFLAGS = -version-info 0:0:0

AM_CFLAGS += @botan_CFLAGS@ @botan_LIBS@

# all: $(CC) $(lib_mysqludf_crypt_la_CFLAGS) $(lib_mysqludf_crypt_la_LDFLAGS) -o %.c