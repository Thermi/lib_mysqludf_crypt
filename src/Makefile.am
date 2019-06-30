lib_LTLIBRARIES = lib_mysqludf_crypt.la

AM_CFLAGS = $(CFLAGS) -march=x86-64 -mtune=generic -pipe -fstack-protector-strong \
			-fno-plt -O2 -g3 -Wall -Werror -Wno-format-extra-args -DSTANDARD -DMYSQL_SERVER @MYSQL_CFLAGS@ \
			-Wl,-O1,--sort-common,--as-needed,-z,relro,-z,now -fvar-tracking-assignments @botan_CFLAGS@ 

AM_CXXFLAGS = -DSTANDARD -DMYSQL_SERVER @MYSQL_CFLAGS@
AM_LDFLAGS = -module -avoid-version -no-undefined -rpath @MYSQL_PLUGINDIR@
lib_mysqludf_crypt_la_LDFLAGS = @botan_LIBS@ 

if USE_BOTAN_STATIC
lib_LTLIBRARIES += lib_mysqludf_crypt_static.la
lib_mysqludf_crypt_static_la_LDFLAGS = -L$(SOURCE_DIR)/src -l:libbotan-2.a @botan_LIBS@ -L/usr/lib
lib_mysqludf_crypt_static_la_SOURCES = \
	lib_mysqludf_crypt.c lib_mysqludf_crypt.h
endif



lib_mysqludf_crypt_la_SOURCES = \
	lib_mysqludf_crypt.c lib_mysqludf_crypt.h
