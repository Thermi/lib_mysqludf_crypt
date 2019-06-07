AC_PREREQ(2.59)

AC_INIT([lib_mysqludf_crypt],[0.0.1],[you@example.com])

AC_CONFIG_SRCDIR([Makefile.am])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR(config)
AC_CONFIG_HEADER(config.h)

AC_DEFINE([CONFIG_H_INCLUDED], [], [defined if config.h included])

# AM_INIT_AUTOMAKE(m4_esyscmd())
AM_INIT_AUTOMAKE([-Wall foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])
AC_USE_SYSTEM_EXTENSIONS

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])],
    [AC_SUBST([AM_DEFAULT_VERBOSITY], [1])])


AC_ENABLE_SHARED
AC_DISABLE_STATIC
# AC_PROG_LIBTOOL(libtool)

AC_LIBTOOL_WIN32_DLL
AM_PROG_AR
AM_PROG_LIBTOOL
AC_PROG_CC
AC_PROG_CXX
PKG_PROG_PKG_CONFIG

LT_INIT

AC_CHECK_HEADERS([stdlib.h string.h limits.h syslimits.h])
AC_CHECK_HEADER_STDBOOL


AC_C_CONST
AC_TYPE_SIZE_T

AC_FUNC_MALLOC

AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([setenv])

m4_include(config/ax_lib_mysql.m4)
AX_LIB_MYSQL(,,AC_MSG_ERROR("Can't find mysql library" ))

if test -n "$MYSQL_PLUGINDIR" && test "$libdir" == '${exec_prefix}/lib' ; then
  AC_MSG_NOTICE(setting libdir to mysql plugin dir $MYSQL_PLUGINDIR)
  libdir=$MYSQL_PLUGINDIR
  AC_SUBST(libdir)
fi

m4_include(config/ax_mysql_bin.m4)
AX_MYSQL_BIN

AC_ARG_WITH([botan],
  AC_HELP_STRING([--with-botan=@<:@ARG@:>@],
    [user botan client library @<:@default=yes@:>@]
    ),
    [
      if test "$withval" = "no"; then
        want_botan="no"
      elif test "$withval" = "yes"; then
        want_botan="yes"
      else
        want_botan="yes"
        BOTAN_CONFIG="$withval"
      fi
    ],
    [want_botan="yes"]
  )
PKG_CHECK_MODULES(botan, [botan-2],
  [AC_SUBST(botan_CFLAGS)
   AC_SUBST(botan_LIBS)])

AC_CONFIG_FILES([Makefile src/Makefile test/Makefile])

AC_OUTPUT
