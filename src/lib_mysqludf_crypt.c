/*
    lib_mysqludf_crypt - a library for cryptographic primitives and functions for password authentication
    Copyright (C) 2019 Noel Kuntze
    email: noel.kuntze@thermi.consulting
*/

#include <lib_mysqludf.h>



/* For Windows, define PACKAGE_STRING in the VS project */
#ifndef __WIN__
#include "config.h"
#endif

/* These must be right or mysqld will not find the symbol! */
#ifdef  __cplusplus
extern "C" {
#endif
    DLLEXP my_bool lib_mysqludf_crypt_info_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    DLLEXP void lib_mysqludf_crypt_info_deinit(UDF_INIT *initid);
    /* For functions that return STRING or DECIMAL */ 
    DLLEXP char *lib_mysqludf_crypt_info(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);

    /* For functions that return REAL */
    /* DLLEXP double lib_mysqludf_crypt_info(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error); */
    /* For functions that return INTEGER */
    /* DLLEXP longlong lib_mysqludf_crypt_info(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error); */

    /* If you are doing an Aggregate function you'll need these too */
    /* DLLEXP void lib_mysqludf_crypt_info_clear( UDF_INIT* initid, char* is_null, char* is_error ); */
    /* DLLEXP void lib_mysqludf_crypt_info_add( UDF_INIT* initid, UDF_ARGS* args, char* is_null, char* is_error ); */

#ifdef  __cplusplus
}
#endif


/*
 * Output the library version.
 * lib_mysqludf_crypt_info()
 */

my_bool lib_mysqludf_crypt_info_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return 0;
}

void lib_mysqludf_crypt_info_deinit(UDF_INIT *initid)
{
}

/* For functions that return REAL */
/* double lib_mysqludf_crypt_info(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error) */
/* For functions that return INTEGER */
/* longlong lib_mysqludf_crypt_info(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error) */

/* For functions that return STRING or DECIMAL */ 
char* lib_mysqludf_crypt_info(UDF_INIT *initid, UDF_ARGS *args, char* result, unsigned long* length, char *is_null, char *error)
{
    strcpy(result, PACKAGE_STRING);
    *length = strlen(PACKAGE_STRING);
    return result;
}