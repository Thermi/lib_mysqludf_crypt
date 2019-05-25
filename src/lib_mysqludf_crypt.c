/*
    lib_mysqludf_crypt - a library for cryptographic primitives and functions for password authentication
    Copyright (C) 2019 Noel Kuntze
    email: noel.kuntze@thermi.consulting
*/

#include "lib_mysqludf_crypt.h"

/* 
    https://dev.mysql.com/doc/refman/8.0/en/udf-calling.html
    https://dev.mysql.com/doc/refman/8.0/en/adding-udf.html
    https://dev.mysql.com/doc/refman/8.0/en/udf-aggr-calling.html
    https://dev.mysql.com/doc/refman/8.0/en/udf-arguments.html
    https://dev.mysql.com/doc/refman/8.0/en/udf-return-values.html
    https://dev.mysql.com/doc/refman/8.0/en/udf-compiling.html
    https://dev.mysql.com/doc/refman/8.0/en/udf-security.html

    https://dev.mysql.com/doc/refman/8.0/en/create-procedure.html

    https://github.com/randombit/botan/blob/master/src/lib/ffi/ffi.h

    https://mariadb.com/kb/en/library/creating-user-defined-functions/
    https://mariadb.com/kb/en/library/user-defined-functions-calling-sequences/

    At least one symbol, beyond the required x() - corresponding to an SQL
    function X()) - is required. These can be x_init(), x_deinit(), xxx_reset(),
    x_clear() and x_add() functions (see Creating User-defined Functions). The
    allow-suspicious-udfs mysqld option (by default unset) provides a workaround,
    permitting only one symbol to be used. This is not recommended, as it opens
    the possibility of loading shared objects that are not legitimate user-defined
    functions.

*/

/*
 * The lib supports the following hash algorithms:
   * SHA2-256
   * SHA2-384
   * SHA2-512
   * SHA3
   * BLAKE2
   * ARGON2
   * SCRPYT
 */

/*
 * TODO:
 * - Implement the MSCHAPv2 hand shake and expose function to check challenge and response against stored password
 *   - Requires DES and MD4 (Do not expose those to the user)
 */

/* For Windows, define PACKAGE_STRING in the VS project */
#ifndef __WIN__
#include "config.h"
#endif

/* These must be right or mysqld will not find the symbol! */
#ifdef  __cplusplus
extern "C" {
#endif

    // DLLEXP my_bool lib_mysqludf_crypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    //     /* Check args */
    //     /* Specifically check values and numbers of args */
    //     bool valid_algo = lib_mysqludf_crypt_check_valid_algo(args);
    //     /* Require variable number of args */
    //     /* first arg is hash/digest type, then the salt, then the data to digest */
    //     struct lib_mysqludf_crypt_args *crypto_args = lib_mysqludf_crypt_algo_to_args(args);
        
    //     if (crypto_args->not_enough_args) {
    //         /* Handle failure */
    //         return FALSE;
    //     }

    //     enum lib_mysqludf_crypt_crypto_provider crypto_provider = lib_mysqludf_crypt_algo_to_provider(args);

    //     /* input is first de-base64'd */
    //     char *debase64ed = debase64(message);
    //     if (!debase64ed) {
    //         /* Handle failure */
    //         return FALSE;
    //     }

    //     struct lib_mysqludf_crypt_storage_struct *storage_struct =
    //         calloc(1, (sizeof(lib_mysqludf_crypt_storage_struct)));

    //     storage_struct->provider = crypto_provider;
    //     /* allocate memory for openssl/gnutls/botan structures */
    //     switch(crypto_provider) {
    //         case BOTAN:
    //             storage_struct->botan_handle = make_handle_botan();
    //         break;
    //         default:
    //             return FALSE;
    //         break;
    //     }
        
    //     /* initialize structures */

    //     initid->const_item = 0;
    //     initid->ptr = storage_struct;
    //     return TRUE;
    // }


    // DLLEXP void lib_mysqludf_crypt_deinit(UDF_INIT *initid) {
    //     /* Deinitialize structures */
    //     switch(crypto_provider) {
    //         case OPENSSL:
    //         break;
    //         case GNUTLS:
    //         break;
    //         case BOTAN:
    //         break;
    //         default:
    //         break;
    //     }
    //     /* free memory */
    //     free(initid->ptr);
    // }

    static bool constant_time_compare(const char *s1, const char *s2, size_t string1_length, size_t string2_length)
    {
        int    m = 0;
        size_t i = 0;
        size_t j = 0;
        size_t k = 0;

        if (!s1 || !s2 || !string1_length || !string2_length) {
            return false;
        }

        while (true) {
            m |= s1[i]^s2[j];

            if (i == string1_length-1) {
                break;
            }
            
            i++;

            if (j != string2_length-1) {
                j++;
            }

            if (j == string2_length-1) {
                k++;
            }
        }

        return m == 0;
    }

    static char *hash_common_operation(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
                                        char *is_null, char *error) {
        struct hash_data_storage *pointers = (struct hash_data_storage *) initid->ptr;
        botan_hash_t *botan_hash_structure = pointers->hash_structure;
        void *output_buffer = pointers->output_data;

        botan_hash_output_length(*botan_hash_structure, length);
        /* put data into hash */

        /* Output aggregate result */
        botan_hash_update(*botan_hash_structure, args->args[0], args->lengths[0]);
        botan_hash_final(*botan_hash_structure, output_buffer);

        result = output_buffer;

        /* deinit */
        botan_hash_destroy(*botan_hash_structure);
        free(botan_hash_structure);
        free(pointers);
        return result;
    }

    static my_bool hash_common_init(char *hash_name, UDF_INIT *initid, UDF_ARGS *args, char *message) {
        int ret;
        size_t length = 0, str_length = 0;
        char *hash_udf_name = malloc(strlen(hash_name)+1);
        memset(hash_udf_name, 0, strlen(hash_name) + 1);
        for (int i=0; i<str_length;i++) {
            hash_udf_name[i] = (char) tolower(hash_name[i]);
        }

        /* Check number of args (must be one) */
        if (args->arg_count != 1) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "lib_mysqludf_crypt_%s requires exactly one argument.\n",
                hash_udf_name);
            free(hash_udf_name);
            return 1;
        }

        /* allocate and init hashing structure */
        botan_hash_t *hash_structure = malloc(sizeof(botan_hash_t));
        if(!hash_structure) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "lib_mysqludf_crypt_%s could not allocate enough memory for the hash structure.\n",
                hash_udf_name);
            free(hash_udf_name);
            return 1;
        }
        ret = botan_hash_init(hash_structure, hash_name, 0);
        if (ret) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "lib_mysqludf_crypt_%s could not initialize the hash structure. "
                "Reported failure: %s\n", hash_udf_name, botan_error_description(ret));
            free(hash_udf_name);
            return 1;
        }
        botan_hash_output_length(*hash_structure, &length);
        char *output_data = malloc(length);
        if (!output_data) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "lib_mysqludf_crypt_%s could not initialize the buffer for the result.\n",
                hash_udf_name);
            free(hash_udf_name);
            return 1;
        }
        struct hash_data_storage *hash_data_storage = malloc(sizeof(void *)*2);
        hash_data_storage->hash_structure = hash_structure;
        hash_data_storage->output_data = output_data;

        initid->ptr = (void *) hash_data_storage;

        return 0;      
    }

    DLLEXP my_bool lib_mysqludf_crypt_sha256_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
        return hash_common_init("SHA-256", initid, args, message);
    }

    DLLEXP my_bool lib_mysqludf_crypt_sha384_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
        return hash_common_init("SHA-384", initid, args, message);
    }

    DLLEXP my_bool lib_mysqludf_crypt_sha512_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
        return hash_common_init("SHA-512", initid, args, message);
    }

    DLLEXP my_bool lib_mysqludf_crypt_sha3_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
        return hash_common_init("SHA-3", initid, args, message);
    }

    DLLEXP my_bool lib_mysqludf_crypt_sha1_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
        return hash_common_init("SHA-1", initid, args, message);
    }

    DLLEXP my_bool lib_mysqludf_crypt_blake2b_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
        return hash_common_init("BLAKE2b", initid, args, message);
    }

    DLLEXP my_bool lib_mysqludf_crypt_argon2_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
        snprintf(message, MYSQL_ERRMSG_SIZE, "ARGON2 is not implemented.\n");
        return 1;
        //return hash_argon2_init(initid, args, message);
    }

    DLLEXP my_bool lib_mysqludf_crypt_scrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
        snprintf(message, MYSQL_ERRMSG_SIZE, "SCRYPT is not implemented.\n");
        return 1;
        // return hash_scrypt_init(initid, args, message);
    }

    DLLEXP my_bool lib_mysqludf_crypt_constant_time_compare_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
        return 0;
    }

    DLLEXP my_bool lib_mysqludf_crypt_random_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
        uint64_t bytes_to_request = 8;
        int ret;

        struct rng_data_storage *rng_data_storage;

        if (args->arg_count > 1) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "lib_mysqludf_crypt_random_init takes at most one argument.\n");
            return 1;
        }

        if(args->arg_count == 1) {
            if (args->arg_type[0] == INT_RESULT) {
                if (!scanf("%ld", &bytes_to_request)) {
                    snprintf(message, MYSQL_ERRMSG_SIZE, "lib_mysqludf_crypt_random_init failed to parse the first argument as 64 bit integer.\n");
                    return 1;
                }
            } else {
                snprintf(message, MYSQL_ERRMSG_SIZE, "The first argument to lib_mysqludf_crypt_random has to be of type INT.\n");
                return 1;
            }
        }

        /* Allocate memory for structures */

        rng_data_storage = malloc(sizeof(rng_data_storage));

        if (!rng_data_storage) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "lib_mysqludf_crypt_random could not allocate enough memory for the data storage structure.\n");
            return 1;
        }

        rng_data_storage->rng_structure = malloc(sizeof(botan_rng_t));

        if (!rng_data_storage->rng_structure) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "lib_mysqludf_crypt_random could not allocate enough memory for the rng structure.\n");
            free(rng_data_storage);
            return 1;
        }

        ret = botan_rng_init(rng_data_storage->rng_structure, NULL);

        if(ret) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "lib_mysqludf_crypt_random could not initialize the rng structure. "
                "Reported failure: %s\n", botan_error_description(ret));
            free(rng_data_storage->rng_structure);
            free(rng_data_storage);
            return 1;
        }

        /* Allocate memory for output buffer */
        rng_data_storage->output_data = malloc(bytes_to_request);

        if(!rng_data_storage) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "lib_mysqludf_crypt_random could allocate enough memory for the output buffer.\n");
            free(rng_data_storage->rng_structure);
            free(rng_data_storage);
            return 1;            
        }

        rng_data_storage->output_data_length = bytes_to_request;

        /* initid->ptr should ideally be of void*, but nooo, the devs made it a char*. */
        initid->ptr = (char *)rng_data_storage;
        return 0;
    }

    DLLEXP my_bool lib_mysqludf_crypt_info_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
        if (args->arg_count) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "lib_mysqludf_crypt_info does not take any arguments.\n");
            return 1;
        }
        return 0;
    }

    DLLEXP my_bool lib_mysqludf_crypt_base64_encode_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
        if (args->arg_count != 1) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "lib_mysqludf_crypt_base64_encode takes exactly one argument.\n");
            return 1;
        }
        initid->ptr = malloc((args->lengths[0]*4)/3);
        if (!initid->ptr) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "lib_mysqludf_crypt_base64_encode could allocate enough memory for the output buffer.\n");
            return 1;
        }

        return 0;
    }

    DLLEXP my_bool lib_mysqludf_crypt_base64_decode_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
        if (args->arg_count != 1) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "lib_mysqludf_crypt_base64_decode takes exactly one argument.\n");
            return 1;
        }
        initid->ptr = malloc((args->lengths[0]*3)/4);
        if (!initid->ptr) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "lib_mysqludf_crypt_base64_encode could allocate enough memory for the output buffer.\n");
            return 1;
        }

        return 0;
    }

    DLLEXP char *lib_mysqludf_crypt_sha1(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
        char *is_null, char *error) {
        return hash_common_operation(initid, args, result, length, is_null, error);
    }

    DLLEXP char *lib_mysqludf_crypt_sha256(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
        char *is_null, char *error) {
        return hash_common_operation(initid, args, result, length, is_null, error);
    }
    
    DLLEXP char *lib_mysqludf_crypt_sha384(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
        char *is_null, char *error) {
        return hash_common_operation(initid, args, result, length, is_null, error);
    }

    DLLEXP char *lib_mysqludf_crypt_sha512(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
        char *is_null, char *error){
        return hash_common_operation(initid, args, result, length, is_null, error);
    }


    DLLEXP char *lib_mysqludf_crypt_sha3(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
        char *is_null, char *error){
        return hash_common_operation(initid, args, result, length, is_null, error);
    }

    DLLEXP char *lib_mysqludf_crypt_blake2b(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
        char *is_null, char *error) {
        return hash_common_operation(initid, args, result, length, is_null, error);
    }

    DLLEXP char *lib_mysqludf_crypt_argon2(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
        char *is_null, char *error) {
        return NULL;
        /* return hash_argon2_operation(initid, args, result, length, is_null, error); */
    }

    DLLEXP char *lib_mysqludf_crypt_scrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
        char *is_null, char *error) {
        return NULL;
        /* return hash_scrypt_operation(initid, args, result, length, is_null, error); */
    }

    DLLEXP long long lib_mysqludf_crypt_constant_time_compare(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error) {
        if (args->arg_count != 2) {
            *error = 1;
            snprintf(error, MYSQL_ERRMSG_SIZE, "lib_mysqludf_crypt_constant_time_compare takes exactly two arguments.\n");
            return 1;
        }

        if (!args->args[0]) {
            *error = 1;
            snprintf(error, MYSQL_ERRMSG_SIZE, "The first argument to lib_mysqludf_crypt_constant_time_compare must not be NULL.\n");
            return 1;
        }

        if (!args->args[1]) {
            *error = 1;
            snprintf(error, MYSQL_ERRMSG_SIZE, "The second argument to lib_mysqludf_crypt_constant_time_compare must not be NULL.\n");
            return 1;
        }
        /* Use botan_constant_time_compare instead */
        return (long long) constant_time_compare(args->args[0], args->args[1], args->lengths[0], args->lengths[1]);
    }

    DLLEXP char* lib_mysqludf_crypt_info(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error) {
        char *return_message = malloc(strlen(LIBMYSQLUDF_CRYPT_VERSION)+1);
        strncpy(return_message, LIBMYSQLUDF_CRYPT_VERSION, strlen(LIBMYSQLUDF_CRYPT_VERSION)+1);
        return return_message;
    }

    DLLEXP char *lib_mysqludf_crypt_random(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
        char *is_null, char *error) {
        struct rng_data_storage *data_storage = (struct rng_data_storage *) initid->ptr;

        int ret = botan_rng_get(*data_storage->rng_structure, data_storage->output_data, data_storage->output_data_length);
        if(ret) {
            snprintf(error, MYSQL_ERRMSG_SIZE, "lib_mysqludf_crypt_random could not get random data from the rng. "
                "Reported failure: %s\n", botan_error_description(ret));
            botan_rng_destroy(*data_storage->rng_structure);
            free(data_storage->rng_structure);
            free(data_storage->output_data);
            free(data_storage);
            *is_null = true;
            return NULL;
        }
        botan_rng_destroy(*data_storage->rng_structure);
        *length = data_storage->output_data_length;
        result = data_storage->output_data;
        free(data_storage);
        return result;
    }

    DLLEXP char*lib_mysqludf_crypt_base64_encode(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
        char *is_null, char *error) {
        size_t out_length = (args->lengths[0]*4)/3;
        int ret = botan_base64_encode(args->args[0], args->lengths[0], initid->ptr, &out_length);

        if(ret) {
            snprintf(error, MYSQL_ERRMSG_SIZE, "lib_mysqludf_crypt_base64_encode could not encode the data. "
                "Reported failure: %s\n", botan_error_description(ret));
            free(initid->ptr);
            return NULL;
        }

        *length = out_length;
        result = initid->ptr;
        return result;
    }


    DLLEXP char*lib_mysqludf_crypt_base64_decode(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
        char *is_null, char *error) {
        size_t out_length = (args->lengths[0]*3)/4;
        int ret = botan_base64_decode(args->args[0], args->lengths[0], initid->ptr, &out_length);

        if(ret) {
            snprintf(error, MYSQL_ERRMSG_SIZE, "lib_mysqludf_crypt_base64_decode could not encode the data. "
                "Reported failure: %s\n", botan_error_description(ret));
            free(initid->ptr);
            return NULL;
        }

        *length = out_length;
        result = initid->ptr;
        return result;
    }

    /* For functions that return REAL */
    /* DLLEXP double lib_mysqludf_crypt_info(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error); */
    /* For functions that return INTEGER */
    /* DLLEXP longlong lib_mysqludf_crypt_info(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error); */

    /* If you are doing an Aggregate function you'll need these too */
    /* DLLEXP void lib_mysqludf_crypt_info_clear( UDF_INIT* initid, char* is_null, char* is_error ); */
    /* DLLEXP void lib_mysqludf_crypt_info_add( UDF_INIT* initid, UDF_ARGS* args, char* is_null, char* is_error ); */

    /*
     * This function attempts to get the active crypto provider via the environmental variables
     */
    // enum lib_mysqludf_crypt_crypto_provider get_active_provider() {
    //     char *provider = NULL;
    //     provider = getenv(LIB_MYSQLUDF_CRYPT_PROVIDER_ENV);
    //     int provider_int = -1;
    //     if (provider) {
    //         sscanf(provider, "%d", &provider_int)
    //     } else {
    //         /* This code path should be taken exactly once (at the start of the daemon, of the variable is unset)*/
    //         provider = lib_mysqludf_crypt_crypto_get_default_provider()
    //         char provider_string[2];
    //         snprintf(provider_string, 1, "%d", provider);
    //         setenv(LIB_MYSQLUDF_CRYPT_PROVIDER_ENV, provider_string, true);
    //         /* initialize the chosen crypto provider */
    //         switch(provider) {
    //             case OPENSSL:
    //             break;
    //             case GNUTLS:
    //             break;
    //             case BOTAN:
    //             break;
    //         }
    //     }
        
    //     return enum lib_mysqludf_crypt_crypto_provider provider;
    // }

    /*
     * Callback function for call to dl_iterate_phdr in lib_mysqludf_crypt_crypto_get_default_provider
     * The info argument is a structure of the following type:
     *
     * struct dl_phdr_info {
     *      ElfW(Addr)        dlpi_addr;  Base address of object
     *      const char       *dlpi_name;  (Null-terminated) name of object
     *      const ElfW(Phdr) *dlpi_phdr;  Pointer to array of
     *                                    ELF program headers
     *                                    for this object
     *      ElfW(Half)        dlpi_phnum; number of items in dlpi_phdr
     * };
     */
    /* static int lib_mysqludf_crypt_dl_iterate_phdr_callback(struct dl_phdr_info *info, size_t size, void *data) {
        struct storage_object *storage = data;

        if (strstr(info->dlpi_name, "libcrypto.so")) {
            storage_object_put(storage, enum lib_mysqludf_crypt_crypto_provider(OPENSSL));
        } elif (strstr(info->dlpi_name, "libgnutls.so")) {
            storage_object_put(storage, enum lib_mysqludf_crypt_crypto_provider(GNUTLS));
        } elif (strstr(info->dlpi_name, "libbotan-2.so")) {
            storage_object_put(storage, enum lib_mysqludf_crypt_crypto_provider(BOTAN));
        }
        return 0;
    }
    */
    /*
     * This function looks through the loaded libraries and returns a loaded provider by priority
     */
    /* int lib_mysqludf_crypt_crypto_get_default_provider() {
        struct storage_object storage;
        enum lib_mysqludf_crypt_crypto_provider provider;
        dl_iterate_phdr(lib_mysqludf_crypt_dl_iterate_phdr_callback, storage_object);
        /* Order providers by priority */
    /*
        order_providers(storage);
        if (storage_object_length(storage) > 0) {
            provider = storage_object_get(storage, 0);
            return rovider;
        }
        return -1;
    }
    */


#ifdef  __cplusplus
}
#endif

