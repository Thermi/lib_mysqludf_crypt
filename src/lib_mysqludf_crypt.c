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
        botan_hash_update(*botan_hash_structure, (const unsigned char *) args->args[0], args->lengths[0]);
        botan_hash_final(*botan_hash_structure, output_buffer);

        botan_hex_encode(output_buffer, *length, pointers->hex_data, 0);

        /* two times because of hex encoding*/
        //(*length) *= 2;

        result = pointers->hex_data;

        /* deinit */
        botan_hash_destroy(*botan_hash_structure);
        free(botan_hash_structure);
        free(output_buffer);
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
            snprintf(message, MYSQL_ERRMSG_SIZE, "Could not allocate enough memory for the hash structure.\n",
                hash_udf_name);
            free(hash_udf_name);
            return 1;
        }
        ret = botan_hash_init(hash_structure, hash_name, 0);
        if (ret) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "Could not initialize the hash structure. "
                "Reported failure: %s\n", hash_udf_name, botan_error_description(ret));
            free(hash_udf_name);
            return 1;
        }
        botan_hash_output_length(*hash_structure, &length);
        char *output_data = malloc(length);

        if (!output_data) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "Could not initialize the buffer for the result.\n",
                hash_udf_name);
            free(hash_udf_name);
            return 1;
        }

        char *hex_data = malloc(length*2);
        if (!hex_data) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "Could not initialize the hex buffer for the result.\n",
                hash_udf_name);
            free(hash_udf_name);
            return 1;
        }

        struct hash_data_storage *hash_data_storage = malloc(sizeof(struct hash_data_storage));
        if (!hash_data_storage) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "Could not allocate the buffer for the hash data storage.\n",
                hash_udf_name);
            free(hash_udf_name);
            free(hex_data);
            return 1;
        }
        hash_data_storage->hash_structure = hash_structure;
        hash_data_storage->output_data = output_data;
        hash_data_storage->hex_data = hex_data;

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

    static my_bool switch_case_arg_type(UDF_ARGS *args, char **selected_rng_type, uint64_t *bytes_to_request, char *message) {
        /* exactly two args */
        bool got_rng_type = false;
        bool got_bytes_to_request = false;

        for (int i=0; i<2;i++) {
            switch(args->arg_type[i]) {
                case INT_RESULT:
                    if (!got_bytes_to_request) {
                        *bytes_to_request = *(uint *) (args->args[i]);
                        got_bytes_to_request = true;
                    } else {
                        snprintf(message, MYSQL_ERRMSG_SIZE, "Invalid argument: Reject specification of amount of randomness twice.\n");
                        return 1;
                    }
                break;
                case STRING_RESULT:
                    if (!got_rng_type) {
                        *selected_rng_type = calloc(sizeof(char), args->lengths[i]+1);
                        if (!*selected_rng_type) {
                            snprintf(message, MYSQL_ERRMSG_SIZE, "Could not allocate enough memory for the RNG type name.\n");
                            return 1;
                        }

                        snprintf(*selected_rng_type, args->lengths[i]+1, "%s", args->args[i]);
                        got_rng_type = true;
                    } else {
                        snprintf(message, MYSQL_ERRMSG_SIZE, "Invalid argument: Rejected specification of RNG type twice.\n");
                        return 1;
                    }
                break;
                default:
                    snprintf(message, MYSQL_ERRMSG_SIZE, "Invalid argument: Wrong argument type.\n");
                    return 1;
                break;
            }
        }
        return 0;
    }

    DLLEXP my_bool lib_mysqludf_crypt_random_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
        uint64_t bytes_to_request = 8;
        int ret;
        char *selected_rng_type = "system";

        struct rng_data_storage *rng_data_storage;

        switch(args->arg_count) {
            case 0:
            /* no args, this is fine. */
            break;
            case 1:
                switch(args->arg_type[0]) {
                    case INT_RESULT:
                        bytes_to_request = *(int *) (args->args[0]);
                    break;
                    case STRING_RESULT:
                        selected_rng_type = calloc(sizeof(char), args->lengths[0]+1);
                        snprintf(selected_rng_type, args->lengths[0], "%s", args->args[0]);
                    break;
                    default:
                        snprintf(message, MYSQL_ERRMSG_SIZE, "Invalid argument: Wrong argument type.\n");
                        return 1;
                    break;
                }
            break;
            case 2:
                ret = switch_case_arg_type(args, &selected_rng_type, &bytes_to_request, message);
                if (ret) {
                    return ret;
                }
                break;
            default:
                /* Too many args */
                snprintf(message, MYSQL_ERRMSG_SIZE, "Takes at most two arguments.\n");
                return 1;
            break;
        }

        if (!bytes_to_request) {
                snprintf(message, MYSQL_ERRMSG_SIZE, "You can not request 0 bytes of randomness.\n");
                return 1;
        }
        /* Allocate memory for structures */

        rng_data_storage = malloc(sizeof(struct rng_data_storage));

        if (!rng_data_storage) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "Could not allocate enough memory for the data storage structure.\n");
            return 1;
        }

        ret = botan_rng_init(&rng_data_storage->rng_structure, selected_rng_type);

        if(ret) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "Could not initialize the rng structure: "
                "%s\n", botan_error_description(ret));
            free(rng_data_storage);
            return 1;
        }

        /* Allocate memory for output buffer */
        rng_data_storage->output_data = malloc(sizeof(char)*bytes_to_request*2);

        if(!rng_data_storage->output_data) {
            botan_rng_destroy(rng_data_storage->rng_structure);
            snprintf(message, MYSQL_ERRMSG_SIZE, "Could not allocate enough memory for the random data buffer.\n",
                bytes_to_request);
            free(rng_data_storage);
            return 1;
        }

        rng_data_storage->hex_buffer = malloc(sizeof(char)*bytes_to_request*2);

        if (!rng_data_storage->hex_buffer) {
            botan_rng_destroy(rng_data_storage->rng_structure);
            snprintf(message, MYSQL_ERRMSG_SIZE, "Could not allocate enough memory for the output buffer.\n");
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
            snprintf(message, MYSQL_ERRMSG_SIZE, "Does not take any arguments.\n");
            return 1;
        }
        return 0;
    }

    DLLEXP my_bool lib_mysqludf_crypt_base64_encode_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
        struct base64_data_storage *storage;
        if (args->arg_count != 1) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "Requires exactly one argument.\n");
            return 1;
        }

        storage = malloc(sizeof(struct base64_data_storage));

        if (!storage) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "%ld, could not allocate enough memory for the the data structure.\n",
                sizeof(struct base64_data_storage));
            return 1;
        }

        storage->length = args->lengths[0]*2;

        if(storage->length < 2) {
            storage->length = 2;
        }

        storage->storage = malloc(sizeof(char)*storage->length);
        if (!storage->storage) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "%ld, could not allocate enough memory for the output buffer.\n",
                storage->length);
            free(storage);
            return 1;
        }
        initid->ptr = (char *)storage;

        return 0;
    }

    DLLEXP my_bool lib_mysqludf_crypt_base64_decode_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
        struct base64_data_storage *storage;
        if (args->arg_count != 1) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "Requires exactly one argument.\n");
            return 1;
        }

        storage = malloc(sizeof(struct base64_data_storage));

        if (!storage) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "Could not allocate enough memory for the the data structure.\n");
            return 1;
        }

        storage->length = args->lengths[0]*2;

        if (storage->length < 2) {
            storage->length = 2;
        }

        storage->storage = malloc(sizeof(char)*storage->length);

        if (!storage->storage) {
            snprintf(message, MYSQL_ERRMSG_SIZE, "Could not allocate enough memory for the output buffer.\n");
            free(storage);
            return 1;
        }
        initid->ptr = (char *)storage;

        return 0;
    }

    DLLEXP char *lib_mysqludf_crypt_sha1(UDF_INIT *initid, UDF_ARGS *args,
        char *result, unsigned long *length, char *is_null, char *error) {
        return hash_common_operation(initid, args, result, length, is_null, error);
    }

    DLLEXP char *lib_mysqludf_crypt_sha256(UDF_INIT *initid, UDF_ARGS *args,
        char *result, unsigned long *length, char *is_null, char *error) {
        return hash_common_operation(initid, args, result, length, is_null, error);
    }
    
    DLLEXP char *lib_mysqludf_crypt_sha384(UDF_INIT *initid, UDF_ARGS *args,
        char *result, unsigned long *length, char *is_null, char *error) {
        return hash_common_operation(initid, args, result, length, is_null, error);
    }

    DLLEXP char *lib_mysqludf_crypt_sha512(UDF_INIT *initid, UDF_ARGS *args,
        char *result, unsigned long *length, char *is_null, char *error) {
        return hash_common_operation(initid, args, result, length, is_null, error);
    }


    DLLEXP char *lib_mysqludf_crypt_sha3(UDF_INIT *initid, UDF_ARGS *args,
        char *result, unsigned long *length, char *is_null, char *error) {
        return hash_common_operation(initid, args, result, length, is_null, error);
    }

    DLLEXP char *lib_mysqludf_crypt_blake2b(UDF_INIT *initid, UDF_ARGS *args,
        char *result, unsigned long *length, char *is_null, char *error) {
        return hash_common_operation(initid, args, result, length, is_null, error);
    }

    DLLEXP char *lib_mysqludf_crypt_argon2(UDF_INIT *initid, UDF_ARGS *args,
        char *result, unsigned long *length, char *is_null, char *error) {
        return NULL;
        /* return hash_argon2_operation(initid, args, result, length, is_null, error); */
    }

    DLLEXP char *lib_mysqludf_crypt_scrypt(UDF_INIT *initid, UDF_ARGS *args,
        char *result, unsigned long *length, char *is_null, char *error) {
        return NULL;
        /* return hash_scrypt_operation(initid, args, result, length, is_null, error); */
    }

    DLLEXP long long lib_mysqludf_crypt_constant_time_compare(UDF_INIT *initid, UDF_ARGS *args,
        char *is_null, char *error) {
        if (args->arg_count != 2) {
            *error = 1;
            snprintf(error, MYSQL_ERRMSG_SIZE, "Takes exactly two arguments.\n");
            return 1;
        }

        if (!args->args[0]) {
            *error = 1;
            snprintf(error, MYSQL_ERRMSG_SIZE, "First argument must not be NULL.\n");
            return 1;
        }

        if (!args->args[1]) {
            *error = 1;
            snprintf(error, MYSQL_ERRMSG_SIZE, "Second argument must not be NULL.\n");
            return 1;
        }
        /* Use botan_constant_time_compare instead */
        return (long long) constant_time_compare(args->args[0], args->args[1], args->lengths[0], args->lengths[1]);
    }

    DLLEXP char *lib_mysqludf_crypt_info(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error) {
        char *return_message = malloc(strlen(PACKAGE_STRING)+1);
        strncpy(return_message, PACKAGE_STRING, strlen(PACKAGE_STRING)+1);
        return return_message;
    }

    DLLEXP char *lib_mysqludf_crypt_random(UDF_INIT *initid, UDF_ARGS *args,
        char *result, unsigned long *length, char *is_null, char *error) {

        struct rng_data_storage *data_storage = (struct rng_data_storage *) initid->ptr;
        int ret = botan_rng_get(data_storage->rng_structure, data_storage->output_data,
            data_storage->output_data_length);

        if(ret) {
            *error = true;
            *length = snprintf(error, MYSQL_ERRMSG_SIZE, "Could not get random data from the rng. "
                "Reported failure: %s\n", botan_error_description(ret));
            botan_rng_destroy(data_storage->rng_structure);
            free(data_storage->hex_buffer);
            free(data_storage->output_data);
            free(data_storage);
            *is_null = true;
            return NULL;
        }

        ret = botan_rng_destroy(data_storage->rng_structure);

        if (ret) {
            *error = true;
            *length = snprintf(error, MYSQL_ERRMSG_SIZE, "Failed to destroy RNG: %s",
                botan_error_description(ret));
            free(data_storage->hex_buffer);
            free(data_storage->output_data);
            free(data_storage);
            *is_null = true;
            return NULL;
        }
        /* probably should hex encode the output, so it's always a valid string */
        ret = botan_hex_encode(data_storage->output_data, data_storage->output_data_length,
            data_storage->hex_buffer, 0);

        free(data_storage->output_data);

        if (ret) {
            *error = true;
            *length = snprintf(error, MYSQL_ERRMSG_SIZE, "Could not hex encode the string: %s",
                botan_error_description(ret));
            free(data_storage->hex_buffer);
            *is_null = true;
            return NULL;
        }

        *length = data_storage->output_data_length*2;
        result = data_storage->hex_buffer;
        free(data_storage);
        return result;
    }

    DLLEXP char *lib_mysqludf_crypt_base64_encode(UDF_INIT *initid, UDF_ARGS *args,
        char *result, unsigned long *length, char *is_null, char *error) {

        struct base64_data_storage *storage = (struct base64_data_storage *) initid->ptr;
        int ret = botan_base64_encode((const uint8_t *) args->args[0], args->lengths[0],
            storage->storage, &storage->length);

        if(ret) {
            *error = true;
            *length = snprintf(result, MYSQL_ERRMSG_SIZE, "Could not encode the data. Reported failure: %s\n",
                botan_error_description(ret));
            free(storage->storage);
            free(storage);
            return result;
        }
        *error = false;
        *length = storage->length;
        result = storage->storage;
        free(storage);
        return result;
    }


    DLLEXP char *lib_mysqludf_crypt_base64_decode(UDF_INIT *initid, UDF_ARGS *args,
        char *result, unsigned long *length, char *is_null, char *error) {

        struct base64_data_storage *storage = (struct base64_data_storage *) initid->ptr;

        int ret = botan_base64_decode(args->args[0], args->lengths[0],
            (uint8_t *) storage->storage, &storage->length);

        if(ret) {
            *error = true;
            *length = snprintf(result, MYSQL_ERRMSG_SIZE, "Could not decode the data. Reported failure: %s\n",
                botan_error_description(ret));
            free(storage->storage);
            free(storage);
            return result;
        }
        *error = false;
        *length = storage->length;
        result = storage->storage;
        free(storage);
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
        Order providers by priority
    
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

