/*
    lib_mysqludf_crypt - a library for cryptographic primitives and functions for password authentication
    Copyright (C) 2019 Noel Kuntze
    email: noel.kuntze@thermi.consulting
*/


#ifndef MYSQLUDF_CRYPT_H_
#define MYSQLUDF_CRYPT_H_

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
#define DLLEXP __declspec(dllexport)
#else
#define DLLEXP
#endif

#ifdef STANDARD
/* STANDARD is defined, don't use any mysql functions */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <link.h>
#include <threads.h>

#ifdef __WIN__
typedef unsigned __int64 ulonglong; /* Microsofts 64 bit types */
typedef __int64 longlong;
#else
typedef unsigned long long ulonglong;
typedef long long longlong;
#endif /*__WIN__*/

#else
#include <my_global.h>
#include <my_sys.h>
#include <m_string.h>

#endif

#include <mysql.h>
#include <ctype.h>

#include "config.h"
#include <botan/ffi.h>

#ifndef LIB_MYSQLUDF_CRYPT_PROVIDER_ENV
#define LIB_MYSQLUDF_CRYPT_PROVIDER_ENV "LIB_MYSQLUDF_CRYPT_PROVIDER"
#endif

#ifndef LIBMYSQLUDF_CRYPT_VERSION
#define LIBMYSQLUDF_CRYPT_VERSION "0.0.0"
#endif

#include "mysqludf.h"

/* Right now only botan is supported because the API of openssl is stupid
 * and gnutls doesn't have any API for the primitives yet
 */

enum lib_mysqludf_crypt_crypto_provider {
    OPENSSL,
    GNUTLS,
    BOTAN
};

enum lib_mysqludf_crypt_hashes {
    SHA256,
    SHA384,
    SHA512,
    SHA3,
    BLAKE2,
    ARGON2,
    SCRPYT
};

struct hash_data_storage {
    botan_hash_t *hash_structure;
    void *output_data;
};

struct rng_data_storage {
    botan_rng_t *rng_structure;
    uint64_t output_data_length;
    void *output_data;
};

#endif /* MYSQLUDF_CRYPT_H_ */

