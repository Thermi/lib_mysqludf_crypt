#include <stdio.h>
#include <time.h>   // for clock_t, clock()
#include <unistd.h> // for sleep()

#include <mysql.h>
#include <lib_mysqludf_crypt.h>
#define BILLION  1000000000.0;

// main function to find the execution time of a C program
bool test(UDF_INIT *initid, UDF_ARGS *args, char message[MYSQL_ERRMSG_SIZE],
    char error[MYSQL_ERRMSG_SIZE], char *is_null) {
    my_bool ret;
    double time_spent;
    struct timespec start, end;

    /* init initid and args */
    clock_gettime(CLOCK_REALTIME, &start);
    ret = lib_mysqludf_crypt_constant_time_compare_init(initid, args, message);
    /* init and run */
    ret = lib_mysqludf_crypt_constant_time_compare(initid, args, is_null, error);

    clock_gettime(CLOCK_REALTIME, &end);
    fprintf(stderr, "Comparison result: %d\n", ret);
    // time_spent = end - start
    time_spent = (end.tv_sec - start.tv_sec) +
                        (end.tv_nsec - start.tv_nsec) / BILLION;

    printf("Time elpased is %f seconds\n", time_spent);
    return ret;

}

int main()
{
    char message[MYSQL_ERRMSG_SIZE];
    char error[MYSQL_ERRMSG_SIZE];
    char is_null[2] = {
        0,
        0
    };
    char null_chars[2] = {
        false,
        false
    };
    char args_chars[2][4096];
    char *args_pointers[2];
    long unsigned lengths_args[2] = {4096, 4096};

    args_pointers[0] = args_chars[0];
    args_pointers[1] = args_chars[1];

    enum Item_result arg_type_args[2] = {STRING_RESULT, STRING_RESULT};

    UDF_INIT initid = {
        .maybe_null = 0,
        .decimals = 0,
        .max_length = 0,
        .ptr = NULL,
        .const_item = 0
    };

    UDF_ARGS args = { 
        .arg_count = 2,
        .lengths = lengths_args,
        .args = args_pointers,
        .maybe_null = null_chars,
        .arg_type = arg_type_args
    };
    
    for(uint64_t i=0; i<4096;i++) {
        /* test 4096*a and 4096*b */
        memset(message, 0, sizeof(message));
        memset(message, 0, sizeof(error));
     
        memset(args_chars[0], 'a', 4096);
        memset(args_chars[1], 'b', 4096);


        test(&initid, &args, message, error, is_null);
        /* test 4096*a and 4095*a + 1*b */

        memset(args_chars[0], 'a', 4096);
        memset(args_chars[1], 'a', 4095);
        args_chars[1][4095] = 'b';

        test(&initid, &args, message, error, is_null);        
    }

    return 0;
}
