#include <stdio.h>
#include <stdint.h>
#include <gmssl/sm3.h>
#include <sys/time.h>

#include "../params.h"
#include "../xmss.h"

#ifdef XMSSMT
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_KEYPAIR xmssmt_keypair
#else
    #define XMSS_STR_TO_OID xmss_str_to_oid
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_KEYPAIR xmss_keypair
#endif

int main(int argc, char **argv)
{
    xmss_params params;
    uint32_t oid = 0;
    int parse_oid_result = 0;

    if (argc != 3) {
        fprintf(stderr, "Expected parameter string (e.g. 'XMSS-SHA2_10_256')"
                        " as only parameter.\n"
                        "The keypair is written to a file named after the second parameter.\n");
        return -1;
    }

    XMSS_STR_TO_OID(&oid, argv[1]);
    parse_oid_result = XMSS_PARSE_OID(&params, oid);
    if (parse_oid_result != 0) {
        fprintf(stderr, "Error parsing oid.\n");
        return parse_oid_result;
    }

    FILE *keypair_file = fopen(argv[2], "wb");

    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char sk[XMSS_OID_LEN + params.sk_bytes];

    struct timeval start, end;
    gettimeofday(&start, NULL);

    XMSS_KEYPAIR(pk, sk, oid);

    gettimeofday(&end, NULL);
    unsigned long long timeuse = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
    printf("time = %lf seconds\n", timeuse/1000000.0);

    printf("Compress function called: %lld times\n", count);

    fwrite(pk, 1, XMSS_OID_LEN + params.pk_bytes, keypair_file);
    fwrite(sk, 1, XMSS_OID_LEN + params.sk_bytes, keypair_file);

    fclose(keypair_file);

    return 0;
}
