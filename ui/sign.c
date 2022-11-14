#include <stdio.h>
#include <stdlib.h>
#include <gmssl/sm3.h>
#include <sys/time.h>

#include "../params.h"
#include "../xmss.h"
#include "../utils.h"

#ifdef XMSSMT
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_SIGN xmssmt_sign
#else
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_SIGN xmss_sign
#endif

int main(int argc, char **argv) {
    FILE *keypair_file;
    FILE *m_file;
    FILE *sm_file;

    xmss_params params;
    uint32_t oid_pk = 0;
    uint32_t oid_sk = 0;
    uint8_t buffer[XMSS_OID_LEN];
    int parse_oid_result;

    unsigned long long mlen;

    if (argc != 4) {
        fprintf(stderr, "Expected keypair, message and sign + message filenames as three "
                        "parameters.\n"
                        "The keypair is updated with the changed state, "
                        "and the message + signature is output to a file named after the third parameter.\n");
        return -1;
    }

    keypair_file = fopen(argv[1], "r+b");
    if (keypair_file == NULL) {
        fprintf(stderr, "Could not open keypair file.\n");
        return -1;
    }

    m_file = fopen(argv[2], "rb");
    if (m_file == NULL) {
        fprintf(stderr, "Could not open message file.\n");
        fclose(keypair_file);
        return -1;
    }

    sm_file = fopen(argv[3], "wb");

    /* Find out the message length. */
    fseek(m_file, 0, SEEK_END);
    mlen = ftell(m_file);

    /* Read the OID from the public key, as we need its length to seek past it */
    fread(&buffer, 1, XMSS_OID_LEN, keypair_file);
    /* The XMSS_OID_LEN bytes in buffer are a big-endian uint32. */
    oid_pk = (uint32_t)bytes_to_ull(buffer, XMSS_OID_LEN);
    parse_oid_result = XMSS_PARSE_OID(&params, oid_pk);
    if (parse_oid_result != 0) {
        fprintf(stderr, "Error parsing public key oid.\n");
        fclose(keypair_file);
        fclose(m_file);
        return parse_oid_result;
    }

    /* fseek past the public key */
    fseek(keypair_file, params.pk_bytes, SEEK_CUR);
    /* This is the OID we're actually going to use. Likely the same, but still. */
    fread(&buffer, 1, XMSS_OID_LEN, keypair_file);
    oid_sk = (uint32_t)bytes_to_ull(buffer, XMSS_OID_LEN);
    parse_oid_result = XMSS_PARSE_OID(&params, oid_sk);
    if (parse_oid_result != 0) {
        fprintf(stderr, "Error parsing secret key oid.\n");
        fclose(keypair_file);
        fclose(m_file);
        return parse_oid_result;
    }

    unsigned char sk[XMSS_OID_LEN + params.sk_bytes];
    unsigned char *m = malloc(mlen);
    unsigned char *sm = malloc(params.sig_bytes + mlen);
    unsigned long long smlen;

    /* fseek back to start of sk. */
    fseek(keypair_file, -((long int)XMSS_OID_LEN), SEEK_CUR);
    fseek(m_file, 0, SEEK_SET);
    fread(sk, 1, XMSS_OID_LEN + params.sk_bytes, keypair_file);
    fread(m, 1, mlen, m_file);

    struct timeval start, end;
    gettimeofday(&start, NULL);

    XMSS_SIGN(sk, sm, &smlen, m, mlen);

    gettimeofday(&end, NULL);
    unsigned long long timeuse = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
    printf("time = %lf seconds\n", timeuse/1000000.0);

    printf("Compress function called: %lld times\n", count);

    fseek(keypair_file, -((long int)params.sk_bytes), SEEK_CUR);
    fwrite(sk + XMSS_OID_LEN, 1, params.sk_bytes, keypair_file);
    fwrite(sm, 1, smlen, sm_file);

    fclose(keypair_file);
    fclose(m_file);
    fclose(sm_file);

    free(m);
    free(sm);

    return 0;
}
