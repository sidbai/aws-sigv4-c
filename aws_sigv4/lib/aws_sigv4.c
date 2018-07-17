#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "aws_sigv4.h"

int get_credential_scope(aws_sigv4_params_t* sigv4_params, char* credential_scope)
{
    if (credential_scope == NULL
        || sigv4_params == NULL
        || sigv4_params->x_amz_date == NULL
        || sigv4_params->region == NULL
        || sigv4_params->service == NULL)
    {
        goto err;
    }
    char* curr = credential_scope;
    /* get date in yyyymmdd format */
    strncpy(curr, sigv4_params->x_amz_date, 8);
    curr += 8;
    *curr = '/';
    curr++;

    size_t region_len = strlen(sigv4_params->region);
    strncpy(curr, sigv4_params->region, region_len);
    curr += region_len;
    *curr = '/';
    curr++;

    size_t service_len = strlen(sigv4_params->service);
    strncpy(curr, sigv4_params->service, service_len);
    curr += service_len;
    *curr = '/';
    curr++;

    strncpy(curr, "aws4_request", 12);
    curr += 12;

    return curr - credential_scope;
err:
    return 0;
}

int aws_sigv4_sign(aws_sigv4_params_t* sigv4_params, char** auth_header)
{
    if (auth_header == NULL)
    {
        goto err;
    }

    /* TODO: Support custom memory allocator */
    *auth_header = malloc(AWS_SIGV4_AUTH_HEADER_MAX_LEN);
    if (*auth_header == NULL)
    {
        goto err;
    }
    int len = 0;
    return len;
err:
    /* deallocate memory in case of failure */
    if (auth_header && *auth_header)
    {
        free(*auth_header);
        *auth_header = NULL;
    }
    return 0;
}

int test()
{
    return 0;
}
