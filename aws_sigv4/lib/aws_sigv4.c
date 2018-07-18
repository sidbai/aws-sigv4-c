#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "aws_sigv4.h"

static inline int empty_str(aws_sigv4_str_t str)
{
    return (str.data == NULL || str.len == 0) ? 1 : 0;
}

int get_credential_scope(aws_sigv4_params_t* sigv4_params, aws_sigv4_str_t* credential_scope)
{
    int rc = AWS_SIGV4_OK;
    if (credential_scope == NULL
        || credential_scope->data == NULL
        || sigv4_params == NULL
        || empty_str(sigv4_params->x_amz_date)
        || empty_str(sigv4_params->region)
        || empty_str(sigv4_params->service))
    {
        rc = AWS_SIGV4_INVALID_INPUT_ERROR;
        goto finished;
    }
    char* str = credential_scope->data;
    /* get date in yyyymmdd format */
    strncpy(str, sigv4_params->x_amz_date.data, 8);
    str += 8;
    *str = '/';
    str++;

    strncpy(str, sigv4_params->region.data, sigv4_params->region.len);
    str += sigv4_params->region.len;
    *str = '/';
    str++;

    strncpy(str, sigv4_params->service.data, sigv4_params->service.len);
    str += sigv4_params->service.len;
    *str = '/';
    str++;

    strncpy(str, "aws4_request", 12);
    str += 12;

    credential_scope->len = str - credential_scope->data;
finished:
    return rc;
}

int get_signed_headers(aws_sigv4_params_t* sigv4_params, aws_sigv4_str_t* signed_headers)
{
    int rc = AWS_SIGV4_OK;
    if (signed_headers == NULL
        || signed_headers->data == NULL
        || sigv4_params == NULL
        || empty_str(sigv4_params->host)
        || empty_str(sigv4_params->x_amz_date))
    {
        rc = AWS_SIGV4_INVALID_INPUT_ERROR;
        goto finished;
    }
    const char* str = "host;x-amz-date";
    size_t str_len = strlen(str);
    strncpy(signed_headers->data, str, str_len);
    signed_headers->len = str_len;
finished:
    return rc;
}

int get_canonical_headers(aws_sigv4_params_t* sigv4_params, aws_sigv4_str_t* canonical_headers)
{
    int rc = AWS_SIGV4_OK;
    if (canonical_headers == NULL
        || canonical_headers->data == NULL
        || sigv4_params == NULL
        || empty_str(sigv4_params->host)
        || empty_str(sigv4_params->x_amz_date))
    {
        rc = AWS_SIGV4_INVALID_INPUT_ERROR;
        goto finished;
    }
    char* str = canonical_headers->data;
    strncpy(str, "host:", 5);
    str += 5;
    /* TODO: Add logic to remove leading and trailing spaces for header values*/
    strncpy(str, sigv4_params->host.data, sigv4_params->host.len);
    str += sigv4_params->host.len;
    *str = '\n';
    str++;

    strncpy(str, "x-amz-date:", 11);
    str += 11;
    strncpy(str, sigv4_params->x_amz_date.data, sigv4_params->x_amz_date.len);
    str += sigv4_params->x_amz_date.len;
    *str = '\n';
    str++;

    canonical_headers->len = str - canonical_headers->data;
finished:
    return rc;
}

int aws_sigv4_sign(aws_sigv4_params_t* sigv4_params, aws_sigv4_str_t* auth_header)
{
    if (auth_header == NULL)
    {
        goto err;
    }

    /* TODO: Support custom memory allocator */
    auth_header->data = malloc(AWS_SIGV4_AUTH_HEADER_MAX_LEN);
    if (auth_header->data == NULL)
    {
        goto err;
    }
    int len = 0;
    return len;
err:
    /* deallocate memory in case of failure */
    if (auth_header && auth_header->data)
    {
        free(auth_header->data);
        auth_header->data = NULL;
    }
    return 0;
}
