#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include "aws_sigv4.h"

static inline int empty_str(aws_sigv4_str_t str)
{
    return (str.data == NULL || str.len == 0) ? 1 : 0;
}

int get_hex_sha256(aws_sigv4_str_t* str_in, char hex_sha256_out[AWS_SIGV4_HEX_SHA256_LENGTH])
{
    if (str_in == NULL)
    {
        return AWS_SIGV4_INVALID_INPUT_ERROR;
    }
    unsigned char sha256_buf[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, str_in->data, str_in->len);
    SHA256_Final(sha256_buf, &ctx);

    static const char digits[] = "0123456789abcdef";
    char* c_ptr = hex_sha256_out;
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        *(c_ptr++) = digits[(sha256_buf[i] & 0xf0) >> 4];
        *(c_ptr++) = digits[sha256_buf[i] & 0x0f];
    }
    return AWS_SIGV4_OK;
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
    /* TODO: Add logic to remove leading and trailing spaces for header values */
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

int get_canonical_request(aws_sigv4_params_t* sigv4_params, aws_sigv4_str_t* canonical_request)
{
    int rc = AWS_SIGV4_OK;
    if (canonical_request == NULL
        || canonical_request->data == NULL
        || sigv4_params == NULL
        || empty_str(sigv4_params->method)
        || empty_str(sigv4_params->uri)
        || empty_str(sigv4_params->query_str))
    {
        rc = AWS_SIGV4_INVALID_INPUT_ERROR;
        goto finished;
    }
    char* str = canonical_request->data;
    strncpy(str, sigv4_params->method.data, sigv4_params->method.len);
    str += sigv4_params->method.len;
    *str = '\n';
    str++;

    /* TODO: Here we assume the URI has already been encoded. Add encoding logic in future. */
    strncpy(str, sigv4_params->uri.data, sigv4_params->uri.len);
    str += sigv4_params->uri.len;
    *str = '\n';
    str++;

    /* TODO: Here we assume the query string has already been encoded. Add encoding logic in future. */
    strncpy(str, sigv4_params->query_str.data, sigv4_params->query_str.len);
    str += sigv4_params->query_str.len;
    *str = '\n';
    str++;

    aws_sigv4_str_t canonical_headers = { .data = str, .len = 0 };
    rc = get_canonical_headers(sigv4_params, &canonical_headers);
    if (rc != AWS_SIGV4_OK)
    {
        goto finished;
    }
    str += canonical_headers.len;
    *str = '\n';
    str++;

    aws_sigv4_str_t signed_headers = { .data = str, .len = 0 };
    rc = get_signed_headers(sigv4_params, &signed_headers);
    if (rc != AWS_SIGV4_OK)
    {
        goto finished;
    }
    str += signed_headers.len;
    *str = '\n';
    str++;

    rc = get_hex_sha256(&sigv4_params->payload, str);
    if (rc != AWS_SIGV4_OK)
    {
        goto finished;
    }
    str += AWS_SIGV4_HEX_SHA256_LENGTH;

    canonical_request->len = str - canonical_request->data;
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
