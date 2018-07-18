#ifndef __AWS_SIGV4_H
#define __AWS_SIGV4_H

#define AWS_SIGV4_SIGNING_ALGORITHM     "AWS4-HMAC-SHA256"
#define AWS_SIGV4_AUTH_HEADER_MAX_LEN   4096

#define AWS_SIGV4_MEMORY_ALLOCATION_ERROR  -2
#define AWS_SIGV4_INVALID_INPUT_ERROR      -1
#define AWS_SIGV4_OK                        0

typedef struct aws_sigv4_str_s {
    char* data;
    size_t len;
} aws_sigv4_str_t;

typedef struct aws_sigv4_params_s {
    /* AWS credential parameters */
    aws_sigv4_str_t secret_access_key;
    aws_sigv4_str_t access_key_id;

    /* HTTP request parameters */
    aws_sigv4_str_t method;
    aws_sigv4_str_t uri;
    aws_sigv4_str_t query_str;
    aws_sigv4_str_t host;
    /* x-amz-date header value in ISO8601 format */
    aws_sigv4_str_t x_amz_date;
    aws_sigv4_str_t payload;

    /* AWS service parameters */
    aws_sigv4_str_t service;
    aws_sigv4_str_t region;
} aws_sigv4_params_t;


/** @brief get credential scope string
 *
 * @param[in] sigv4_params A pointer to a struct of sigv4 parameters
 * @param[out] credential_scope A struct of buffer to store credential scope string
 * @return Status code where zero for success and non-zero for failure
 */
int get_credential_scope(aws_sigv4_params_t* sigv4_params, aws_sigv4_str_t* credential_scope);

/** @brief get signed headers string
 *
 * @param[in] sigv4_params A pointer to a struct of sigv4 parameters
 * @param[out] signed_headers A struct of buffer to store signed headers string
 * @return Status code where zero for success and non-zero for failure
 */
int get_signed_headers(aws_sigv4_params_t* sigv4_params, aws_sigv4_str_t* signed_headers);

/** @brief get canonical headers string
 *
 * @param[in] sigv4_params A pointer to a struct of sigv4 parameters
 * @param[out] canonical_headers A struct of buffer to store canonical headers string
 * @return Status code where zero for success and non-zero for failure
 */
int get_canonical_headers(aws_sigv4_params_t* sigv4_params, aws_sigv4_str_t* canonical_headers);

/** @brief perform sigv4 signing
 *
 * @param[in] sigv4_params A pointer to a struct of sigv4 parameters
 * @param[out] auth_header A struct of buffer to store Authorization header string
 * @return Status code where zero for success and non-zero for failure
 */
int aws_sigv4_sign(aws_sigv4_params_t* sigv4_params, aws_sigv4_str_t* auth_header);

#endif /* __AWS_SIGV4_H */
