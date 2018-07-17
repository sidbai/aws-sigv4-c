#ifndef AWS_SIGV4_H
#define AWS_SIGV4_H

#define AWS_SIGV4_SIGNING_ALGORITHM     "AWS4-HMAC-SHA256"
#define AWS_SIGV4_AUTH_HEADER_MAX_LEN   4096

typedef struct aws_sigv4_params_s {
    /* AWS credential parameters */
    char* secret_access_key;
    char* access_key_id;

    /* HTTP request parameters */
    char* method;
    char* uri;
    char* query_str;
    char* host;
    /* x-amz-date header value in ISO8601 format */
    char* x_amz_date;
    char* payload;

    /* AWS service parameters */
    char* service;
    char* region;
} aws_sigv4_params_t;

/** @brief get credential scope string
 *
 * @param[in] sigv4_params A pointer to a struct of sigv4 parameters
 * @param[in] credential_scope A buffer to store credential scope string
 * @return Non-zero signed header string length and 0 on failure
 */
int get_credential_scope(aws_sigv4_params_t* sigv4_params, char* credential_scope);

/** @brief get signed headers string
 *
 * @param[in] sigv4_params A pointer to a struct of sigv4 parameters
 * @param[in] signed_headers A buffer to store signed headers string
 * @return Non-zero signed header string length and 0 on failure
 */
int get_signed_headers(aws_sigv4_params_t* sigv4_params, char* signed_headers);

/** @brief perform sigv4 signing
 *
 * @param[in] sigv4_params A pointer to a struct of sigv4 parameters
 * @param[out] auth_header A pointer to the Authorization header string
 * @return Non-zero Authorization header length and 0 on failure
 */
int aws_sigv4_sign(aws_sigv4_params_t* sigv4_params, char** auth_header);

#endif // AWS_SIGV4_H
