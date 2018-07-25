#ifndef __AWS_SIGV4_H
#define __AWS_SIGV4_H

#define AWS_SIGV4_MEMORY_ALLOCATION_ERROR  -2
#define AWS_SIGV4_INVALID_INPUT_ERROR      -1
#define AWS_SIGV4_OK                        0

#include "aws_sigv4_common.h"

typedef struct aws_sigv4_header_s {
  aws_sigv4_str_t name;
  aws_sigv4_str_t value;
} aws_sigv4_header_t;

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

/** @brief get hex encoding of a given string
 *
 * @param[in] str_in Input string
 * @param[out] hex_out Output buffer to store hex encoded string
 */
void get_hexdigest(aws_sigv4_str_t* str_in, aws_sigv4_str_t* hex_out);

/** @brief get hex encoded sha256 of a given string
 *
 * @param[in] str_in Input string
 * @param[out] hex_sha256_out Output buffer to store hex encoded sha256 string
 */
void get_hex_sha256(aws_sigv4_str_t* str_in, aws_sigv4_str_t* hex_sha256_out);

/** @brief derive signing key
 *
 * @param[in] sigv4_params A pointer to a struct of sigv4 parameters
 * @param[out] signing_key A struct of buffer to store derived signing key
 */
void get_signing_key(aws_sigv4_params_t* sigv4_params, aws_sigv4_str_t* signing_key);

/** @brief get credential scope string
 *
 * @param[in] sigv4_params A pointer to a struct of sigv4 parameters
 * @param[out] credential_scope A struct of buffer to store credential scope string
 */
void get_credential_scope(aws_sigv4_params_t* sigv4_params, aws_sigv4_str_t* credential_scope);

/** @brief get signed headers string
 *
 * @param[in] sigv4_params A pointer to a struct of sigv4 parameters
 * @param[out] signed_headers A struct of buffer to store signed headers string
 */
void get_signed_headers(aws_sigv4_params_t* sigv4_params, aws_sigv4_str_t* signed_headers);

/** @brief get canonical headers string
 *
 * @param[in] sigv4_params A pointer to a struct of sigv4 parameters
 * @param[out] canonical_headers A struct of buffer to store canonical headers string
 */
void get_canonical_headers(aws_sigv4_params_t* sigv4_params, aws_sigv4_str_t* canonical_headers);

/** @brief get canonical request string
 *
 * @param[in] sigv4_params A pointer to a struct of sigv4 parameters
 * @param[out] canonical_request A struct of buffer to store canonical request string
 */
void get_canonical_request(aws_sigv4_params_t* sigv4_params, aws_sigv4_str_t* canonical_request);

/** @brief get string to sign
 *
 * @param[in] request_date A pointer to a struct of request date in ISO8601 format
 * @param[in] credential_scope A pointer to a struct of precomputed credential scope
 * @param[in] canonical_request A pointer to a struct of precomputed canonical request
 * @param[out] string_to_sign A struct of buffer to store string to sign
 */
void get_string_to_sign(aws_sigv4_str_t* request_date, aws_sigv4_str_t* credential_scope,
                        aws_sigv4_str_t* canonical_request, aws_sigv4_str_t* string_to_sign);

/** @brief perform sigv4 signing
 *
 * @param[in] sigv4_params A pointer to a struct of sigv4 parameters
 * @param[out] auth_header A struct to store Authorization header string
 * @return Status code where zero for success and non-zero for failure
 */
int aws_sigv4_sign(aws_sigv4_params_t* sigv4_params, aws_sigv4_header_t* auth_header);

#endif /* __AWS_SIGV4_H */
