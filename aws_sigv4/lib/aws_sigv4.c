#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "aws_sigv4.h"

#define AWS_SIGV4_SIGNING_ALGORITHM    "AWS4-HMAC-SHA256"
#define AWS_SIGV4_HEX_SHA256_LENGTH SHA256_DIGEST_LENGTH * 2
#define AWS_SIGV4_AUTH_HEADER_MAX_LEN         1024
#define AWS_SIGV4_CANONICAL_REQUEST_BUFF_LEN  4096
#define AWS_SIGV4_STRING_TO_SIGN_BUFF_LEN     4096
#define AWS_SIGV4_KEY_BUFF_LEN                256


static inline int empty_str(aws_sigv4_str_t* str)
{
  return (str == NULL || str->data == NULL || str->len == 0) ? 1 : 0;
}

static inline void cleanup_str(aws_sigv4_str_t* str)
{
  if (str != NULL && str->data != NULL)
  {
    memset(str->data, 0, str->len);
    str->len = 0;
  }
}

int get_hexdigest(aws_sigv4_str_t* str_in, aws_sigv4_str_t* hex_out)
{
  if (str_in == NULL
      || hex_out == NULL
      || hex_out->data == NULL)
  {
    return AWS_SIGV4_INVALID_INPUT_ERROR;
  }
  static const unsigned char digits[] = "0123456789abcdef";
  unsigned char* c_ptr = hex_out->data;
  for (size_t i = 0; i < str_in->len; i++)
  {
    *(c_ptr++) = digits[(str_in->data[i] & 0xf0) >> 4];
    *(c_ptr++) = digits[str_in->data[i] & 0x0f];
  }
  hex_out->len = str_in->len * 2;
  return AWS_SIGV4_OK;
}

int get_hex_sha256(aws_sigv4_str_t* str_in, aws_sigv4_str_t* hex_sha256_out)
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

  aws_sigv4_str_t sha256_str = { .data = sha256_buf, .len = SHA256_DIGEST_LENGTH };
  return get_hexdigest(&sha256_str, hex_sha256_out);
}

int get_hmac_sha256(aws_sigv4_str_t* key, aws_sigv4_str_t* msg, aws_sigv4_str_t* signed_msg)
{
  int rc = AWS_SIGV4_OK;
  if (key == NULL || empty_str(key)
      || msg == NULL || empty_str(msg)
      || signed_msg == NULL || signed_msg->data == NULL)
  {
    rc = AWS_SIGV4_INVALID_INPUT_ERROR;
    goto finished;
  }
  HMAC(EVP_sha256(), key->data, key->len, msg->data, msg->len, signed_msg->data, &signed_msg->len);
finished:
  return rc;
}

int get_signing_key(aws_sigv4_params_t* sigv4_params, aws_sigv4_str_t* signing_key)
{
  int rc = AWS_SIGV4_OK;
  if (signing_key == NULL
      || signing_key->data == NULL
      || sigv4_params == NULL
      || empty_str(&sigv4_params->secret_access_key)
      || empty_str(&sigv4_params->x_amz_date)
      || empty_str(&sigv4_params->region)
      || empty_str(&sigv4_params->service))
  {
    rc = AWS_SIGV4_INVALID_INPUT_ERROR;
    goto finished;
  }
  unsigned char key_buff[AWS_SIGV4_KEY_BUFF_LEN]  = { 0 };
  unsigned char msg_buff[AWS_SIGV4_KEY_BUFF_LEN]  = { 0 };
  aws_sigv4_str_t key = { .data = key_buff, .len = 0 };
  aws_sigv4_str_t msg = { .data = msg_buff, .len = 0 };
  /* kDate = HMAC("AWS4" + kSecret, Date) */
  strncpy(key_buff, "AWS4", 4);
  strncpy(key_buff + 4, sigv4_params->secret_access_key.data, sigv4_params->secret_access_key.len);
  key.len = 4 + sigv4_params->secret_access_key.len;
  /* data in YYYYMMDD format */
  strncpy(msg_buff, sigv4_params->x_amz_date.data, 8);
  msg.len = 8;
  cleanup_str(signing_key);
  rc = get_hmac_sha256(&key, &msg, signing_key);
  if (rc != AWS_SIGV4_OK)
  {
    goto finished;
  }
  /* kRegion = HMAC(kDate, Region) */
  memset(key_buff, 0, AWS_SIGV4_KEY_BUFF_LEN);
  strncpy(key_buff, signing_key->data, signing_key->len);
  key.len = signing_key->len;
  cleanup_str(signing_key);
  memset(msg_buff, 0, AWS_SIGV4_KEY_BUFF_LEN);
  strncpy(msg_buff, sigv4_params->region.data, sigv4_params->region.len);
  msg.len = sigv4_params->region.len;
  rc = get_hmac_sha256(&key, &msg, signing_key);
  if (rc != AWS_SIGV4_OK)
  {
    goto finished;
  }
  /* kService = HMAC(kRegion, Service) */
  memset(key_buff, 0, AWS_SIGV4_KEY_BUFF_LEN);
  strncpy(key_buff, signing_key->data, signing_key->len);
  key.len = signing_key->len;
  cleanup_str(signing_key);
  memset(msg_buff, 0, AWS_SIGV4_KEY_BUFF_LEN);
  strncpy(msg_buff, sigv4_params->service.data, sigv4_params->service.len);
  msg.len = sigv4_params->service.len;
  rc = get_hmac_sha256(&key, &msg, signing_key);
  if (rc != AWS_SIGV4_OK)
  {
    goto finished;
  }
  /* kSigning = HMAC(kService, "aws4_request") */
  memset(key_buff, 0, AWS_SIGV4_KEY_BUFF_LEN);
  strncpy(key_buff, signing_key->data, signing_key->len);
  key.len = signing_key->len;
  cleanup_str(signing_key);
  memset(msg_buff, 0, AWS_SIGV4_KEY_BUFF_LEN);
  strncpy(msg_buff, "aws4_request", 12);
  msg.len = 12;
  rc = get_hmac_sha256(&key, &msg, signing_key);
finished:
  return rc;
}

int get_credential_scope(aws_sigv4_params_t* sigv4_params, aws_sigv4_str_t* credential_scope)
{
  int rc = AWS_SIGV4_OK;
  if (credential_scope == NULL
      || credential_scope->data == NULL
      || sigv4_params == NULL
      || empty_str(&sigv4_params->x_amz_date)
      || empty_str(&sigv4_params->region)
      || empty_str(&sigv4_params->service))
  {
    rc = AWS_SIGV4_INVALID_INPUT_ERROR;
    goto finished;
  }
  unsigned char* str = credential_scope->data;
  /* get date in yyyymmdd format */
  strncpy(str, sigv4_params->x_amz_date.data, 8);
  str += 8;
  *(str++) = '/';

  strncpy(str, sigv4_params->region.data, sigv4_params->region.len);
  str += sigv4_params->region.len;
  *(str++) = '/';

  strncpy(str, sigv4_params->service.data, sigv4_params->service.len);
  str += sigv4_params->service.len;
  *(str++) = '/';

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
      || empty_str(&sigv4_params->host)
      || empty_str(&sigv4_params->x_amz_date))
  {
    rc = AWS_SIGV4_INVALID_INPUT_ERROR;
    goto finished;
  }
  /* TODO: Need to support additional headers and header sorting */
  const unsigned char* str = "host;x-amz-date";
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
      || empty_str(&sigv4_params->host)
      || empty_str(&sigv4_params->x_amz_date))
  {
    rc = AWS_SIGV4_INVALID_INPUT_ERROR;
    goto finished;
  }
  unsigned char* str = canonical_headers->data;
  strncpy(str, "host:", 5);
  str += 5;
  /* TODO: Add logic to remove leading and trailing spaces for header values */
  strncpy(str, sigv4_params->host.data, sigv4_params->host.len);
  str += sigv4_params->host.len;
  *(str++) = '\n';

  strncpy(str, "x-amz-date:", 11);
  str += 11;
  strncpy(str, sigv4_params->x_amz_date.data, sigv4_params->x_amz_date.len);
  str += sigv4_params->x_amz_date.len;
  *(str++) = '\n';

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
      || empty_str(&sigv4_params->method)
      || empty_str(&sigv4_params->uri)
      || empty_str(&sigv4_params->query_str))
  {
    rc = AWS_SIGV4_INVALID_INPUT_ERROR;
    goto finished;
  }
  unsigned char* str = canonical_request->data;
  strncpy(str, sigv4_params->method.data, sigv4_params->method.len);
  str += sigv4_params->method.len;
  *(str++) = '\n';

  /* TODO: Here we assume the URI has already been encoded. Add encoding logic in future. */
  strncpy(str, sigv4_params->uri.data, sigv4_params->uri.len);
  str += sigv4_params->uri.len;
  *(str++) = '\n';

  /* TODO: Here we assume the query string has already been encoded. Add encoding logic in future. */
  /* TODO: Need to support sorting on params */
  strncpy(str, sigv4_params->query_str.data, sigv4_params->query_str.len);
  str += sigv4_params->query_str.len;
  *(str++) = '\n';

  aws_sigv4_str_t canonical_headers = { .data = str, .len = 0 };
  rc = get_canonical_headers(sigv4_params, &canonical_headers);
  if (rc != AWS_SIGV4_OK)
  {
    goto finished;
  }
  str += canonical_headers.len;
  *(str++) = '\n';

  aws_sigv4_str_t signed_headers = { .data = str, .len = 0 };
  rc = get_signed_headers(sigv4_params, &signed_headers);
  if (rc != AWS_SIGV4_OK)
  {
    goto finished;
  }
  str += signed_headers.len;
  *(str++) = '\n';

  aws_sigv4_str_t hex_sha256 = { .data = str, .len = 0 };
  rc = get_hex_sha256(&sigv4_params->payload, &hex_sha256);
  if (rc != AWS_SIGV4_OK)
  {
    goto finished;
  }
  str += hex_sha256.len;

  canonical_request->len = str - canonical_request->data;
finished:
  return rc;
}

int get_string_to_sign(aws_sigv4_str_t* request_date, aws_sigv4_str_t* credential_scope,
                       aws_sigv4_str_t* canonical_request, aws_sigv4_str_t* string_to_sign)
{
  int rc = AWS_SIGV4_OK;
  if (string_to_sign == NULL || string_to_sign->data == NULL
      || request_date == NULL || empty_str(request_date)
      || credential_scope == NULL || empty_str(credential_scope)
      || canonical_request == NULL || empty_str(canonical_request))
  {
    rc = AWS_SIGV4_INVALID_INPUT_ERROR;
    goto finished;
  }

  unsigned char* str = string_to_sign->data;
  size_t algo_str_len = strlen(AWS_SIGV4_SIGNING_ALGORITHM);
  strncpy(str, AWS_SIGV4_SIGNING_ALGORITHM, algo_str_len);
  str += algo_str_len;
  *(str++) = '\n';

  strncpy(str, request_date->data, request_date->len);
  str += request_date->len;
  *(str++) = '\n';

  strncpy(str, credential_scope->data, credential_scope->len);
  str += credential_scope->len;
  *(str++) = '\n';

  aws_sigv4_str_t hex_sha256 = { .data = str, .len = 0 };
  rc = get_hex_sha256(canonical_request, &hex_sha256);
  if (rc != AWS_SIGV4_OK)
  {
    goto finished;
  }
  str += hex_sha256.len;

  string_to_sign->len = str - string_to_sign->data;
finished:
  return rc;
}

int aws_sigv4_sign(aws_sigv4_params_t* sigv4_params, aws_sigv4_str_t* auth_header)
{
  int rc = AWS_SIGV4_OK;
  if (sigv4_params == NULL
      || auth_header == NULL)
  {
    rc = AWS_SIGV4_INVALID_INPUT_ERROR;
    goto err;
  }

  /* TODO: Support custom memory allocator */
  auth_header->data = malloc(AWS_SIGV4_AUTH_HEADER_MAX_LEN);
  if (auth_header->data == NULL)
  {
    rc = AWS_SIGV4_MEMORY_ALLOCATION_ERROR;
    goto err;
  }
  memset(auth_header->data, 0, AWS_SIGV4_AUTH_HEADER_MAX_LEN);

  unsigned char* str = auth_header->data;
  /* AWS4-HMAC-SHA256 */
  strncpy(str, AWS_SIGV4_SIGNING_ALGORITHM, 16);
  str += 16;
  *(str++) = ' ';

  /* Credential=AKIDEXAMPLE/<credential_scope> */
  if (empty_str(&sigv4_params->access_key_id))
  {
    rc = AWS_SIGV4_INVALID_INPUT_ERROR;
    goto err;
  }
  strncpy(str, "Credential=", 11);
  str += 11;
  strncpy(str, sigv4_params->access_key_id.data, sigv4_params->access_key_id.len);
  str += sigv4_params->access_key_id.len;
  *(str++) = '/';
  aws_sigv4_str_t credential_scope = { .data = str, .len = 0 };
  rc = get_credential_scope(sigv4_params, &credential_scope);
  if (rc != AWS_SIGV4_OK)
  {
    goto err;
  }
  str += credential_scope.len;
  *(str++) = ',';
  *(str++) = ' ';

  /* SignedHeaders=<signed_headers> */
  strncpy(str, "SignedHeaders=", 14);
  str += 14;
  aws_sigv4_str_t signed_headers = { .data = str, .len = 0 };
  rc = get_signed_headers(sigv4_params, &signed_headers);
  if (rc != AWS_SIGV4_OK)
  {
    goto err;
  }
  str += signed_headers.len;
  *(str++) = ',';
  *(str++) = ' ';

  /* Signature=<signature> */
  strncpy(str, "Signature=", 10);
  str += 10;
  /* Task 1: Create a canonical request */
  unsigned char canonical_request_buff[AWS_SIGV4_CANONICAL_REQUEST_BUFF_LEN] = { 0 };
  aws_sigv4_str_t canonical_request = { .data = canonical_request_buff, .len = 0 };
  rc = get_canonical_request(sigv4_params, &canonical_request);
  if (rc != AWS_SIGV4_OK)
  {
    goto err;
  }
  /* Task 2: Create a string to sign */
  unsigned char string_to_sign_buff[AWS_SIGV4_STRING_TO_SIGN_BUFF_LEN] = { 0 };
  aws_sigv4_str_t string_to_sign = { .data = string_to_sign_buff, .len = 0 };
  rc = get_string_to_sign(&sigv4_params->x_amz_date, &credential_scope, &canonical_request, &string_to_sign);
  if (rc != AWS_SIGV4_OK)
  {
    goto err;
  }
  /* Task 3: Calculate the signature */
  /* 3.1: Derive signing key */
  unsigned char signing_key_buff[AWS_SIGV4_KEY_BUFF_LEN] = { 0 };
  aws_sigv4_str_t signing_key = { .data = signing_key_buff, .len = 0 };
  rc = get_signing_key(sigv4_params, &signing_key);
  if (rc != AWS_SIGV4_OK)
  {
    goto err;
  }
  /* 3.2: Calculate signature on the string to sign */
  unsigned char signed_msg_buff[HMAC_MAX_MD_CBLOCK] = { 0 };
  aws_sigv4_str_t signed_msg = { .data = signed_msg_buff, .len = 0 };
  rc = get_hmac_sha256(&signing_key, &string_to_sign, &signed_msg);
  if (rc != AWS_SIGV4_OK)
  {
    goto err;
  }
  aws_sigv4_str_t signature = { .data = str, .len = 0 };
  rc = get_hexdigest(&signed_msg, &signature);
  if (rc != AWS_SIGV4_OK)
  {
    goto err;
  }
  str += signature.len;
  auth_header->len = str - auth_header->data;
  return rc;
err:
  /* deallocate memory in case of failure */
  if (auth_header && auth_header->data)
  {
    free(auth_header->data);
    auth_header->data = NULL;
  }
  return rc;
}
