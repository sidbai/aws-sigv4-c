#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "aws_sigv4.h"

#define AWS_SIGV4_AUTH_HEADER_NAME    "Authorization"
#define AWS_SIGV4_SIGNING_ALGORITHM   "AWS4-HMAC-SHA256"
#define AWS_SIGV4_HEX_SHA256_LENGTH SHA256_DIGEST_LENGTH * 2
#define AWS_SIGV4_AUTH_HEADER_MAX_LEN         1024
#define AWS_SIGV4_CANONICAL_REQUEST_BUF_LEN   4096
#define AWS_SIGV4_STRING_TO_SIGN_BUF_LEN      4096
#define AWS_SIGV4_KEY_BUF_LEN                 256

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
  if (key == NULL || aws_sigv4_empty_str(key)
      || msg == NULL || aws_sigv4_empty_str(msg)
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
      || aws_sigv4_empty_str(&sigv4_params->secret_access_key)
      || aws_sigv4_empty_str(&sigv4_params->x_amz_date)
      || aws_sigv4_empty_str(&sigv4_params->region)
      || aws_sigv4_empty_str(&sigv4_params->service))
  {
    rc = AWS_SIGV4_INVALID_INPUT_ERROR;
    goto finished;
  }
  unsigned char key_buf[AWS_SIGV4_KEY_BUF_LEN]  = { 0 };
  unsigned char msg_buf[AWS_SIGV4_KEY_BUF_LEN]  = { 0 };
  aws_sigv4_str_t key = { .data = key_buf, .len = 0 };
  aws_sigv4_str_t msg = { .data = msg_buf, .len = 0 };
  /* kDate = HMAC("AWS4" + kSecret, Date) */
  key.len = aws_sigv4_sprintf(key_buf, "AWS4%V", &sigv4_params->secret_access_key);
  /* data in YYYYMMDD format */
  msg.len = aws_sigv4_snprintf(msg_buf, 8, "%V", &sigv4_params->x_amz_date);
  rc = get_hmac_sha256(&key, &msg, signing_key);
  if (rc != AWS_SIGV4_OK)
  {
    goto finished;
  }
  /* kRegion = HMAC(kDate, Region) */
  key.len = aws_sigv4_sprintf(key_buf, "%V", signing_key);
  msg.len = aws_sigv4_sprintf(msg_buf, "%V", &sigv4_params->region);
  rc = get_hmac_sha256(&key, &msg, signing_key);
  if (rc != AWS_SIGV4_OK)
  {
    goto finished;
  }
  /* kService = HMAC(kRegion, Service) */
  key.len = aws_sigv4_sprintf(key_buf, "%V", signing_key);
  msg.len = aws_sigv4_sprintf(msg_buf, "%V", &sigv4_params->service);
  rc = get_hmac_sha256(&key, &msg, signing_key);
  if (rc != AWS_SIGV4_OK)
  {
    goto finished;
  }
  /* kSigning = HMAC(kService, "aws4_request") */
  key.len = aws_sigv4_sprintf(key_buf, "%V", signing_key);
  msg.len = aws_sigv4_sprintf(msg_buf, "aws4_request");
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
      || aws_sigv4_empty_str(&sigv4_params->x_amz_date)
      || aws_sigv4_empty_str(&sigv4_params->region)
      || aws_sigv4_empty_str(&sigv4_params->service))
  {
    rc = AWS_SIGV4_INVALID_INPUT_ERROR;
    goto finished;
  }
  unsigned char* str = credential_scope->data;
  /* get date in yyyymmdd format */
  str += aws_sigv4_snprintf(str, 8, "%V", &sigv4_params->x_amz_date);
  str += aws_sigv4_sprintf(str, "/%V/%V/aws4_request",&sigv4_params->region, &sigv4_params->service);
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
      || aws_sigv4_empty_str(&sigv4_params->host)
      || aws_sigv4_empty_str(&sigv4_params->x_amz_date))
  {
    rc = AWS_SIGV4_INVALID_INPUT_ERROR;
    goto finished;
  }
  /* TODO: Need to support additional headers and header sorting */
  signed_headers->len = aws_sigv4_sprintf(signed_headers->data, "host;x-amz-date");
finished:
  return rc;
}

int get_canonical_headers(aws_sigv4_params_t* sigv4_params, aws_sigv4_str_t* canonical_headers)
{
  int rc = AWS_SIGV4_OK;
  if (canonical_headers == NULL
      || canonical_headers->data == NULL
      || sigv4_params == NULL
      || aws_sigv4_empty_str(&sigv4_params->host)
      || aws_sigv4_empty_str(&sigv4_params->x_amz_date))
  {
    rc = AWS_SIGV4_INVALID_INPUT_ERROR;
    goto finished;
  }
  /* TODO: Add logic to remove leading and trailing spaces for header values */
  canonical_headers->len  = aws_sigv4_sprintf(canonical_headers->data, "host:%V\nx-amz-date:%V\n",
                                              &sigv4_params->host, &sigv4_params->x_amz_date);
finished:
  return rc;
}

int get_canonical_request(aws_sigv4_params_t* sigv4_params, aws_sigv4_str_t* canonical_request)
{
  int rc = AWS_SIGV4_OK;
  if (canonical_request == NULL
      || canonical_request->data == NULL
      || sigv4_params == NULL
      || aws_sigv4_empty_str(&sigv4_params->method)
      || aws_sigv4_empty_str(&sigv4_params->uri)
      || aws_sigv4_empty_str(&sigv4_params->query_str))
  {
    rc = AWS_SIGV4_INVALID_INPUT_ERROR;
    goto finished;
  }
  unsigned char* str = canonical_request->data;
  /* TODO: Here we assume the URI and query string have already been encoded. Add encoding logic in future. */
  /* TODO: Need to support sorting on params */
  str += aws_sigv4_sprintf(str, "%V\n%V\n%V\n", &sigv4_params->method, &sigv4_params->uri, &sigv4_params->query_str);

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
      || request_date == NULL || aws_sigv4_empty_str(request_date)
      || credential_scope == NULL || aws_sigv4_empty_str(credential_scope)
      || canonical_request == NULL || aws_sigv4_empty_str(canonical_request))
  {
    rc = AWS_SIGV4_INVALID_INPUT_ERROR;
    goto finished;
  }

  unsigned char* str = string_to_sign->data;
  str += aws_sigv4_sprintf(str, "AWS4-HMAC-SHA256\n%V\n%V\n", request_date, credential_scope);

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

int aws_sigv4_sign(aws_sigv4_params_t* sigv4_params, aws_sigv4_header_t* auth_header)
{
  int rc = AWS_SIGV4_OK;
  if (sigv4_params == NULL
      || auth_header == NULL)
  {
    rc = AWS_SIGV4_INVALID_INPUT_ERROR;
    goto err;
  }

  /* TODO: Support custom memory allocator */
  auth_header->value.data = calloc(AWS_SIGV4_AUTH_HEADER_MAX_LEN, sizeof(unsigned char));
  if (auth_header->value.data == NULL)
  {
    rc = AWS_SIGV4_MEMORY_ALLOCATION_ERROR;
    goto err;
  }

  auth_header->name.data  = AWS_SIGV4_AUTH_HEADER_NAME;
  auth_header->name.len   = strlen(AWS_SIGV4_AUTH_HEADER_NAME);

  /* AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/<credential_scope> */
  unsigned char* str = auth_header->value.data;
  if (aws_sigv4_empty_str(&sigv4_params->access_key_id))
  {
    rc = AWS_SIGV4_INVALID_INPUT_ERROR;
    goto err;
  }
  str += aws_sigv4_sprintf(str, "AWS4-HMAC-SHA256 Credential=%V/", &sigv4_params->access_key_id);

  aws_sigv4_str_t credential_scope = { .data = str, .len = 0 };
  rc = get_credential_scope(sigv4_params, &credential_scope);
  if (rc != AWS_SIGV4_OK)
  {
    goto err;
  }
  str += credential_scope.len;

  /* SignedHeaders=<signed_headers> */
  str += aws_sigv4_sprintf(str, ", SignedHeaders=", &sigv4_params->access_key_id);
  aws_sigv4_str_t signed_headers = { .data = str, .len = 0 };
  rc = get_signed_headers(sigv4_params, &signed_headers);
  if (rc != AWS_SIGV4_OK)
  {
    goto err;
  }
  str += signed_headers.len;

  /* Signature=<signature> */
  str += aws_sigv4_sprintf(str, ", Signature=", &sigv4_params->access_key_id);
  /* Task 1: Create a canonical request */
  unsigned char canonical_request_buf[AWS_SIGV4_CANONICAL_REQUEST_BUF_LEN]  = { 0 };
  aws_sigv4_str_t canonical_request = { .data = canonical_request_buf, .len = 0 };
  rc = get_canonical_request(sigv4_params, &canonical_request);
  if (rc != AWS_SIGV4_OK)
  {
    goto err;
  }
  /* Task 2: Create a string to sign */
  unsigned char string_to_sign_buf[AWS_SIGV4_STRING_TO_SIGN_BUF_LEN]  = { 0 };
  aws_sigv4_str_t string_to_sign = { .data = string_to_sign_buf, .len = 0 };
  rc = get_string_to_sign(&sigv4_params->x_amz_date, &credential_scope, &canonical_request, &string_to_sign);
  if (rc != AWS_SIGV4_OK)
  {
    goto err;
  }
  /* Task 3: Calculate the signature */
  /* 3.1: Derive signing key */
  unsigned char signing_key_buf[AWS_SIGV4_KEY_BUF_LEN] = { 0 };
  aws_sigv4_str_t signing_key = { .data = signing_key_buf, .len = 0 };
  rc = get_signing_key(sigv4_params, &signing_key);
  if (rc != AWS_SIGV4_OK)
  {
    goto err;
  }
  /* 3.2: Calculate signature on the string to sign */
  unsigned char signed_msg_buf[HMAC_MAX_MD_CBLOCK] = { 0 };
  aws_sigv4_str_t signed_msg = { .data = signed_msg_buf, .len = 0 };
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
  auth_header->value.len = str - auth_header->value.data;
  return rc;
err:
  /* deallocate memory in case of failure */
  if (auth_header && auth_header->value.data)
  {
    free(auth_header->value.data);
    auth_header->value.data = NULL;
  }
  return rc;
}
