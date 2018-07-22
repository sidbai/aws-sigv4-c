#include <stdio.h>
#include <stdlib.h>
#include <check.h>
#include "aws_sigv4.h"

static inline aws_sigv4_str_t construct_str(const char* cstr)
{
  aws_sigv4_str_t ret = { .data = NULL, .len = 0 };
  if (cstr)
  {
    ret.data = (char*) cstr;
    ret.len  = strlen(cstr);
  }
  return ret;
}

static inline aws_sigv4_ustr_t construct_ustr(const unsigned char* cstr)
{
  aws_sigv4_ustr_t ret = { .data = NULL, .len = 0 };
  if (cstr)
  {
    ret.data = (unsigned char*) cstr;
    ret.len  = strlen(cstr);
  }
  return ret;
}

START_TEST (AwsSigv4Test_Dummy)
{
  ck_assert_int_eq(0, 0);
}
END_TEST

START_TEST (AwsSigv4Test_HEX)
{
  /*
   * test data is from https://tools.ietf.org/html/rfc4231
   */
  const char* expected_output_str1  = "4a656665";
  const char* expected_output_str2  = "7768617420646f2079612077616e7420666f72206e6f7468696e673f";
  char hex_buff[AWS_SIGV4_HEX_SHA256_LENGTH + 1] = { 0 };

  aws_sigv4_ustr_t str_in_str1  = construct_ustr("Jefe");
  int rc = get_hexdigest(&str_in_str1, hex_buff);
  ck_assert_int_eq(rc, AWS_SIGV4_OK);
  ck_assert_pstr_eq(hex_buff, expected_output_str1);

  memset(hex_buff, 0, AWS_SIGV4_HEX_SHA256_LENGTH + 1);
  aws_sigv4_ustr_t str_in_str2  = construct_ustr("what do ya want for nothing?");
  rc = get_hexdigest(&str_in_str2, hex_buff);
  ck_assert_int_eq(rc, AWS_SIGV4_OK);
  ck_assert_pstr_eq(hex_buff, expected_output_str2);
}
END_TEST

START_TEST (AwsSigv4Test_HexSHA256)
{
  /*
   * test data is from https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
   */
  const char* empty_str_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  char hex_sha256[AWS_SIGV4_HEX_SHA256_LENGTH];
  aws_sigv4_str_t str_in = construct_str(NULL);
  int rc = get_hex_sha256(&str_in, hex_sha256);
  ck_assert_int_eq(rc, AWS_SIGV4_OK);
  ck_assert_mem_eq(hex_sha256, empty_str_sha256, AWS_SIGV4_HEX_SHA256_LENGTH);
}
END_TEST

START_TEST (AwsSigv4Test_SigningKey)
{
  /*
   * test data is from https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
   */
  aws_sigv4_params_t sigv4_params = { .secret_access_key  = construct_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
                                      .x_amz_date = construct_str("20150830T050102Z"),
                                      .region     = construct_str("us-east-1"),
                                      .service    = construct_str("iam") };
  char key_buff[1024] = { 0 };
  char msg_buff[1024] = { 0 };
  unsigned char signing_key_buff[AWS_SIGV4_KEY_BUFF_LEN]  = { 0 };
  char signing_key_hash[AWS_SIGV4_HEX_SHA256_LENGTH + 1]  = { 0 };

  aws_sigv4_ustr_t signing_key = { .data = signing_key_buff, .len = 0 };
  int rc = get_signing_key(&sigv4_params, &signing_key);
  ck_assert_int_eq(rc, AWS_SIGV4_OK);
  rc = get_hexdigest(&signing_key, signing_key_hash);
  ck_assert_int_eq(rc, AWS_SIGV4_OK);
  const char* expected_signing_key_hash = "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9";
  ck_assert_pstr_eq(signing_key_hash, expected_signing_key_hash);
  ck_assert_mem_eq(signing_key_hash, expected_signing_key_hash, AWS_SIGV4_HEX_SHA256_LENGTH);
}
END_TEST

START_TEST (AwsSigv4Test_CredentialScope)
{
  char credential_scope_data[1024] = { 0 };
  aws_sigv4_str_t credential_scope    = { .data = credential_scope_data, .len = 0 };
  aws_sigv4_params_t sigv4_params     = { .x_amz_date = construct_str(NULL),
                                          .region     = construct_str(NULL),
                                          .service    = construct_str(NULL) };
  /* invalid input */
  int rc = get_credential_scope(NULL, &credential_scope);
  ck_assert_int_eq(rc, AWS_SIGV4_INVALID_INPUT_ERROR);

  rc = get_credential_scope(&sigv4_params, &credential_scope);
  ck_assert_int_eq(rc, AWS_SIGV4_INVALID_INPUT_ERROR);

  const char* test_iso8601_date = "20180717T074800Z";
  sigv4_params.x_amz_date = construct_str(test_iso8601_date);
  rc = get_credential_scope(&sigv4_params, &credential_scope);
  ck_assert_int_eq(rc, AWS_SIGV4_INVALID_INPUT_ERROR);

  const char* test_region = "us-east-1";
  sigv4_params.region = construct_str(test_region);
  rc = get_credential_scope(&sigv4_params, &credential_scope);
  ck_assert_int_eq(rc, AWS_SIGV4_INVALID_INPUT_ERROR);

  const char* test_service = "s3";
  sigv4_params.service = construct_str(test_service);
  rc = get_credential_scope(&sigv4_params, NULL);
  ck_assert_int_eq(rc, AWS_SIGV4_INVALID_INPUT_ERROR);

  /* happy case */
  rc = get_credential_scope(&sigv4_params, &credential_scope);
  const char* expected_credential_scope = "20180717/us-east-1/s3/aws4_request";
  int expected_len = strlen(expected_credential_scope);
  ck_assert_int_eq(rc, AWS_SIGV4_OK);
  ck_assert_mem_eq(credential_scope.data, expected_credential_scope, expected_len);
  ck_assert_int_eq(credential_scope.len, expected_len);
}
END_TEST

START_TEST (AwsSigv4Test_SignedHeaders)
{
  char signed_headers_data[128];
  aws_sigv4_str_t signed_headers  = { .data = signed_headers_data, .len = 0 };
  aws_sigv4_params_t sigv4_params = { .host       = construct_str(NULL),
                                      .x_amz_date = construct_str(NULL) };

  /* invalid input */
  int rc = get_signed_headers(NULL, &signed_headers);
  ck_assert_int_eq(rc, AWS_SIGV4_INVALID_INPUT_ERROR);

  rc = get_signed_headers(&sigv4_params, &signed_headers);
  ck_assert_int_eq(rc, AWS_SIGV4_INVALID_INPUT_ERROR);

  sigv4_params.host = construct_str("abc.com");
  rc = get_signed_headers(&sigv4_params, &signed_headers);
  ck_assert_int_eq(rc, AWS_SIGV4_INVALID_INPUT_ERROR);

  sigv4_params.x_amz_date = construct_str("20180717T074800Z");
  rc = get_signed_headers(&sigv4_params, NULL);
  ck_assert_int_eq(rc, AWS_SIGV4_INVALID_INPUT_ERROR);

  /* happy case */
  rc = get_signed_headers(&sigv4_params, &signed_headers);
  const char* expected_signed_headers = "host;x-amz-date";
  int expected_len = strlen(expected_signed_headers);
  ck_assert_int_eq(rc, AWS_SIGV4_OK);
  ck_assert_mem_eq(signed_headers.data, expected_signed_headers, expected_len);
  ck_assert_int_eq(signed_headers.len, expected_len);
}
END_TEST

START_TEST (AwsSigv4Test_CanonicalHeaders)
{
  char canonical_headers_data[256];
  aws_sigv4_str_t canonical_headers   = { .data = canonical_headers_data, .len = 0 };
  aws_sigv4_params_t sigv4_params     = { .host       = construct_str(NULL),
                                          .x_amz_date = construct_str(NULL) };

  /* invalid input */
  int rc = get_canonical_headers(NULL, &canonical_headers);
  ck_assert_int_eq(rc, AWS_SIGV4_INVALID_INPUT_ERROR);

  rc = get_canonical_headers(&sigv4_params, &canonical_headers);
  ck_assert_int_eq(rc, AWS_SIGV4_INVALID_INPUT_ERROR);

  sigv4_params.host = construct_str("abc.com");
  rc = get_canonical_headers(&sigv4_params, &canonical_headers);
  ck_assert_int_eq(rc, AWS_SIGV4_INVALID_INPUT_ERROR);

  sigv4_params.x_amz_date = construct_str("20180717T074800Z");
  rc = get_canonical_headers(&sigv4_params, NULL);
  ck_assert_int_eq(rc, AWS_SIGV4_INVALID_INPUT_ERROR);

  /* happy case */
  rc = get_canonical_headers(&sigv4_params, &canonical_headers);
  const char* expected_canonical_headers = "host:abc.com\nx-amz-date:20180717T074800Z\n";
  int expected_len = strlen(expected_canonical_headers);
  ck_assert_int_eq(rc, AWS_SIGV4_OK);
  ck_assert_mem_eq(canonical_headers.data, expected_canonical_headers, expected_len);
  ck_assert_int_eq(canonical_headers.len, expected_len);
}
END_TEST

START_TEST (AwsSigv4Test_CanonicalRequest)
{
  char canonical_request_data[1024] = { 0 };
  aws_sigv4_str_t canonical_request = { .data = canonical_request_data, .len = 0 };
  aws_sigv4_params_t sigv4_params   = { .method     = construct_str(NULL),
                                        .host       = construct_str("abc.com"),
                                        .x_amz_date = construct_str("20180717T074800Z"),
                                        .uri        = construct_str(NULL),
                                        .query_str  = construct_str(NULL),
                                        .payload    = construct_str(NULL) };

  /* invalid input */
  int rc = get_canonical_request(NULL, &canonical_request);
  ck_assert_int_eq(rc, AWS_SIGV4_INVALID_INPUT_ERROR);

  rc = get_canonical_request(&sigv4_params, &canonical_request);
  ck_assert_int_eq(rc, AWS_SIGV4_INVALID_INPUT_ERROR);

  sigv4_params.method = construct_str("GET");
  rc = get_canonical_request(&sigv4_params, &canonical_request);
  ck_assert_int_eq(rc, AWS_SIGV4_INVALID_INPUT_ERROR);

  sigv4_params.uri = construct_str("/test_uri");
  rc = get_canonical_request(&sigv4_params, NULL);
  ck_assert_int_eq(rc, AWS_SIGV4_INVALID_INPUT_ERROR);

  sigv4_params.query_str = construct_str("action=test");
  rc = get_canonical_request(&sigv4_params, NULL);
  ck_assert_int_eq(rc, AWS_SIGV4_INVALID_INPUT_ERROR);

  /* happy case */
  rc = get_canonical_request(&sigv4_params, &canonical_request);
  const char* expected_canonical_request = \
"GET\n\
/test_uri\n\
action=test\n\
host:abc.com\n\
x-amz-date:20180717T074800Z\n\
\n\
host;x-amz-date\n\
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  int expected_len = strlen(expected_canonical_request);
  ck_assert_int_eq(rc, AWS_SIGV4_OK);
  ck_assert_int_eq(canonical_request.len, expected_len);
  ck_assert_pstr_eq(canonical_request.data, expected_canonical_request);
  ck_assert_mem_eq(canonical_request.data, expected_canonical_request, expected_len);
}
END_TEST

START_TEST (AwsSigv4Test_StringToSign)
{
  /*
   * happy case
   * test data is from https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
   */
  char string_to_sign_data[1024] = { 0 };
  const char* request_date_data       = "20150830T123600Z";
  const char* credential_scope_data   = "20150830/us-east-1/iam/aws4_request";
  const char* canonical_request_data  = \
"GET\n\
/\n\
Action=ListUsers&Version=2010-05-08\n\
content-type:application/x-www-form-urlencoded; charset=utf-8\n\
host:iam.amazonaws.com\n\
x-amz-date:20150830T123600Z\n\
\n\
content-type;host;x-amz-date\n\
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  aws_sigv4_str_t request_date        = construct_str(request_date_data);
  aws_sigv4_str_t credential_scope    = construct_str(credential_scope_data);
  aws_sigv4_str_t canonical_request   = construct_str(canonical_request_data);
  aws_sigv4_str_t string_to_sign      = { .data = string_to_sign_data, .len = 0 };
  int rc = get_string_to_sign(&request_date, &credential_scope, &canonical_request, &string_to_sign);
  const char* expected_string_to_sign = \
"AWS4-HMAC-SHA256\n\
20150830T123600Z\n\
20150830/us-east-1/iam/aws4_request\n\
f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59";
  int expected_len = strlen(expected_string_to_sign);
  ck_assert_int_eq(rc, AWS_SIGV4_OK);
  ck_assert_int_eq(string_to_sign.len, expected_len);
  ck_assert_pstr_eq(string_to_sign.data, expected_string_to_sign);
  ck_assert_mem_eq(string_to_sign.data, expected_string_to_sign, expected_len);
}
END_TEST

Suite * aws_sigv4_test_suite(void)
{
  Suite *s;
  s = suite_create("AwsSigv4Test");

  TCase *tc_dummy             = tcase_create("AwsSigv4Test_Dummy");
  TCase *tc_hex               = tcase_create("AwsSigv4Test_HEX");
  TCase *tc_hex_sha256        = tcase_create("AwsSigv4Test_HexSHA256");
  TCase *tc_credential_scope  = tcase_create("AwsSigv4Test_CredentialScope");
  TCase *tc_signed_headers    = tcase_create("AwsSigv4Test_SignedHeaders");
  TCase *tc_canonical_headers = tcase_create("AwsSigv4Test_CanonicalHeaders");
  TCase *tc_canonical_request = tcase_create("AwsSigv4Test_CanonicalRequest");
  TCase *tc_string_to_sign    = tcase_create("AwsSigv4Test_StringToSign");
  TCase *tc_signing_key       = tcase_create("AwsSigv4Test_SigningKey");
  tcase_add_test(tc_dummy, AwsSigv4Test_Dummy);
  tcase_add_test(tc_hex_sha256, AwsSigv4Test_HexSHA256);
  tcase_add_test(tc_hex, AwsSigv4Test_HEX);
  tcase_add_test(tc_credential_scope, AwsSigv4Test_CredentialScope);
  tcase_add_test(tc_signed_headers, AwsSigv4Test_SignedHeaders);
  tcase_add_test(tc_canonical_headers, AwsSigv4Test_CanonicalHeaders);
  tcase_add_test(tc_canonical_request, AwsSigv4Test_CanonicalRequest);
  tcase_add_test(tc_string_to_sign, AwsSigv4Test_StringToSign);
  tcase_add_test(tc_signing_key, AwsSigv4Test_SigningKey);
  suite_add_tcase(s, tc_dummy);
  suite_add_tcase(s, tc_hex);
  suite_add_tcase(s, tc_hex_sha256);
  suite_add_tcase(s, tc_credential_scope);
  suite_add_tcase(s, tc_signed_headers);
  suite_add_tcase(s, tc_canonical_headers);
  suite_add_tcase(s, tc_canonical_request);
  suite_add_tcase(s, tc_string_to_sign);
  suite_add_tcase(s, tc_signing_key);
  return s;
}

int main(int argc, char **argv) {
  int number_failed;
  SRunner *sr;

  sr = srunner_create(aws_sigv4_test_suite());

  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);

  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
