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

START_TEST (AwsSigv4Test_Dummy)
{
    ck_assert_int_eq(0, 0);
}
END_TEST

START_TEST (AwsSigv4Test_HexSHA256)
{
    const char* empty_str_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    char hex_sha256[AWS_SIGV4_HEX_SHA256_LENGTH];
    aws_sigv4_str_t str_in = construct_str(NULL);
    int rc = get_hex_sha256(&str_in, hex_sha256);
    ck_assert_int_eq(rc, AWS_SIGV4_OK);
    ck_assert_mem_eq(hex_sha256, empty_str_sha256, AWS_SIGV4_HEX_SHA256_LENGTH);
}
END_TEST

START_TEST (AwsSigv4Test_CredentialScope)
{
    char credential_scope_data[1024] = { 0 };
    aws_sigv4_str_t credential_scope = { .data = credential_scope_data, .len = 0 };
    aws_sigv4_params_t sigv4_params = { .x_amz_date = construct_str(NULL),
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
    aws_sigv4_str_t signed_headers = { .data = signed_headers_data, .len = 0 };
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
    aws_sigv4_str_t canonical_headers = { .data = canonical_headers_data, .len = 0 };
    aws_sigv4_params_t sigv4_params = { .host       = construct_str(NULL),
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
    aws_sigv4_params_t sigv4_params = { .method     = construct_str(NULL),
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
x-amz-date:20180717T074800Z\n\n\
host;x-amz-date\n\
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    int expected_len = strlen(expected_canonical_request);
    ck_assert_int_eq(rc, AWS_SIGV4_OK);
    ck_assert_int_eq(canonical_request.len, expected_len);
    ck_assert_pstr_eq(canonical_request.data, expected_canonical_request);
    ck_assert_mem_eq(canonical_request.data, expected_canonical_request, expected_len);
}
END_TEST

Suite * aws_sigv4_test_suite(void)
{
    Suite *s;
    s = suite_create("AwsSigv4Test");

    TCase *tc_dummy             = tcase_create("AwsSigv4Test_Dummy");
    TCase *tc_hex_sha256        = tcase_create("AwsSigv4Test_HexSHA256");
    TCase *tc_credential_scope  = tcase_create("AwsSigv4Test_CredentialScope");
    TCase *tc_signed_headers    = tcase_create("AwsSigv4Test_SignedHeaders");
    TCase *tc_canonical_headers = tcase_create("AwsSigv4Test_CanonicalHeaders");
    TCase *tc_canonical_request = tcase_create("AwsSigv4Test_CanonicalRequest");
    tcase_add_test(tc_dummy, AwsSigv4Test_Dummy);
    tcase_add_test(tc_hex_sha256, AwsSigv4Test_HexSHA256);
    tcase_add_test(tc_credential_scope, AwsSigv4Test_CredentialScope);
    tcase_add_test(tc_signed_headers, AwsSigv4Test_SignedHeaders);
    tcase_add_test(tc_canonical_headers, AwsSigv4Test_CanonicalHeaders);
    tcase_add_test(tc_canonical_request, AwsSigv4Test_CanonicalRequest);
    suite_add_tcase(s, tc_dummy);
    suite_add_tcase(s, tc_hex_sha256);
    suite_add_tcase(s, tc_credential_scope);
    suite_add_tcase(s, tc_signed_headers);
    suite_add_tcase(s, tc_canonical_headers);
    suite_add_tcase(s, tc_canonical_request);
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
