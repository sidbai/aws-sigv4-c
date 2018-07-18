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

Suite * aws_sigv4_test_suite(void)
{
    Suite *s;
    s = suite_create("AwsSigv4Test");

    TCase *tc_dummy             = tcase_create("AwsSigv4Test_Dummy");
    TCase *tc_credential_scope  = tcase_create("AwsSigv4Test_CredentialScope");
    tcase_add_test(tc_dummy, AwsSigv4Test_CredentialScope);
    tcase_add_test(tc_credential_scope, AwsSigv4Test_CredentialScope);
    suite_add_tcase(s, tc_dummy);
    suite_add_tcase(s, tc_credential_scope);
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
