#include <stdio.h>
#include <stdlib.h>
#include <check.h>

START_TEST (DummyTest_Dummy)
{
    ck_assert_int_eq(0, 0);
}
END_TEST

Suite * dummy_test_suite(void)
{
    Suite *s;
    s = suite_create("DummyTest");

    TCase *tc_dummy;
    tc_dummy = tcase_create("DummyTest_Dummy");
    tcase_add_test(tc_dummy, DummyTest_Dummy);
    suite_add_tcase(s, tc_dummy);
    return s;
}

int main(int argc, char **argv) {
    int number_failed;
    SRunner *sr;

    sr = srunner_create(dummy_test_suite());

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
