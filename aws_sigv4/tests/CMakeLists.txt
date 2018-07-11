cmake_minimum_required (VERSION 3.0)
project (aws_sigv4_tests)

add_executable(dummy_test dummy_test.c)

find_library(LIBCHECK check)
find_library(LIBCOMPAT compat)
target_link_libraries(dummy_test
    "${LIBCHECK}"
    "${LIBCOMPAT}"
)

add_test(DummyTest dummy_test)
