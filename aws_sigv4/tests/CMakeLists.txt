cmake_minimum_required (VERSION 3.0)
project (aws_sigv4_tests)

add_executable(dummy_test dummy_test.c)

find_library(LIBCHECK check)
target_link_libraries(dummy_test
    aws_sigv4
    "${LIBCHECK}"
)

add_test(DummyTest dummy_test)
