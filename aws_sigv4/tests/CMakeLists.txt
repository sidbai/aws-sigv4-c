cmake_minimum_required (VERSION 3.0)
project (aws_sigv4_tests)

find_library(LIBCHECK check)

add_executable("${PROJECT_NAME}" aws_sigv4_test.c)
target_include_directories("${PROJECT_NAME}"
    PUBLIC
        "${PROJECT_SOURCE_DIR}/../lib"
)

target_link_libraries("${PROJECT_NAME}"
    aws_sigv4
    "${LIBCHECK}"
)

add_test(AwsSigv4Test "${PROJECT_NAME}")
