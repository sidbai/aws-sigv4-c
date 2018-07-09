cmake_minimum_required (VERSION 3.0)
project (aws_sigv4_tests)

# Add extra include directories
include_directories("/usr/local/include")
# Add extra link directories
link_directories("/usr/local/lib")

add_executable(dummy_test dummy_test.c)

target_link_libraries(dummy_test
    libcheck.so
    libcompat.so
)

add_test(DummyTest dummy_test)
