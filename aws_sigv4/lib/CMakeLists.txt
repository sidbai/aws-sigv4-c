cmake_minimum_required (VERSION 3.0)

# Set project name
project (aws_sigv4_lib)

add_library(aws_sigv4 STATIC
    aws_sigv4.c
)
