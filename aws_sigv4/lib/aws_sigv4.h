#ifndef AWS_SIGV4_H
#define AWS_SIGV4_H

typedef struct aws_sigv4_params_s {
    /* AWS credential parameters */
    char* secret_access_key;
    char* access_key_id;
    /* HTTP request parameters */
    char* method;
    char* uri;
    char* query_str;
    char* host;
    char* payload;
    /* AWS service parameters */
    char* service;
    char* region;
} aws_sigv4_params_t;

int aws_sigv4_sign(aws_sigv4_params_t* sigv4_params, char** auth_header);

#endif // AWS_SIGV4_H
