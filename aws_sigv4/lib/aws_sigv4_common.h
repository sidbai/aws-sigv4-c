#ifndef __AWS_SIGV4_COMMON_H
#define __AWS_SIGV4_COMMON_H

typedef struct aws_sigv4_str_s {
  unsigned char*  data;
  unsigned int    len;
} aws_sigv4_str_t;

int aws_sigv4_empty_str(aws_sigv4_str_t* str);

int aws_sigv4_sprintf(unsigned char* buf, const char* fmt, ...);

int aws_sigv4_snprintf(unsigned char* buf, unsigned int n, const char* fmt, ...);

#endif /* __AWS_SIGV4_COMMON_H */
