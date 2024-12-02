#ifndef ENCODE_H
#define ENCODE_H


char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length);

void build_decoding_table();

unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length);

void base64_cleanup();


#endif