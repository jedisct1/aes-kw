#ifndef aes_kw_H
#define aes_kw_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

#ifndef aes_kw_KEYBYTES
#define aes_kw_KEYBYTES 32
#endif

#define aes_kw_MACBYTES 8

int aes_kw_wrap(unsigned char *padded_out, size_t padded_out_len, const unsigned char *in,
                size_t in_len, const unsigned char key[aes_kw_KEYBYTES]);

int aes_kw_unwrap(unsigned char *out, size_t out_len, size_t padded_out_len,
                  const unsigned char *padded_in, size_t padded_in_len,
                  const unsigned char key[aes_kw_KEYBYTES]);

#ifdef __cplusplus
}
#endif

#endif
