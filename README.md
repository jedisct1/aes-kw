# A standalone AES-KW (RFC 3394 / RFC 5649) implementation

AES-KW is a construction to encrypt secret keys using a master key.

It is essentially a 5 round Feistel network using AES as the core function. One half of each AES block is used to encrypt the key, and the second half of the last permutation is used to compute a 64-bit MAC.

It doesn't require nonces, but still allows key reuse.

This is a NIST-blessed construction. Other than that, AES-KW is inefficient and is generally not very useful.

## Usage

The code uses AES-NI, so you may have to add `-maes` or `-march=native` to your compilation flags.

### Wrapping:

```c
int aes_kw_wrap(unsigned char *padded_out, size_t padded_out_len, const unsigned char *in,
                size_t in_len, const unsigned char key[aes_kw_KEYBYTES]);
```

Encrypts a key `in` of length `in_len` bytes using the AES key `key` of size `aes_kw_KEYBYTES` bytes (the code uses AES-256 by default, so `aes_kw_KEYBYTES` is 32 bytes).

The encrypted key is put into `padded_out`, whose length is `padded_out_len`.

`padded_out_len` must be `aes_kw_MACBYTES` (8 bytes) larger than the input. Extra space is needed if the wrapped key size is not a multiple of 8 bytes, but this case is virtually nonexistent in the real world.

The function returns `0` on success, `-1` or error.

### Unwrapping:

```c
int aes_kw_unwrap(unsigned char *out, size_t out_len, size_t padded_out_len,
                  const unsigned char *padded_in, size_t padded_in_len,
                  const unsigned char key[aes_kw_KEYBYTES]);
```

Decrypt the wrapped key `padded_in` of length `padded_in_len` using the AES key `key`, and store the decrypted key of length `out_len` bytes into `out` whose size is `padded_out_len`.

Unless you are using key sizes that are not a multiple of 8 bytes, `padded_out_len` and `out_len` can be set to the same value.

The function returns `0` on success, `-1` or error.
