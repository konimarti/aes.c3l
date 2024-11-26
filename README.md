## AES implementation for C3

This is an implementation of the AES ECB, CTR and CBC encryption algorithms for
C3 based on the [tiny-AES-c](http://github.com/kokke/tiny-AES-c) project.

It supports 128, 192 and 256 bit key sizes.

API overview:
```cpp
import crypto::aes;

// Initialize the context with one of:
AesCtx *ctx = AesCtx{}.init(aes::AES128, key);
AesCtx *ctx = AesCtx{}.init_with_iv(aes::AES128, key, iv);

// Start encrypting and decrypting with either the ECB, CBC or CTR modes.
// Each mode defines a namespace with the following functions:
fn void encrypt_buffer(AesCtx *ctx, char[] text, char[] cipher)
fn void decrypt_buffer(AesCtx *ctx, char[] cipher, char[] text)

fn char[] encrypt(AesCtx *ctx, char[] text, Allocator allocator)
fn char[] decrypt(AesCtx *ctx, char[] cipher, Allocator allocator)

fn char[] encrypt_new(AesCtx *ctx, char[] text)
fn char[] encrypt_temp(AesCtx *ctx, char[] text)

fn char[] decrypt_new(AesCtx *ctx, char[] cipher)
fn char[] decrypt_temp(AesCtx *ctx, char[] cipher)
```


### Example: AEC128 ECB encryption

```cpp
module app;

import crypto::aes;
import std::io;

fn void main()
{
	char[] key 	= x"2b7e151628aed2a6abf7158809cf4f3c";
	char[] text	= x"6bc1bee22e409f96e93d7e117393172a";

	char[] cipher = ecb::encrypt_new(AesCtx{}.init(aes::AES128, key), text);
	defer free(cipher);

	assert(cipher == x"3ad77bb40d7a3660a89ecaf32466ef97");
}

```

### Installation

Clone the repository with
```git clone http://github.com/konimarti/aes.c3l```
to the `./lib` folder of your C3 project and add the following to
`project.json`:

```json
{
    "dependency-search-paths": [ "lib" ],
    "dependencies": [ "aes" ]
}
```

If you didn't clone it into the `lib` folder, adjust your
`dependency-search-paths` accordingly.
