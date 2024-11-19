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

// Start encrypting and decrypting with either the ECB or CBC modes.
fn void ecb_encrypt(AesCtx *ctx, char[] buf, char[] out)
fn void ecb_decrypt(AesCtx *ctx, char[] buf, char[] out)

fn void cbc_encrypt_buffer(AesCtx *ctx, char[] buf, char[] out)
fn void cbc_decrypt_buffer(AesCtx *ctx, char[] buf, char[] out)

// Same function for encrypting as for decrypting in CTR mode
fn void ctr_xcrypt_buffer(AesCtx *ctx, char[] buf, char[] out)
```


### Example: AEC128 ECB encryption

```cpp
module app;

import crypto::aes;
import std::io;

fn void main()
{
	AesKeyType type = aes::AES128;

	char[] key 	= x"2b7e151628aed2a6abf7158809cf4f3c";
	char[] text	= x"6bc1bee22e409f96e93d7e117393172a";
	char[] cipher 	= x"3ad77bb40d7a3660a89ecaf32466ef97";

	char[16] out;

	aes::ecb_encrypt(AesCtx{}.init(type, key), text, &out);

	assert(out[:16] == cipher[:16]);
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
