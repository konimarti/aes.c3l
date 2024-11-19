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

