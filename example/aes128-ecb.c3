module app;

import crypto::aes;
import std::io;

fn void main()
{
	char[] key 	= x"2b7e151628aed2a6abf7158809cf4f3c";
	char[] text	= x"6bc1bee22e409f96e93d7e117393172a";

	char[16] cipher;

	ecb::encrypt(AesCtx{}.init(aes::AES128, key), text, &cipher);

	assert(cipher[:16] == x"3ad77bb40d7a3660a89ecaf32466ef97");
}

