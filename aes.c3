module crypto::aes;

import std::io;

import crypto::aes::impl @public;

/*
Port of github.com/kokke/tiny-aes-c

This is an implementation of the AES algorithm, specifically ECB, CTR and CBC
mode. Key size can be chosen in aes.h - available choices are AES128, AES192,
AES256.

The implementation is verified against the test vectors in:
  National Institute of Standards and Technology Special Publication 800-38A
2001 ED

String length must be evenly divisible by 16 bytes (str_len % 16 == 0).
You should pad the end of the string with zeros if this is not the case.
For AES192/256 the key size is proportionally larger.

*/

// block length in bytes. AES is 128-bit blocks only.
const BLOCKLEN = 16;

// number of columns of a AES state.
const NB = 4;

struct AesKey
{
	usz key_size;
	int key_len;
	int key_exp_size; // expected size of round_key
	usz nk; // number of 32 bit words in a key.
	usz nr; // number of rounds in AES cipher.
}

const AesKey AES128 = { 128, 16, 176, 4, 10 };
const AesKey AES192 = { 192, 24, 208, 6, 12 };
const AesKey AES256 = { 256, 32, 240, 8, 14 };

/*
 *
 * AesCtx
 *
 */

struct AesCtx
{
	AesKey type;
	char[256] round_key;
	char[BLOCKLEN] iv;
	char[NB][NB] state;
}

<*
@require key.len == type.key_len, "Key does not match expected size."
*>
fn AesCtx* AesCtx.init(&self, AesKey type, char[] key)
{
	self.type = type;
	self.type.key_expansion(&self.round_key, key);
	return self;
}

<*
@require key.len == type.key_len, "Key does not match expected length."
@require iv.len == BLOCKLEN, "iv length should be equal to BLOCKLEN."
*>
fn AesCtx* AesCtx.init_with_iv(&self, AesKey type, char[] key, char[] iv)
{
	self.init(type, key);
	if (iv.len < BLOCKLEN)
	{
		io::eprintn("iv: not long enough?");
	}
	self.iv[:BLOCKLEN] = iv[:BLOCKLEN];
	return self;
}

<*
@require iv.len == BLOCKLEN, "iv length should be equal to BLOCKLEN."
*>
fn AesCtx* AesCtx.set_iv(&self, char[] iv)
{
	self.iv[:BLOCKLEN] = iv[:BLOCKLEN];
	return self;
}


module crypto::aes::impl @private;

macro char get_sbox_value(num) => SBOX[num];
macro char get_sbox_invert(num) => RSBOX[num];

const char[256] SBOX = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

const char[256] RSBOX = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

const char[11] RCON = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
};

fn void AesCtx.add_round_key(&self, usz round, char[] round_key) @private
{
	usz i, j;
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			self.state[i][j] ^= round_key[(round * aes::NB * 4) + (i * aes::NB) + j];
		}
	}
}

fn void AesCtx.sub_bytes(&self) @private
{
	usz i, j;
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			self.state[j][i] = get_sbox_value(self.state[j][i]);
		}
	}
}

fn void AesCtx.shift_rows(&self) @private
{
	char temp;

	temp        = self.state[0][1];
	self.state[0][1] = self.state[1][1];
	self.state[1][1] = self.state[2][1];
	self.state[2][1] = self.state[3][1];
	self.state[3][1] = temp;

	temp	    = self.state[0][2];
	self.state[0][2] = self.state[2][2];
	self.state[2][2] = temp;

	temp	    = self.state[1][2];
	self.state[1][2] = self.state[3][2];
	self.state[3][2] = temp;

	temp	    = self.state[0][3];
	self.state[0][3] = self.state[3][3];
	self.state[3][3] = self.state[2][3];
	self.state[2][3] = self.state[1][3];
	self.state[1][3] = temp;
}

fn char xtime(char x) @local
{
	return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

fn void AesCtx.mix_columns(&self) @private
{
	usz i;
	char tmp, tm, t;
	for (i = 0; i < 4; i++)
	{
		t = self.state[i][0];
		tmp = self.state[i][0] ^ self.state[i][1] ^ self.state[i][2] ^ self.state[i][3];

		tm = self.state[i][0] ^ self.state[i][1];
		tm = xtime(tm);
		self.state[i][0] ^= tm ^ tmp;

		tm = self.state[i][1] ^ self.state[i][2];
		tm = xtime(tm);
		self.state[i][1] ^= tm ^ tmp;

		tm = self.state[i][2] ^ self.state[i][3];
		tm = xtime(tm);
		self.state[i][2] ^= tm ^ tmp;

		tm = self.state[i][3] ^ t;
		tm = xtime(tm);
		self.state[i][3] ^= tm ^ tmp;
	}
}

fn char multiply(char x, char y) @local
{
	return (((y & 1) * x) ^
	(((y>>1) & 1) * xtime(x)) ^
	(((y>>2) & 1) * xtime(xtime(x))) ^
	(((y>>3) & 1) * xtime(xtime(xtime(x)))) ^
	(((y>>4) & 1) * xtime(xtime(xtime(xtime(x))))));
}

fn void AesCtx.inv_mix_columns(&self) @private
{
	usz i;
	char a, b, c, d;
	for (i = 0; i < 4; i++)
	{
		a = self.state[i][0];
		b = self.state[i][1];
		c = self.state[i][2];
		d = self.state[i][3];

		self.state[i][0] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
		self.state[i][1] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
		self.state[i][2] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
		self.state[i][3] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
	}
}

fn void AesCtx.inv_sub_bytes(&self) @private
{
	usz i, j;
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			self.state[j][i] = get_sbox_invert(self.state[j][i]);
		}
	}
}

fn void AesCtx.inv_shift_rows(&self) @private
{
	char temp;

	temp        = self.state[3][1];
	self.state[3][1] = self.state[2][1];
	self.state[2][1] = self.state[1][1];
	self.state[1][1] = self.state[0][1];
	self.state[0][1] = temp;

	temp	    = self.state[0][2];
	self.state[0][2] = self.state[2][2];
	self.state[2][2] = temp;

	temp	    = self.state[1][2];
	self.state[1][2] = self.state[3][2];
	self.state[3][2] = temp;

	temp	    = self.state[0][3];
	self.state[0][3] = self.state[1][3];
	self.state[1][3] = self.state[2][3];
	self.state[2][3] = self.state[3][3];
	self.state[3][3] = temp;
}

fn void AesCtx.cipher(&self, char[] round_key) @private
{
	usz round = 0;

	self.add_round_key(0, round_key);

	for LOOP: (round = 1; ; round++)
	{
		self.sub_bytes();
		self.shift_rows();
		if (round == self.type.nr) break LOOP;
		self.mix_columns();
		self.add_round_key(round, round_key);
	}
	self.add_round_key(self.type.nr, round_key);
}

fn void AesCtx.inv_cipher(&self, char[] round_key) @private
{
	usz round = 0;

	self.add_round_key(self.type.nr, round_key);

	for LOOP: (round = self.type.nr - 1; ; round--)
	{
		self.inv_shift_rows();
		self.inv_sub_bytes();
		self.add_round_key(round, round_key);
		if (round == 0) break LOOP;
		self.inv_mix_columns();
	}
}

/*
 *
 * AesKey
 *
 */

<*
@require key.len == self.key_len, "Key does not match expected length."
*>
fn void AesKey.key_expansion(&self, char[] round_key, char[] key) @private
{
	usz i, j, k;
	char[4] tempa;

	for (i = 0; i < self.nk; i++)
	{
		round_key[(i * 4) + 0] = key[(i * 4) + 0];
		round_key[(i * 4) + 1] = key[(i * 4) + 1];
		round_key[(i * 4) + 2] = key[(i * 4) + 2];
		round_key[(i * 4) + 3] = key[(i * 4) + 3];
	}

	for (i = self.nk; i < aes::NB * (self.nr + 1); i++)
	{
		k = (i - 1) * 4;
		tempa[0] = round_key[k + 0];
		tempa[1] = round_key[k + 1];
		tempa[2] = round_key[k + 2];
		tempa[3] = round_key[k + 3];

		if (i % self.nk == 0)
		{
			// rotword
			char tmp = tempa[0];
			tempa[0] = tempa[1];
			tempa[1] = tempa[2];
			tempa[2] = tempa[3];
			tempa[3] = tmp;

			// subword
			tempa[0] = get_sbox_value(tempa[0]);
			tempa[1] = get_sbox_value(tempa[1]);
			tempa[2] = get_sbox_value(tempa[2]);
			tempa[3] = get_sbox_value(tempa[3]);

			tempa[0] = tempa[0] ^ RCON[i/self.nk];
		}

		if (self.key_size == 256)
		{
			if (i % self.nk == 4)
			{
				// subword
				tempa[0] = get_sbox_value(tempa[0]);
				tempa[1] = get_sbox_value(tempa[1]);
				tempa[2] = get_sbox_value(tempa[2]);
				tempa[3] = get_sbox_value(tempa[3]);
			}
		}
		j = i * 4;
		k = (i - self.nk) * 4;
		round_key[j + 0] = round_key[k + 0] ^ tempa[0];
		round_key[j + 1] = round_key[k + 1] ^ tempa[1];
		round_key[j + 2] = round_key[k + 2] ^ tempa[2];
		round_key[j + 3] = round_key[k + 3] ^ tempa[3];
	}
}

/*
 *
 * ECB
 *
 */
module crypto::aes::ecb;

import crypto::aes::impl @public;

fn void encrypt(AesCtx *ctx, char[] buf, char[] out) @inline => ecb_encrypt(ctx, buf, out);
fn void decrypt(AesCtx *ctx, char[] buf, char[] out) @inline => ecb_decrypt(ctx, buf, out);

<*
@param [&inout] ctx "AES context."
@param [in] buf "Plaintext input."
@param [out] out "Cipher output."
@require buf.len == 16, out.len == 16
*>
fn void ecb_encrypt(AesCtx *ctx, char[] buf, char[] out)
{
	usz i, j;
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			ctx.state[i][j] = buf[i*4+j];
		}
	}
	ctx.cipher(&ctx.round_key);
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			out[i*4+j] = ctx.state[i][j];
		}
	}
}

<*
@param [&inout] ctx "AES context."
@param [in] buf "Plaintext input."
@param [out] out "Cipher output."
@require buf.len == 16, out.len == 16
*>
fn void ecb_decrypt(AesCtx *ctx, char[] buf, char[] out)
{
	usz i, j;
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			ctx.state[i][j] = buf[i*4+j];
		}
	}
	ctx.inv_cipher(&ctx.round_key);
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			out[i*4+j] = ctx.state[i][j];
		}
	}
}

/*
 *
 * CBC
 *
 */
module crypto::aes::cbc;

import crypto::aes::ecb;

fn void encrypt(AesCtx *ctx, char[] buf, char[] out) @inline => cbc_encrypt_buffer(ctx, buf, out);
fn void decrypt(AesCtx *ctx, char[] buf, char[] out) @inline => cbc_decrypt_buffer(ctx, buf, out);


fn void xor_with_iv(char[] buf, char[] iv) @local
{
	usz i;
	for (i = 0; i < aes::BLOCKLEN; i++)
	{
		buf[i] ^= iv[i];
	}
}

<*
@param [&inout] ctx "AES context."
@param [in] buf "Plaintext input."
@param [out] out "Cipher output."
@require buf.len % aes::BLOCKLEN == 0, "buf must be a multiple of 16."
@require out.len % aes::BLOCKLEN == 0, "out must be a multiple of 16."
*>
fn void cbc_encrypt_buffer(AesCtx *ctx, char[] buf, char[] out)
{
	usz i;
	char[] iv = ctx.iv[..];
	char[aes::BLOCKLEN] tmp;
	char[aes::BLOCKLEN] tmp2;
	for (i = 0; i < buf.len; i += aes::BLOCKLEN)
	{
		tmp[:aes::BLOCKLEN] = buf[i:aes::BLOCKLEN];
		xor_with_iv(&tmp, iv);
		ecb::encrypt(ctx, &tmp, &tmp2);
		out[i:aes::BLOCKLEN] = tmp2[..];
		iv[:aes::BLOCKLEN] = tmp2[..];
	}
	// store iv in ctx for next call
	ctx.iv[:aes::BLOCKLEN] = iv[:aes::BLOCKLEN];
}

<*
@param [&inout] ctx "AES context."
@param [in] buf "Cipher input."
@param [out] out "Plaintext output."
@require buf.len % aes::BLOCKLEN == 0, "buf must be a multiple of 16."
@require out.len % aes::BLOCKLEN == 0, "out must be a multiple of 16."
*>
fn void cbc_decrypt_buffer(AesCtx *ctx, char[] buf, char[] out)
{
	usz i;
	char[aes::BLOCKLEN] tmp;
	for (i = 0; i < buf.len; i += aes::BLOCKLEN)
	{
		ecb::decrypt(ctx, buf[i:aes::BLOCKLEN], &tmp);
		xor_with_iv(&tmp, ctx.iv[..]);
		out[i:aes::BLOCKLEN] = tmp[..];
		ctx.iv[:aes::BLOCKLEN] = buf[i:aes::BLOCKLEN];
	}
}

/*
 *
 * CTR
 *
 */
module crypto::aes::ctr;

import crypto::aes::ecb;

fn void encrypt(AesCtx *ctx, char[] buf, char[] out) @inline => ctr_xcrypt_buffer(ctx, buf, out);
fn void decrypt(AesCtx *ctx, char[] buf, char[] out) @inline => ctr_xcrypt_buffer(ctx, buf, out);

<*
@param [&inout] ctx "AES context."
@param [in] buf "Plaintext input."
@param [out] out "Cipher output."
@require buf.len % aes::BLOCKLEN == 0, "buf must be a multiple of 16."
@require out.len % aes::BLOCKLEN == 0, "out must be a multiple of 16."
*>
fn void ctr_xcrypt_buffer(AesCtx *ctx, char[] buf, char[] out)
{
	 char[aes::BLOCKLEN] buffer;

	 usz i;
	 int bi = aes::BLOCKLEN;
	 for (i = 0; i < buf.len; i++)
	 {
		 if (bi == aes::BLOCKLEN)
		 {
			 buffer[..] = ctx.iv[..];
			 ecb::encrypt(ctx, &buffer, &buffer);

			 for LOOP: (bi = (aes::BLOCKLEN - 1); bi >= 0; bi--)
			 {
				 if (ctx.iv[bi] == 255)
				 {
					 ctx.iv[bi] = 0;
					 continue;
				 }
				 ctx.iv[bi] += 1;
				 break LOOP;
			 }
			 bi = 0;
		 }
		 out[i] = (buf[i] ^ buffer[bi]);
		 bi++;
	 }
}

