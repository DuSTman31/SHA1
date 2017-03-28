// SHA1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <cstdint>
#include <cstring>
#include "Endian.h"
#include "SHA1.h"
#include <cstdio>

namespace SHA1
{
	uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

	SHA1State *createSHA1Context()
	{
		SHA1State *ns = new SHA1State;
	
		ns->wv[0] = h[0];
		ns->wv[1] = h[1];
		ns->wv[2] = h[2];
		ns->wv[3] = h[3];
		ns->wv[4] = h[4];

		ns->blockCont = 0;
		ns->fullMsgSize = 0;

		return ns;
	}

	// As we're not using assembly, we can't use the native rotation instructions
	//	replace it with a small inline
	static inline uint32_t rotateLeft(uint32_t x, int n)
	{
		return ((x << n) | (x >> (32 - n)));
	}

	static inline uint32_t ch(const uint32_t x, const uint32_t y, const uint32_t z)
	{
		return ((x&y)^((~x)&z));
	}

	static inline uint32_t parity(const uint32_t x, const uint32_t y, const uint32_t z)
	{
		return ((x^y)^z);
	}

	static inline uint32_t maj(const uint32_t x, const uint32_t y, const uint32_t z)
	{
		return ((x&y)^(x&z)^(y&z));
	}

	static inline uint32_t ft(const unsigned int t, const uint32_t x, const uint32_t y, const uint32_t z)
	{
		if (t <= 19)
		{
			return ch(x, y, z);
		}
		else if ((t >= 20) && (t <= 39))
		{
			return parity(x, y, z);
		}
		else if ((t >= 40) && (t <= 59))
		{
			return maj(x, y, z);
		}
		else if ((t >= 60) && (t <= 79))
		{
			return parity(x, y, z);
		}
		return 0;
	}

	static inline uint32_t kt(const unsigned int t)
	{
		if (t <= 19)
		{
			return 0x5A827999;
		}
		else if ((t >= 20) && (t <= 39))
		{
			return 0x6ED9EBA1;
		}
		else if ((t >= 40) && (t <= 59))
		{
			return 0x8F1BBCDC;
		}
		else if ((t >= 60) && (t <= 79))
		{
			return 0xCA62C1D6;
		}
		return 0;
	}

	void doHash(SHA1State *nState)
	{
		uint32_t w[80];

		uint32_t a = nState->wv[0];
		uint32_t b = nState->wv[1];
		uint32_t c = nState->wv[2];
		uint32_t d = nState->wv[3];
		uint32_t e = nState->wv[4];

		uint8_t *messageBlock = nState->block;
		for(unsigned int i=0 ; i!=16 ; i++)
		{
			w[i] = BigToNative(((uint32_t *)messageBlock)[i]);
		}
		for (unsigned int i = 16; i != 80; i++)
		{
			w[i] = rotateLeft(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
		}


		unsigned int t = 0;
		uint32_t tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 1;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 2;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 3;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 4;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 5;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 6;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 7;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 8;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 9;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 10;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 11;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 12;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 13;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 14;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 15;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 16;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 17;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 18;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 19;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 20;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 21;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 22;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 23;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 24;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 25;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 26;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 27;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 28;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 29;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 30;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 31;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 32;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 33;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 34;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 35;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 36;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 37;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 38;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 39;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 40;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 41;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 42;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 43;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 44;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 45;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 46;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 47;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 48;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 49;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 50;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 51;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 52;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 53;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 54;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 55;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 56;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 57;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 58;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 59;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 60;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 61;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 62;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 63;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 64;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 65;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 66;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 67;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 68;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 69;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 70;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 71;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 72;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 73;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 74;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 75;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 76;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 77;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 78;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;
		t = 79;
		tt = 0;
		tt = rotateLeft(a, 5);
		tt += ft(t, b, c, d);
		tt += e;
		tt += kt(t);
		tt += w[t];
		e = d;
		d = c;
		c = rotateLeft(b, 30);
		b = a;
		a = tt;


		nState->wv[0] = a + nState->wv[0];
		nState->wv[1] = b + nState->wv[1];
		nState->wv[2] = c + nState->wv[2];
		nState->wv[3] = d + nState->wv[3];
		nState->wv[4] = e + nState->wv[4];
	}

	void update(SHA1State *state, const uint8_t *input, const unsigned int off, const unsigned int len)
	{
		unsigned int blockCont = state->blockCont;
		unsigned int copy_start = off;

		while (true)
		{
			unsigned int toCopy = 0;

			toCopy = 64 - blockCont;
			if (toCopy > (len - copy_start))
			{
				toCopy = len - copy_start;

				for (unsigned int i = 0; i != toCopy; i++)
				{
					state->block[blockCont + i] = input[i + copy_start];
				}

				blockCont += toCopy;
				state->blockCont = blockCont;

				state->fullMsgSize += len - off;

				return;
			}
			else
			{
				for (unsigned int i = 0; i != toCopy; i++)
				{
					state->block[blockCont + i] = input[i + copy_start];
				}

				doHash(state);

				blockCont = 0;
				copy_start += toCopy;
			}


		}
	}

	void padBlock(SHA1State *state)
	{
		uint8_t *buf = state->block;
		uint64_t fullMsgSize = state->fullMsgSize;
		unsigned int msgSize = state->blockCont;

		for (unsigned int i = msgSize; i != 64; i++)
		{
			buf[i] = 0;
		}
		buf[msgSize] = 0x80;


		unsigned int bitsToPad = 512 - (msgSize * 8);
		bitsToPad--;

		uint64_t msgSizeBuf = NativeToBig(fullMsgSize*8);
		//uint64_t msgSizeBuf = fullMsgSize*8;
		for (unsigned int i = 0 ; i!=sizeof(uint64_t) ; i++)
		{
			buf[56 + i] = ((char *)&msgSizeBuf)[i];
		}

		doHash(state);
	}

	void finalise(SHA1State *state)
	{
		padBlock(state);

		for (unsigned int i=0 ; i!=5 ; i++)
		{
			state->wv[i] = NativeToBig(state->wv[i]);
		}
	}

};

int _tmain(int argc, _TCHAR* argv[])
{
	SHA1::SHA1State *nState = SHA1::createSHA1Context();

	unsigned int bufferSize = 4096;
	FILE *fHand = fopen("test.txt", "rb");
	uint8_t *buf = new uint8_t[bufferSize];

	while (true)
	{
		unsigned int bytesRead = fread(buf, 1, bufferSize, fHand);
		SHA1::update(nState, buf, 0, bytesRead);
		if (bytesRead < bufferSize)
		{
			break; 
		}
	}

	char *message = "The quick brown fox jumps over the lazy dog";
	unsigned int messageSize = strlen(message);

	//SHA1::padBlock(nState, message, messageSize, messageSize);

	SHA1::finalise(nState);

	unsigned char *op = (unsigned char*)&(nState->wv[0]);
	printf("SHA-1 : ");
	for (unsigned int i = 0; i != (160 / 8); i++)
	{
		printf("%.2x", *(op++));
	}
	printf("\n");

	return 0;
}

