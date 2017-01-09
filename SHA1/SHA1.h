#ifndef SHA1_H_
#define SHA1_H_

#include <cstdint>

namespace SHA1
{
	struct SHA1State
	{
		uint32_t wv[5];
		uint8_t block[64];
		unsigned int blockCont;
		uint64_t fullMsgSize;
	};

	SHA1State *createSHA1Context();
	void doHash(SHA1State *nState);
	void update(SHA1State *state, const uint8_t *input, const unsigned int off, const unsigned int len);
	void padBlock(SHA1State *state);
	void finalise(SHA1State *state);


};

#endif //SHA1_h