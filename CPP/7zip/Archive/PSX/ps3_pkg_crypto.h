#pragma once
#include <cstdint>
#include <cstring>
#include <vector>

// PS3 PKG Cryptography Implementation
// Based on PKGView VB.NET - Uses SHA1 for retail, AES-ECB for debug/PSP

namespace PS3Crypto {

	// PS3 NPDRM Package Key (for debug PKGs type 0x80000001)
	static const uint8_t PS3_PKG_AES_KEY[16] = {
		0x2E, 0x7B, 0x71, 0xD7, 0xC9, 0xC9, 0xA1, 0x4E,
		0xA3, 0x22, 0x1F, 0x18, 0x88, 0x28, 0xB8, 0xF8
	};

	// PSP NPDRM Package Key (for type 0x80000002)
	static const uint8_t PSP_PKG_AES_KEY[16] = {
		0x07, 0xF2, 0xC6, 0x82, 0x90, 0xB5, 0x0D, 0x2C,
		0x33, 0x81, 0x8D, 0x70, 0x9B, 0x60, 0xE6, 0x2B
	};

	// AES S-box (keep your existing one)
	static const uint8_t AES_SBOX[256] = {
		0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
		0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
		0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
		0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
		0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
		0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
		0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
		0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
		0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
		0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
		0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
		0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
		0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
		0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
		0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
		0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
	};

	static const uint8_t AES_RCON[11] = {
		0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
	};

	static uint8_t gmul(uint8_t a, uint8_t b) {
		uint8_t p = 0;
		for (int i = 0; i < 8; i++) {
			if (b & 1) p ^= a;
			bool hi_bit_set = (a & 0x80);
			a <<= 1;
			if (hi_bit_set) a ^= 0x1B;
			b >>= 1;
		}
		return p;
	}

	// Keep your AES128 class (it's correct for ECB mode)
	class AES128 {
	private:
		uint8_t roundKeys[11][16];

		void SubBytes(uint8_t* state) {
			for (int i = 0; i < 16; i++) state[i] = AES_SBOX[state[i]];
		}

		void ShiftRows(uint8_t* state) {
			uint8_t temp;
			temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;
			temp = state[2]; state[2] = state[10]; state[10] = temp;
			temp = state[6]; state[6] = state[14]; state[14] = temp;
			temp = state[3]; state[3] = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = temp;
		}

		void MixColumns(uint8_t* state) {
			for (int i = 0; i < 4; i++) {
				uint8_t* col = state + (i * 4);
				uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
				col[0] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
				col[1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
				col[2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
				col[3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
			}
		}

		void AddRoundKey(uint8_t* state, int round) {
			for (int i = 0; i < 16; i++) state[i] ^= roundKeys[round][i];
		}

		void KeyExpansion(const uint8_t* key) {
			memcpy(roundKeys[0], key, 16);
			for (int i = 1; i <= 10; i++) {
				uint8_t temp[4];
				memcpy(temp, &roundKeys[i - 1][12], 4);
				uint8_t k = temp[0];
				temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = k;
				for (int j = 0; j < 4; j++) temp[j] = AES_SBOX[temp[j]];
				temp[0] ^= AES_RCON[i];
				for (int j = 0; j < 4; j++) roundKeys[i][j] = roundKeys[i - 1][j] ^ temp[j];
				for (int j = 4; j < 16; j++) roundKeys[i][j] = roundKeys[i - 1][j] ^ roundKeys[i][j - 4];
			}
		}

	public:
		AES128(const uint8_t* key) { KeyExpansion(key); }

		void EncryptBlock(uint8_t* block) {
			AddRoundKey(block, 0);
			for (int round = 1; round < 10; round++) {
				SubBytes(block); ShiftRows(block); MixColumns(block); AddRoundKey(block, round);
			}
			SubBytes(block); ShiftRows(block); AddRoundKey(block, 10);
		}
	};

	// Simple SHA1 implementation
	class SHA1 {
	private:
		uint32_t h[5];

		uint32_t leftrotate(uint32_t value, int shift) {
			return (value << shift) | (value >> (32 - shift));
		}

		void ProcessBlock(const uint8_t* block) {
			uint32_t w[80];

			// Prepare message schedule
			for (int i = 0; i < 16; i++) {
				w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) |
					(block[i * 4 + 2] << 8) | block[i * 4 + 3];
			}
			for (int i = 16; i < 80; i++) {
				w[i] = leftrotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
			}

			// Working variables
			uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];

			// Main loop
			for (int i = 0; i < 80; i++) {
				uint32_t f, k;
				if (i < 20) {
					f = (b & c) | ((~b) & d);
					k = 0x5A827999;
				}
				else if (i < 40) {
					f = b ^ c ^ d;
					k = 0x6ED9EBA1;
				}
				else if (i < 60) {
					f = (b & c) | (b & d) | (c & d);
					k = 0x8F1BBCDC;
				}
				else {
					f = b ^ c ^ d;
					k = 0xCA62C1D6;
				}

				uint32_t temp = leftrotate(a, 5) + f + e + k + w[i];
				e = d;
				d = c;
				c = leftrotate(b, 30);
				b = a;
				a = temp;
			}

			// Add to hash
			h[0] += a;
			h[1] += b;
			h[2] += c;
			h[3] += d;
			h[4] += e;
		}

	public:
		void Hash(const uint8_t* data, size_t len, uint8_t* output) {
			// Initialize hash values
			h[0] = 0x67452301;
			h[1] = 0xEFCDAB89;
			h[2] = 0x98BADCFE;
			h[3] = 0x10325476;
			h[4] = 0xC3D2E1F0;

			// Process complete blocks
			size_t numBlocks = len / 64;
			for (size_t i = 0; i < numBlocks; i++) {
				ProcessBlock(data + i * 64);
			}

			// Handle final block with padding
			uint8_t finalBlock[128]; // Need up to 2 blocks for padding
			size_t remaining = len % 64;
			memcpy(finalBlock, data + numBlocks * 64, remaining);

			// Add padding
			finalBlock[remaining] = 0x80;

			// Check if we need 2 blocks
			if (remaining >= 56) {
				// Need 2 blocks - pad first block
				for (size_t i = remaining + 1; i < 64; i++) {
					finalBlock[i] = 0;
				}
				ProcessBlock(finalBlock);

				// Second block is all zeros except length
				memset(finalBlock, 0, 64);
			}
			else {
				// One block is enough - pad to 56 bytes
				for (size_t i = remaining + 1; i < 56; i++) {
					finalBlock[i] = 0;
				}
			}

			// Add length in bits (big-endian)
			uint64_t bitLen = len * 8;
			for (int i = 0; i < 8; i++) {
				finalBlock[56 + i] = (bitLen >> (56 - i * 8)) & 0xFF;
			}

			ProcessBlock(finalBlock);

			// Output hash (big-endian)
			for (int i = 0; i < 5; i++) {
				output[i * 4 + 0] = (h[i] >> 24) & 0xFF;
				output[i * 4 + 1] = (h[i] >> 16) & 0xFF;
				output[i * 4 + 2] = (h[i] >> 8) & 0xFF;
				output[i * 4 + 3] = h[i] & 0xFF;
			}
		}
	};

	// Build key from QA digest (VB.NET fillkey function)
	inline void BuildKey(uint8_t* key, const uint8_t* qa_digest, uint16_t pkg_type) {
		if (pkg_type == 1) {
			memset(key, 0, 64);
			memcpy(key + 0, qa_digest + 0, 8);
			memcpy(key + 8, qa_digest + 0, 8);
			memcpy(key + 16, qa_digest + 8, 8);
			memcpy(key + 24, qa_digest + 8, 8);
		}
		else {
			memcpy(key, qa_digest, 16);
		}
	}

	// Increment key array (VB.NET IncrementArray)
	inline bool IncrementArray(uint8_t* key, uint16_t pkg_type, int position = -1) {
		int maxPos = (pkg_type == 1) ? 63 : 15;
		if (position < 0) position = maxPos;

		if (key[position] == 0xFF) {
			if (position != 0) {
				if (IncrementArray(key, pkg_type, position - 1)) {
					key[position] = 0x00;
					return true;
				}
				return false;
			}
			return false;
		}
		key[position] += 0x01;
		return true;
	}

	// Calculate hash (VB.NET CalculeHash)
	inline void CalculateHash(uint8_t* output, const uint8_t* key, uint16_t pkg_type) {
		if (pkg_type == 1) {
			SHA1 sha;
			sha.Hash(key, 64, output);
		}
		else if (pkg_type == 0x8001) {
			AES128 aes(PS3_PKG_AES_KEY);
			memcpy(output, key, 16);
			aes.EncryptBlock(output);
		}
		else if (pkg_type == 0x8002) {
			AES128 aes(PSP_PKG_AES_KEY);
			memcpy(output, key, 16);
			aes.EncryptBlock(output);
		}
	}

	// Main decryption function (matches VB.NET decrypt function)
	inline void DecryptPS3PKG(uint8_t* data, size_t size, uint64_t relativeOffset,
		const uint8_t* pkg_data_riv, uint16_t pkg_type) {

		uint8_t key[64];
		BuildKey(key, pkg_data_riv, pkg_type);

		uint64_t startBlock = relativeOffset / 16;
		for (uint64_t i = 0; i < startBlock; i++) {
			IncrementArray(key, pkg_type);
		}

		for (size_t offset = 0; offset < size; offset += 16) {
			uint8_t hashValue[20];
			CalculateHash(hashValue, key, pkg_type);

			size_t blockSize = (size - offset < 16) ? (size - offset) : 16;
			for (size_t j = 0; j < blockSize; j++) {
				data[offset + j] ^= hashValue[j];
			}

			IncrementArray(key, pkg_type);
		}
	}

} // namespace PS3Crypto