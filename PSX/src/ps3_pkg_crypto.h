#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <windows.h>
#include <wincrypt.h>

// PS3 PKG Cryptography - WITH TYPE 0x0001 AUTO-DETECTION AND CMAC

namespace PS3Crypto {

	// PS3 NPDRM Package Key
	static const uint8_t PS3_PKG_AES_KEY[16] = {
		0x2E, 0x7B, 0x71, 0xD7, 0xC9, 0xC9, 0xA1, 0x4E,
		0xA3, 0x22, 0x1F, 0x18, 0x88, 0x28, 0xB8, 0xF8
	};

	// PSP NPDRM Package Key
	static const uint8_t PSP_PKG_AES_KEY[16] = {
		0x07, 0xF2, 0xC6, 0x82, 0x90, 0xB5, 0x0D, 0x2C,
		0x33, 0x81, 0x8D, 0x70, 0x9B, 0x60, 0xE6, 0x2B
	};

	static const uint8_t pkg_iv[16] = {
			 0x6C, 0xC6, 0x08, 0xD4, 0x6C, 0x84, 0xCE, 0x96,
			 0x7C, 0xDD, 0x83, 0xC1, 0xA6, 0xBB, 0x43, 0x69
	};
	// AES S-box
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

	// AES-CMAC Implementation
	class AESCMAC {
	private:
		AES128 aes;

		void LeftShift(const uint8_t* input, uint8_t* output) {
			uint8_t overflow = 0;
			for (int i = 15; i >= 0; i--) {
				output[i] = (input[i] << 1) | overflow;
				overflow = (input[i] & 0x80) ? 1 : 0;
			}
		}

		void XOR128(const uint8_t* a, const uint8_t* b, uint8_t* out) {
			for (int i = 0; i < 16; i++) {
				out[i] = a[i] ^ b[i];
			}
		}

		void GenerateSubkeys(uint8_t* K1, uint8_t* K2) {
			uint8_t L[16] = { 0 };
			aes.EncryptBlock(L);

			// Generate K1
			LeftShift(L, K1);
			if (L[0] & 0x80) {
				K1[15] ^= 0x87;
			}

			// Generate K2
			LeftShift(K1, K2);
			if (K1[0] & 0x80) {
				K2[15] ^= 0x87;
			}
		}

	public:
		AESCMAC(const uint8_t* key) : aes(key) {}

		void ComputeMAC(const uint8_t* data, size_t length, uint8_t* mac) {
			uint8_t K1[16], K2[16];
			GenerateSubkeys(K1, K2);

			size_t n = (length + 15) / 16; // Number of blocks
			if (n == 0) n = 1;

			bool complete = (length > 0) && (length % 16 == 0);
			uint8_t* lastBlock = new uint8_t[16];
			memset(lastBlock, 0, 16);

			if (complete) {
				memcpy(lastBlock, data + (n - 1) * 16, 16);
				XOR128(lastBlock, K1, lastBlock);
			}
			else {
				size_t lastLen = length % 16;
				if (lastLen == 0 && length > 0) lastLen = 16;
				if (length > 0) {
					memcpy(lastBlock, data + length - lastLen, lastLen);
				}
				lastBlock[lastLen] = 0x80; // Padding
				XOR128(lastBlock, K2, lastBlock);
			}

			uint8_t X[16] = { 0 };

			// Process all complete blocks except the last
			size_t blockCount = complete ? n - 1 : (length > 16 ? n - 1 : 0);
			for (size_t i = 0; i < blockCount; i++) {
				XOR128(X, data + i * 16, X);
				aes.EncryptBlock(X);
			}

			// Process last block
			XOR128(X, lastBlock, X);
			aes.EncryptBlock(X);

			memcpy(mac, X, 16);
			delete[] lastBlock;
		}
	};

	// Fast SHA1 using Windows CryptoAPI (for type 1 homebrew PKGs)
	class FastSHA1 {
	private:
		HCRYPTPROV hProv;
		HCRYPTHASH hHash;
		bool initialized;

	public:
		FastSHA1() : hProv(0), hHash(0), initialized(false) {
			if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
				initialized = true;
			}
		}

		~FastSHA1() {
			if (hHash) CryptDestroyHash(hHash);
			if (hProv) CryptReleaseContext(hProv, 0);
		}

		bool Hash(const uint8_t* data, size_t len, uint8_t* output) {
			if (!initialized) return false;

			if (hHash) {
				CryptDestroyHash(hHash);
				hHash = 0;
			}

			if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
				return false;
			}

			if (!CryptHashData(hHash, data, (DWORD)len, 0)) {
				return false;
			}

			DWORD hashLen = 20;
			if (!CryptGetHashParam(hHash, HP_HASHVAL, output, &hashLen, 0)) {
				return false;
			}

			return true;
		}
	};

	// SHA1 Context for streaming hash
	class SHA1Context {
	private:
		HCRYPTPROV hProv;
		HCRYPTHASH hHash;
		bool initialized;

	public:
		SHA1Context() : hProv(0), hHash(0), initialized(false) {
			if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
				if (CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
					initialized = true;
				}
			}
		}

		~SHA1Context() {
			if (hHash) CryptDestroyHash(hHash);
			if (hProv) CryptReleaseContext(hProv, 0);
		}

		void Update(const uint8_t* data, size_t len) {
			if (initialized && len > 0) {
				CryptHashData(hHash, data, (DWORD)len, 0);
			}
		}

		void Final(uint8_t* output) {
			if (initialized) {
				DWORD hashLen = 20;
				CryptGetHashParam(hHash, HP_HASHVAL, output, &hashLen, 0);
			}
		}

		bool IsValid() const { return initialized; }
	};

	// Compute AES-CMAC for PKG digest
	inline void ComputeAESCMAC(const uint8_t* data, size_t length, uint8_t* output) {
		AESCMAC cmac(PS3_PKG_AES_KEY);
		cmac.ComputeMAC(data, length, output);
	}

	// Increment key array
	inline bool IncrementArray(uint8_t* key, int keySize, int position = -1) {
		if (position < 0) position = keySize - 1;

		if (key[position] == 0xFF) {
			if (position != 0) {
				if (IncrementArray(key, keySize, position - 1)) {
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

	// Test if data decrypts correctly with AES
	inline bool TestAESDecryption(const uint8_t* data, size_t size, const uint8_t* pkg_data_riv, const uint8_t* aesKey) {
		if (size < 32) return false;

		// Make a copy to test
		std::vector<uint8_t> testBuf(data, data + 32);

		AES128 aes(aesKey);
		uint8_t pkgKey[16];
		memcpy(pkgKey, pkg_data_riv, 16);

		// Decrypt first two blocks
		for (size_t offset = 0; offset < 32; offset += 16) {
			uint8_t xorKey[16];
			memcpy(xorKey, pkgKey, 16);
			aes.EncryptBlock(xorKey);

			for (size_t j = 0; j < 16; j++) {
				testBuf[offset + j] ^= xorKey[j];
			}

			IncrementArray(pkgKey, 16);
		}

		// Check if result looks valid
		uint64_t tableSize1 = ((uint64_t)testBuf[8] << 56) | ((uint64_t)testBuf[9] << 48) |
			((uint64_t)testBuf[10] << 40) | ((uint64_t)testBuf[11] << 32) |
			((uint64_t)testBuf[12] << 24) | ((uint64_t)testBuf[13] << 16) |
			((uint64_t)testBuf[14] << 8) | testBuf[15];

		uint64_t tableSize2 = ((uint64_t)testBuf[16] << 56) | ((uint64_t)testBuf[17] << 48) |
			((uint64_t)testBuf[18] << 40) | ((uint64_t)testBuf[19] << 32) |
			((uint64_t)testBuf[20] << 24) | ((uint64_t)testBuf[21] << 16) |
			((uint64_t)testBuf[22] << 8) | testBuf[23];

		bool size1Valid = (tableSize1 > 0 && tableSize1 < 0x3200000);
		bool size2Valid = (tableSize2 > 0 && tableSize2 < 0x3200000);

		return (size1Valid || size2Valid);
	}

	// FIXED: Type 0x0001 can be EITHER homebrew (SHA1) OR retail (AES)
	inline void DecryptPS3PKG(uint8_t* data, size_t size, uint64_t relativeOffset,
		const uint8_t* pkg_data_riv, const uint8_t* qa_digest, uint16_t pkg_type,
		bool useAES_NotSHA1 = false) {

		bool useAES = false;
		bool useSHA1 = false;
		const uint8_t* keySource = nullptr;
		const uint8_t* aesKey = nullptr;
		int keySize = 0;

		// Check type and choose method
		if (pkg_type == 1) {
			if (useAES_NotSHA1) {
				useAES = true;
				keySource = pkg_data_riv;
				aesKey = PS3_PKG_AES_KEY;
				keySize = 16;
			}
			else {
				useSHA1 = true;
				keySource = qa_digest;
				keySize = 64;
			}
		}
		else if (pkg_type == 0x8001 || pkg_type == 0x80000001) {
			useAES = true;
			keySource = pkg_data_riv;
			aesKey = PS3_PKG_AES_KEY;
			keySize = 16;
		}
		else if (pkg_type == 0x8002 || pkg_type == 0x80000002) {
			useAES = true;
			keySource = pkg_data_riv;
			aesKey = PSP_PKG_AES_KEY;
			keySize = 16;
		}
		else {
			useAES = true;
			keySource = pkg_data_riv;
			aesKey = PS3_PKG_AES_KEY;
			keySize = 16;
		}

		if (useSHA1) {
			uint8_t key[64];
			memset(key, 0, 64);
			memcpy(key + 0, keySource + 0, 8);
			memcpy(key + 8, keySource + 0, 8);
			memcpy(key + 16, keySource + 8, 8);
			memcpy(key + 24, keySource + 8, 8);

			uint64_t startBlock = relativeOffset / 16;
			for (uint64_t i = 0; i < startBlock; i++) {
				IncrementArray(key, 64);
			}

			FastSHA1 sha;
			for (size_t offset = 0; offset < size; offset += 16) {
				uint8_t hash[20];
				sha.Hash(key, 64, hash);

				size_t blockSize = (size - offset < 16) ? (size - offset) : 16;
				for (size_t j = 0; j < blockSize; j++) {
					data[offset + j] ^= hash[j];
				}

				IncrementArray(key, 64);
			}
		}
		else if (useAES) {
			AES128 aes(aesKey);

			uint8_t pkgKey[16];
			memcpy(pkgKey, keySource, 16);

			uint64_t startBlock = relativeOffset / 16;
			for (uint64_t i = 0; i < startBlock; i++) {
				IncrementArray(pkgKey, 16);
			}

			for (size_t offset = 0; offset < size; offset += 16) {
				uint8_t xorKey[16];
				memcpy(xorKey, pkgKey, 16);
				aes.EncryptBlock(xorKey);

				size_t blockSize = (size - offset < 16) ? (size - offset) : 16;
				for (size_t j = 0; j < blockSize; j++) {
					data[offset + j] ^= xorKey[j];
				}

				IncrementArray(pkgKey, 16);
			}
		}
	}

	inline void GeneratePKGDigest(const uint8_t* data, uint32_t length, uint8_t* digest) {
		// Zero out the digest buffer
		memset(digest, 0, 0x40);

		// 1. Generate AES-CMAC (first 0x10 bytes)
		ComputeAESCMAC(data, length, digest);

		// 2. Fake signature (0x28 bytes at offset 0x10)
		// Since we can't generate valid ECDSA signatures without Sony's private key,
		// we use the same fake signature as the C# implementation
		const char* fake_sig = "Sony says PSN go byebye, always on NPDRM";
		memcpy(digest + 0x10, fake_sig, 0x28);  // 0x28 = 40 bytes

		// 3. SHA-1 hash (last 8 bytes at offset 0x38)
		uint8_t sha1_hash[20];
		FastSHA1 sha;
		if (sha.Hash(data, length, sha1_hash)) {
			// Copy last 8 bytes of SHA-1 hash (bytes 12-19)
			memcpy(digest + 0x38, sha1_hash + 12, 8);
		}
	}

	inline void EncryptPS3PKG(uint8_t* data, size_t size, uint64_t relativeOffset,
		const uint8_t* pkg_data_riv, const uint8_t* qa_digest, uint16_t pkg_type,
		bool useAES_NotSHA1 = false) {
		// AES-CTR and XOR-based encryption are symmetric operations
		DecryptPS3PKG(data, size, relativeOffset, pkg_data_riv, qa_digest, pkg_type, useAES_NotSHA1);
	}

} // namespace PS3Crypto