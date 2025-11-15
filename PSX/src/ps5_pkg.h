#pragma once
#include <windows.h>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <string>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib") 

class SHA3_256 {
private:
  static const uint64_t keccakf_rndc[24];
  static const int keccakf_rotc[24];
  static const int keccakf_piln[24];

  static uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
  }

  static void keccakf(uint64_t st[25]) {
    uint64_t t, bc[5];

    for (int round = 0; round < 24; round++) {
      // Theta
      for (int i = 0; i < 5; i++) {
        bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
      }

      for (int i = 0; i < 5; i++) {
        t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
        for (int j = 0; j < 25; j += 5) {
          st[j + i] ^= t;
        }
      }

      // Rho Pi
      t = st[1];
      for (int i = 0; i < 24; i++) {
        int j = keccakf_piln[i];
        bc[0] = st[j];
        st[j] = rotl64(t, keccakf_rotc[i]);
        t = bc[0];
      }

      // Chi
      for (int j = 0; j < 25; j += 5) {
        for (int i = 0; i < 5; i++) {
          bc[i] = st[j + i];
        }
        for (int i = 0; i < 5; i++) {
          st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
      }

      // Iota
      st[0] ^= keccakf_rndc[round];
    }
  }

public:
  static std::vector<uint8_t> HashData(const uint8_t* data, size_t length) {
    uint64_t state[25] = { 0 };
    const size_t rate = 136; // SHA3-256 rate (1088 bits / 8)

    uint8_t* stateBytes = (uint8_t*)state;

    // Absorb phase
    size_t offset = 0;
    while (offset < length) {
      size_t blockSize = std::min(rate, length - offset);

      for (size_t i = 0; i < blockSize; i++) {
        stateBytes[i] ^= data[offset + i];
      }

      offset += blockSize;

      if (blockSize == rate) {
        keccakf(state);
      }
    }

    // Padding (SHA3 uses 0x06 for domain separation)
    stateBytes[offset % rate] ^= 0x06;
    stateBytes[rate - 1] ^= 0x80;

    keccakf(state);

    // Squeeze phase - extract 32 bytes
    std::vector<uint8_t> hash(32);
    memcpy(hash.data(), stateBytes, 32);

    return hash;
  }
};

// Keccak round constants
const uint64_t SHA3_256::keccakf_rndc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

const int SHA3_256::keccakf_rotc[24] = {
    1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
    27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
};

const int SHA3_256::keccakf_piln[24] = {
    10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
};

// ---------------------------------------------------------------------
// PS5 PKG constants
// ---------------------------------------------------------------------
#define PKG_MAGIC_PS5 0x7F464948

// RSA Keyset for PS5 PKG Derived Key 3
struct RSAKeyset {
  std::vector<uint8_t> Prime1;
  std::vector<uint8_t> Prime2;
  std::vector<uint8_t> PrivateExponent;
  std::vector<uint8_t> Exponent1;
  std::vector<uint8_t> Exponent2;
  std::vector<uint8_t> Coefficient;
  std::vector<uint8_t> Modulus;
  std::vector<uint8_t> PublicExponent;

  static RSAKeyset GetPkgDerivedKey3Keyset() {
    RSAKeyset keyset;

    // Prime1 (p)
    keyset.Prime1 = {
      0xD8, 0x4F, 0x78, 0x93, 0x8F, 0x31, 0xF4, 0x56, 0xE8, 0x28, 0xCF, 0x28, 0x90, 0x62, 0x04, 0xD9,
      0x36, 0x99, 0xF6, 0xA3, 0x19, 0x6E, 0xC7, 0x27, 0x53, 0x6D, 0xFB, 0x68, 0x5E, 0x63, 0xC4, 0xCF,
      0xAD, 0x76, 0x07, 0x88, 0x1F, 0x6F, 0x3F, 0xBD, 0x86, 0xBD, 0x3A, 0x05, 0x62, 0xC5, 0x22, 0xFD,
      0x0A, 0x42, 0x7D, 0x12, 0x02, 0xC3, 0x77, 0xCE, 0xE3, 0x73, 0xC9, 0x51, 0xE7, 0x63, 0x07, 0x29,
      0x89, 0x00, 0xF2, 0x91, 0x5E, 0xE5, 0xDD, 0xB1, 0x3F, 0x96, 0x14, 0xBA, 0xC3, 0x5F, 0xD2, 0x2B,
      0x34, 0xBD, 0xA8, 0x5B, 0xFF, 0x86, 0xBC, 0xC7, 0x1E, 0x98, 0x8F, 0x64, 0x22, 0xE3, 0xA0, 0x2E,
      0xC9, 0xD1, 0x8D, 0x44, 0xE4, 0xC0, 0xD0, 0x54, 0x5D, 0xBA, 0x7E, 0xC6, 0x59, 0x3A, 0xAE, 0xCB,
      0x0E, 0x1D, 0x1E, 0xB3, 0xDD, 0x7F, 0x61, 0x35, 0x3B, 0xF4, 0x88, 0x11, 0xFB, 0xBB, 0x6F, 0xA5,
      0x0D, 0xF5, 0x35, 0x7F, 0x38, 0xE8, 0x07, 0xE1, 0xC3, 0xC3, 0xFE, 0xF1, 0x52, 0xCB, 0xC6, 0xB2,
      0xC2, 0xB4, 0x67, 0x4F, 0x3D, 0x7D, 0x44, 0x39, 0xC8, 0xEE, 0xA0, 0xEF, 0x17, 0xB4, 0x00, 0xA2,
      0x02, 0xD2, 0x3E, 0x93, 0x39, 0x4A, 0xA2, 0xB2, 0x0F, 0x57, 0x7A, 0x06, 0x15, 0x28, 0xF1, 0xB8,
      0xD5, 0xC8, 0x53, 0xD0, 0x7F, 0x35, 0xA7, 0x53, 0xCB, 0x24, 0x37, 0x3E, 0xE0, 0x05, 0xC5, 0xC9
    };

    // Prime2 (q)
    keyset.Prime2 = {
      0xCA, 0x83, 0x67, 0x7F, 0xF3, 0x9E, 0x73, 0x47, 0xD9, 0x0F, 0x99, 0x55, 0xC5, 0x5A, 0x56, 0x57,
      0xC3, 0x54, 0x3B, 0xA9, 0x66, 0xBA, 0x86, 0x10, 0xE0, 0xB1, 0x2F, 0xC2, 0x96, 0xD5, 0xF1, 0xD1,
      0xD8, 0xCF, 0xF2, 0x7D, 0x03, 0xAE, 0xCE, 0xEC, 0xCC, 0x77, 0x06, 0x5F, 0x31, 0x99, 0x9E, 0x3A,
      0x84, 0x37, 0xB1, 0x86, 0x24, 0x13, 0x75, 0x75, 0x9E, 0xAA, 0x8C, 0x8D, 0x66, 0xCB, 0x5F, 0x4A,
      0xB7, 0xAD, 0x64, 0x18, 0x9C, 0x5C, 0x63, 0x4C, 0x7D, 0xB3, 0x73, 0x70, 0xE2, 0x82, 0x24, 0xE3,
      0x2E, 0xCB, 0xCA, 0x09, 0xB0, 0x8E, 0xDF, 0x64, 0xA9, 0x9E, 0x3E, 0x62, 0xD9, 0xB4, 0xA1, 0xA6,
      0xC7, 0x5E, 0xAC, 0x51, 0xB1, 0x82, 0xE3, 0xD5, 0x6D, 0xD0, 0x71, 0xE2, 0x38, 0xBD, 0x56, 0x41,
      0xD9, 0x9E, 0xCB, 0xE2, 0x91, 0xEB, 0x5F, 0x48, 0xFB, 0xFA, 0x53, 0x43, 0x06, 0xB8, 0x7D, 0x60,
      0xE4, 0x40, 0x1D, 0x18, 0x4B, 0xE0, 0x5A, 0x23, 0x69, 0xCF, 0x39, 0xE0, 0x59, 0xFB, 0x47, 0xC3,
      0xB5, 0x03, 0xF4, 0xAA, 0xA8, 0x82, 0xF3, 0x7D, 0x37, 0x61, 0xDE, 0xCE, 0x5E, 0xA7, 0x0D, 0x87,
      0x1E, 0x09, 0xB3, 0x76, 0xAA, 0x54, 0xEF, 0x33, 0xAA, 0xBD, 0xF2, 0x78, 0xED, 0x68, 0xB2, 0xE2,
      0x51, 0x66, 0x81, 0x07, 0x7C, 0xEE, 0x51, 0x6F, 0x2E, 0x7C, 0x59, 0x03, 0x35, 0x8E, 0x52, 0x69
    };

    // PrivateExponent (d)
    keyset.PrivateExponent = {
      0x8E, 0x04, 0xF3, 0xC5, 0x2C, 0x71, 0x85, 0x76, 0x5F, 0x85, 0x3C, 0x55, 0xE5, 0x29, 0x9C, 0xD4,
      0xA3, 0xCE, 0x14, 0xCB, 0xAA, 0xE4, 0x89, 0x01, 0x3A, 0xDF, 0xB9, 0x66, 0x98, 0x45, 0xDF, 0x09,
      0xAC, 0x41, 0x11, 0x50, 0x88, 0x0B, 0x71, 0xFD, 0x55, 0x52, 0xFC, 0xBC, 0x46, 0xFB, 0x44, 0x38,
      0x1E, 0x26, 0xE2, 0xE6, 0x29, 0x7A, 0x65, 0xEB, 0xA1, 0xCF, 0x1A, 0x48, 0x26, 0x69, 0x1E, 0xE9,
      0x6E, 0x07, 0xB3, 0x34, 0x1D, 0xD8, 0x6A, 0xB4, 0x6B, 0x51, 0xA7, 0x85, 0xC8, 0xC0, 0x82, 0xF5,
      0x93, 0xFF, 0x4B, 0x42, 0x17, 0xCA, 0x52, 0xA5, 0x8A, 0xD7, 0x33, 0x33, 0xC0, 0xD6, 0x27, 0xFD,
      0xA9, 0x92, 0x88, 0x85, 0x22, 0x92, 0x70, 0xC4, 0xA6, 0x49, 0xCD, 0xE9, 0x18, 0x60, 0x26, 0xC8,
      0xA5, 0x0A, 0x63, 0x6A, 0xCF, 0xC9, 0x1F, 0xCF, 0xB7, 0xCF, 0x4F, 0x8D, 0xB1, 0xC5, 0xE3, 0xAA,
      0x0C, 0x14, 0x02, 0x0A, 0xF1, 0xC9, 0x08, 0xFD, 0x51, 0xCF, 0x02, 0x22, 0x98, 0xA4, 0xE5, 0xCD,
      0x20, 0xEE, 0x57, 0x9B, 0x0A, 0x61, 0xBB, 0x58, 0xF6, 0x98, 0xD0, 0x5C, 0x41, 0x96, 0x8F, 0x8C,
      0x24, 0x04, 0xF2, 0xDA, 0x79, 0x64, 0xE2, 0x0C, 0xDB, 0x54, 0x65, 0x9E, 0xDF, 0x6E, 0xA0, 0xFE,
      0xFD, 0xC8, 0x23, 0x16, 0xF9, 0x58, 0xFD, 0x66, 0xBC, 0x40, 0xCA, 0x01, 0x81, 0xD7, 0x67, 0x90,
      0xF3, 0x28, 0xD2, 0x0E, 0xC9, 0x3B, 0xF5, 0xCA, 0xF6, 0xAB, 0xDD, 0xA3, 0xFF, 0x89, 0xFE, 0xA2,
      0x47, 0x43, 0x8A, 0xC8, 0x25, 0xAF, 0xD8, 0x82, 0x2E, 0x13, 0x89, 0x70, 0xFE, 0x8E, 0xFB, 0x19,
      0xDD, 0xD3, 0x73, 0xA5, 0xCE, 0xCB, 0xBF, 0xCC, 0x2E, 0x04, 0x79, 0x58, 0xFC, 0xD8, 0xE7, 0xAD,
      0x3A, 0x5A, 0x6C, 0x33, 0x9D, 0x98, 0xFB, 0x79, 0x47, 0xEA, 0x03, 0x4D, 0x72, 0x4B, 0x90, 0x36,
      0x48, 0x7A, 0x8E, 0x00, 0x69, 0x49, 0x1E, 0x1A, 0xD4, 0x97, 0xE1, 0xE8, 0x57, 0x95, 0x74, 0xE2,
      0x9E, 0xEF, 0xA6, 0x2A, 0xD2, 0x25, 0x1D, 0x83, 0xDA, 0xD7, 0x3A, 0x4F, 0x1A, 0xAA, 0xAC, 0xF7,
      0x1E, 0xDF, 0x35, 0x10, 0x55, 0x7D, 0x8D, 0xB4, 0x71, 0x4F, 0xD0, 0x5D, 0x63, 0xDC, 0x74, 0xEA,
      0xE3, 0x62, 0x1D, 0x2B, 0x04, 0x06, 0xC5, 0x12, 0x6F, 0xC7, 0xD6, 0xA1, 0x0B, 0x99, 0x56, 0x38,
      0x9C, 0x75, 0x56, 0xCB, 0xDA, 0x51, 0xC4, 0x4B, 0x5D, 0xAC, 0x87, 0xBB, 0x97, 0xD6, 0x46, 0x8D,
      0xA7, 0x1E, 0x27, 0xD5, 0x83, 0x2E, 0xFA, 0x96, 0x00, 0x48, 0xD0, 0x53, 0xA4, 0x00, 0xC3, 0xAC,
      0xFE, 0x2A, 0xBA, 0x68, 0xA3, 0xA1, 0xAF, 0x4F, 0x43, 0x7E, 0xA1, 0xAB, 0xBC, 0x31, 0xCD, 0x79,
      0xA5, 0x14, 0x70, 0x7D, 0x61, 0x80, 0xBF, 0xFD, 0x58, 0xDA, 0x7C, 0x2A, 0x44, 0xAB, 0xBF, 0x41
    };

    // Exponent1 (d mod (p-1))
    keyset.Exponent1 = {
      0x07, 0x78, 0x1F, 0x0A, 0xC1, 0x5C, 0x11, 0x3A, 0xDB, 0x03, 0x65, 0xBB, 0xD9, 0xD8, 0x78, 0xA0,
      0x63, 0x81, 0x47, 0x81, 0xF4, 0x43, 0xDD, 0xFE, 0x9E, 0xA3, 0xE2, 0x95, 0x85, 0x04, 0xDE, 0xEB,
      0xE8, 0xEA, 0x75, 0x72, 0x1E, 0xDB, 0xC1, 0x90, 0xB2, 0xD1, 0x5F, 0xEA, 0x85, 0xB1, 0x96, 0xF6,
      0xB3, 0xDE, 0xFD, 0xE0, 0x9C, 0x55, 0xD1, 0x92, 0x44, 0x4A, 0x60, 0x3E, 0x42, 0xC6, 0x29, 0x9E,
      0x26, 0x8B, 0xF0, 0xD4, 0x52, 0x39, 0x8F, 0xC1, 0x2A, 0x17, 0xED, 0x99, 0x51, 0x5B, 0xC2, 0xAF,
      0x19, 0x40, 0x1F, 0x4B, 0x25, 0xF4, 0xAA, 0x1A, 0x1A, 0x15, 0x5C, 0x86, 0x31, 0xAA, 0x38, 0x82,
      0xC5, 0x17, 0x46, 0x50, 0x85, 0xB1, 0x9E, 0xBF, 0xFB, 0x08, 0x90, 0x8E, 0x1A, 0xD0, 0xAA, 0xEE,
      0x7A, 0x0B, 0x49, 0x5F, 0x1E, 0x9B, 0xE2, 0x68, 0x6B, 0x2C, 0x93, 0x72, 0x43, 0x86, 0x02, 0x61,
      0xE9, 0xAC, 0x78, 0xEF, 0x6E, 0xB0, 0x9C, 0x6D, 0x10, 0x4C, 0x79, 0x46, 0x2D, 0xFC, 0xB9, 0x5C,
      0xBC, 0xDA, 0x6B, 0xE2, 0xD1, 0x95, 0xBC, 0xC0, 0x5E, 0x0E, 0xD7, 0x61, 0xCA, 0x28, 0xBE, 0x08,
      0xDA, 0x1E, 0x16, 0x69, 0x11, 0x06, 0x61, 0xBD, 0xD2, 0x47, 0xCB, 0xFF, 0xDF, 0xC5, 0x2D, 0x2B,
      0x9B, 0xBE, 0x32, 0x1E, 0xB5, 0xF5, 0xCD, 0x54, 0x58, 0x64, 0x64, 0xBF, 0xF8, 0x0E, 0x5A, 0xF9
    };

    // Exponent2 (d mod (q-1))
    keyset.Exponent2 = {
      0x3C, 0x99, 0x63, 0xB0, 0x43, 0x1B, 0x48, 0x0D, 0xD8, 0xE3, 0x35, 0x14, 0x18, 0x71, 0x36, 0xE3,
      0x1E, 0x3D, 0x27, 0x79, 0x42, 0x97, 0x50, 0x24, 0xDE, 0xC7, 0xC6, 0xAD, 0xE8, 0xEA, 0xEE, 0x68,
      0xC8, 0x03, 0x39, 0xE1, 0xB4, 0xE7, 0x6B, 0x5E, 0x2A, 0xB4, 0xF7, 0x40, 0x27, 0x1C, 0x7B, 0xDF,
      0xB0, 0xCE, 0xE5, 0x9D, 0x69, 0x50, 0x35, 0x56, 0xD3, 0xFA, 0xDF, 0x02, 0x35, 0x1F, 0x68, 0x4D,
      0x78, 0x77, 0x37, 0x3B, 0xB2, 0x16, 0x67, 0x54, 0x6D, 0x4C, 0xF4, 0x9F, 0x73, 0xF8, 0x53, 0xC7,
      0x73, 0xAA, 0x61, 0xB3, 0xD2, 0x94, 0x7E, 0x3E, 0xA6, 0x0F, 0x07, 0x46, 0x17, 0x35, 0x59, 0x26,
      0x0A, 0x04, 0xC7, 0x75, 0xCE, 0xB3, 0x87, 0x2F, 0xC7, 0xA3, 0x97, 0x60, 0x85, 0x70, 0x0A, 0xCE,
      0xBB, 0xAB, 0x2C, 0x01, 0x89, 0x7E, 0xB0, 0x4D, 0xAB, 0xB1, 0x35, 0x97, 0x19, 0xFC, 0xBC, 0xEF,
      0xF0, 0x7D, 0x4A, 0xF7, 0x89, 0x45, 0x02, 0x54, 0x14, 0x86, 0x81, 0x20, 0x24, 0x6C, 0xF0, 0x05,
      0x9D, 0x36, 0x28, 0xD1, 0xA4, 0x89, 0x43, 0x09, 0x56, 0x38, 0x40, 0x2E, 0xEA, 0xDD, 0xFC, 0x4B,
      0x51, 0x6E, 0xBF, 0xB8, 0x23, 0xB2, 0x34, 0xBD, 0xF6, 0x3A, 0xCE, 0xC2, 0xE6, 0xEF, 0xEC, 0x8F,
      0x92, 0xA2, 0x24, 0xBC, 0x33, 0xE3, 0x30, 0x95, 0x1F, 0x88, 0xF0, 0x2D, 0xE8, 0xA9, 0xC4, 0xF9
    };

    // Coefficient (InverseQ)
    keyset.Coefficient = {
      0x5C, 0x50, 0xEF, 0x23, 0x14, 0xDB, 0xE1, 0xCF, 0x19, 0x66, 0x8A, 0x93, 0x4D, 0xDC, 0xE7, 0x62,
      0x34, 0x72, 0xA5, 0x2F, 0xFD, 0xA7, 0x69, 0x00, 0xCE, 0x05, 0x6C, 0x9A, 0x7A, 0x40, 0x5A, 0x55,
      0x9D, 0x81, 0x4E, 0x49, 0xFC, 0xF3, 0x72, 0x36, 0x18, 0x62, 0x7A, 0x54, 0x68, 0x36, 0x3D, 0x90,
      0x8E, 0xF4, 0xEE, 0x26, 0x33, 0x14, 0x66, 0x36, 0x6A, 0x1E, 0x66, 0x2D, 0x5B, 0x25, 0x52, 0x10,
      0x5D, 0x85, 0x21, 0x11, 0xB9, 0x91, 0xDE, 0x79, 0x10, 0xE2, 0x9A, 0x25, 0xAF, 0x3B, 0x14, 0x2C,
      0x30, 0xDF, 0x3C, 0x5B, 0x8D, 0xFF, 0xE8, 0x9C, 0x35, 0x96, 0xC6, 0xF5, 0x63, 0x09, 0xE8, 0x41,
      0x9E, 0xD9, 0x61, 0x55, 0x94, 0x98, 0x2F, 0xD9, 0x86, 0x05, 0x32, 0x01, 0x23, 0x86, 0x74, 0xDC,
      0x12, 0x4A, 0xF9, 0xD5, 0xB4, 0xFD, 0xA5, 0x9E, 0x6D, 0x28, 0xAE, 0x02, 0xDB, 0xEC, 0xE0, 0xCF,
      0xB2, 0xC3, 0xAC, 0x6C, 0xBE, 0xEE, 0x64, 0x20, 0x63, 0xB4, 0x8E, 0xA7, 0xF0, 0x69, 0x96, 0xBD,
      0xEC, 0x4D, 0xA7, 0xF8, 0x16, 0x14, 0x3C, 0xDA, 0x67, 0x69, 0xFC, 0xB5, 0x84, 0x47, 0x10, 0x71,
      0xAC, 0x64, 0x24, 0xBD, 0x94, 0x3E, 0x8A, 0xE3, 0xDF, 0xB4, 0xA9, 0x54, 0x73, 0x1E, 0x4C, 0xD3,
      0xB8, 0xF9, 0x08, 0xCC, 0x1D, 0x85, 0x3B, 0xC1, 0xCC, 0x0A, 0xCF, 0x47, 0xBB, 0xAD, 0x6B, 0x7B
    };

    // Modulus (n)
    keyset.Modulus = {
      0xAB, 0x1D, 0xBD, 0x43, 0x39, 0x49, 0x33, 0x16, 0xA3, 0x5C, 0x40, 0x4E, 0x2C, 0x22, 0x97, 0xB8,
      0x33, 0x68, 0x5C, 0x1A, 0xD3, 0x54, 0xE8, 0xC5, 0xBA, 0x78, 0x88, 0xD1, 0xB0, 0xFA, 0xF2, 0x5A,
      0x8F, 0x14, 0xAA, 0x06, 0x52, 0x8F, 0xA4, 0x65, 0x86, 0x6E, 0xD4, 0x23, 0x03, 0xD3, 0x00, 0x91,
      0x0B, 0xD9, 0xD8, 0x41, 0x01, 0xFE, 0x54, 0xC1, 0x2B, 0xFC, 0x4F, 0x7F, 0x9C, 0x3A, 0x7A, 0xC9,
      0x13, 0x33, 0xFD, 0x2C, 0xDC, 0xCB, 0x14, 0x00, 0x76, 0x1A, 0xDE, 0x5C, 0x2E, 0xBC, 0xA0, 0x11,
      0x6D, 0x8C, 0x30, 0x4B, 0x8B, 0x47, 0xF3, 0x3C, 0x41, 0x37, 0x72, 0x84, 0x9E, 0x9E, 0x1D, 0x18,
      0x3B, 0x4D, 0x7B, 0xBC, 0x99, 0x4C, 0x37, 0xED, 0x78, 0x87, 0xD4, 0x86, 0x94, 0x23, 0x4B, 0x71,
      0xAC, 0xCB, 0x4D, 0xB9, 0x50, 0x70, 0x33, 0x66, 0x18, 0x97, 0x6E, 0xD6, 0x7B, 0x1C, 0x40, 0x1A,
      0x21, 0x13, 0xD4, 0x39, 0x88, 0x03, 0x40, 0x49, 0x9F, 0x65, 0x6B, 0x7A, 0xEE, 0xB3, 0x86, 0xC0,
      0x67, 0x98, 0xC2, 0xD1, 0x44, 0xEB, 0xB5, 0x84, 0xB5, 0x65, 0x7B, 0x28, 0xE2, 0x90, 0x94, 0x49,
      0x31, 0x79, 0x9B, 0x0B, 0x09, 0xB2, 0x71, 0xA1, 0xD9, 0x37, 0x0B, 0xFE, 0x4F, 0x84, 0xBA, 0xCC,
      0x78, 0xEA, 0x3C, 0x91, 0x7D, 0x30, 0x0D, 0x53, 0xD5, 0xC5, 0x6A, 0x34, 0x0B, 0x2B, 0x07, 0x56,
      0x08, 0x0F, 0x28, 0x32, 0x53, 0x63, 0xEB, 0x9B, 0xC8, 0x4E, 0xB9, 0x1D, 0x70, 0x46, 0x8E, 0xEF,
      0x8B, 0xD4, 0xAB, 0x30, 0x2F, 0x13, 0xF3, 0x00, 0x41, 0x70, 0x95, 0x79, 0xCA, 0xA5, 0x4E, 0x8B,
      0xD7, 0x64, 0x23, 0x56, 0xEC, 0x85, 0x23, 0x0A, 0x15, 0x14, 0xE0, 0x06, 0x67, 0x56, 0x84, 0x23,
      0x08, 0x1D, 0x64, 0x39, 0x96, 0x88, 0x33, 0xA5, 0x1C, 0x5B, 0x2F, 0xC7, 0xB6, 0xEF, 0x00, 0x62,
      0x3F, 0xB7, 0x25, 0x89, 0x9A, 0x29, 0x67, 0xCB, 0xC1, 0x4C, 0xEE, 0xAE, 0xFE, 0x87, 0x47, 0x28,
      0x02, 0x95, 0xA3, 0x1C, 0x90, 0x89, 0x59, 0xB3, 0x7E, 0xCE, 0xB0, 0x06, 0x41, 0x82, 0xC5, 0x33,
      0x66, 0x4D, 0xED, 0x63, 0x55, 0xFF, 0x31, 0x3C, 0xF8, 0x2A, 0x89, 0x1A, 0x42, 0xDC, 0x88, 0x65,
      0x5F, 0xDD, 0xFE, 0x71, 0xE6, 0x50, 0xE5, 0x1B, 0x14, 0x90, 0xA8, 0x88, 0xCE, 0x38, 0xD6, 0xFB,
      0x85, 0x0E, 0x20, 0xD1, 0x24, 0x08, 0xCD, 0xB0, 0xF0, 0xEF, 0xAB, 0x2F, 0xF1, 0x9F, 0x9A, 0x95,
      0x80, 0x2D, 0x43, 0x75, 0x60, 0xC0, 0xC9, 0x86, 0xC5, 0xF2, 0xCB, 0xB2, 0x0E, 0x2B, 0x89, 0x7F,
      0x6B, 0xCB, 0x67, 0xA5, 0x65, 0x7B, 0x47, 0x24, 0xDB, 0xDA, 0x2C, 0xB3, 0x8F, 0xE2, 0x3D, 0x73,
      0x8C, 0xF2, 0x6F, 0x8C, 0xC0, 0x6E, 0x0F, 0x12, 0x21, 0xFE, 0x74, 0x0D, 0x0E, 0x36, 0x81, 0x71
    };

    // PublicExponent (e)
    keyset.PublicExponent = { 0x00, 0x01, 0x00, 0x01 };

    return keyset;
  }
};

// ---------------------------------------------------------------------
// PS5 PKG structures
// ---------------------------------------------------------------------
#pragma pack(push, 1)
struct PKG_HEADER_PS5 {
  uint32_t magic;                   // 0x00: 0x7F464948 ("FIH")
  uint32_t type;                    // 0x04: Package type
  uint32_t unk_0x08;                // 0x08
  uint32_t unk_0x0C;                // 0x0C
  uint16_t unk1_entries_num;        // 0x10
  uint16_t table_entries_num;       // 0x12: Number of file table entries
  uint16_t system_entries_num;      // 0x14
  uint16_t unk2_entries_num;        // 0x16
  uint32_t file_table_offset;       // 0x18: Offset to file table
  uint32_t main_entries_data_size;  // 0x1C
  uint32_t unk_0x20;                // 0x20
  uint32_t body_offset;             // 0x24: Offset to body data
  uint32_t unk_0x28;                // 0x28
  uint32_t body_size;               // 0x2C: Size of body
  uint8_t  unk_0x30[0x10];          // 0x30-0x3F
  uint8_t  content_id[0x30];        // 0x40-0x6F: Content ID (null-terminated string)
  uint8_t  unk_remaining[0x2510];   // 0x70-0x257F: Padding/unknown data
  // Note: RSA encrypted data starts at 0x2580
};

struct PKG_TABLE_ENTRY_PS5 {
  uint32_t type;       // Entry type/ID
  uint32_t unk1;       // Unknown
  uint32_t flags1;     // Flags (bit 31 = encrypted flag)
  uint32_t flags2;     // Flags (bits 12-15 = key index)
  uint32_t offset;     // File offset
  uint32_t size;       // File size
  uint8_t  padding[8]; // Padding
};
#pragma pack(pop)

// ---------------------------------------------------------------------
// PS5 PKG Handler Class
// ---------------------------------------------------------------------
class PS5PKGHandler {
private:
  PKG_HEADER_PS5 header = {};
  RSAKeyset keyset;

  uint32_t SwapEndian32(uint32_t v) { return _byteswap_ulong(v); }
  uint16_t SwapEndian16(uint16_t v) { return _byteswap_ushort(v); }

  // RSA 2048 Decrypt using Windows BCrypt API
// FIXED RSA2048Decrypt with proper BCrypt key blob layout
  std::vector<uint8_t> RSA2048Decrypt(const uint8_t* ciphertext, size_t len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    std::vector<uint8_t> result;

    wchar_t debugMsg[256];
    swprintf_s(debugMsg, L"RSA2048Decrypt: Input length = %zu bytes", len);
    logDebug(debugMsg);

    // Open RSA algorithm provider
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (status != 0) {
      swprintf_s(debugMsg, L"RSA2048Decrypt: BCryptOpenAlgorithmProvider failed with 0x%08X", status);
      logDebug(debugMsg);
      return result;
    }

    logDebug(L"RSA2048Decrypt: Algorithm provider opened");

    // CRITICAL FIX: BCrypt expects this specific layout:
    // BCRYPT_RSAKEY_BLOB | PublicExponent | Modulus | Prime1 | Prime2 | Exponent1 | Exponent2 | Coefficient | PrivateExponent

    DWORD blobSize = sizeof(BCRYPT_RSAKEY_BLOB) +
      keyset.PublicExponent.size() +   // e
      keyset.Modulus.size() +          // n
      keyset.Prime1.size() +           // p
      keyset.Prime2.size() +           // q
      keyset.Exponent1.size() +        // dp (d mod p-1)
      keyset.Exponent2.size() +        // dq (d mod q-1)
      keyset.Coefficient.size() +      // qinv
      keyset.PrivateExponent.size();   // d

    std::vector<uint8_t> blobData(blobSize);
    BCRYPT_RSAKEY_BLOB* keyBlob = (BCRYPT_RSAKEY_BLOB*)blobData.data();

    keyBlob->Magic = BCRYPT_RSAFULLPRIVATE_MAGIC;
    keyBlob->BitLength = 2048;
    keyBlob->cbPublicExp = (ULONG)keyset.PublicExponent.size();
    keyBlob->cbModulus = (ULONG)keyset.Modulus.size();
    keyBlob->cbPrime1 = (ULONG)keyset.Prime1.size();
    keyBlob->cbPrime2 = (ULONG)keyset.Prime2.size();

    // Append key components in the correct order
    uint8_t* pBlob = blobData.data() + sizeof(BCRYPT_RSAKEY_BLOB);

    memcpy(pBlob, keyset.PublicExponent.data(), keyset.PublicExponent.size());
    pBlob += keyset.PublicExponent.size();

    memcpy(pBlob, keyset.Modulus.data(), keyset.Modulus.size());
    pBlob += keyset.Modulus.size();

    memcpy(pBlob, keyset.Prime1.data(), keyset.Prime1.size());
    pBlob += keyset.Prime1.size();

    memcpy(pBlob, keyset.Prime2.data(), keyset.Prime2.size());
    pBlob += keyset.Prime2.size();

    // ADDED: These were missing!
    memcpy(pBlob, keyset.Exponent1.data(), keyset.Exponent1.size());
    pBlob += keyset.Exponent1.size();

    memcpy(pBlob, keyset.Exponent2.data(), keyset.Exponent2.size());
    pBlob += keyset.Exponent2.size();

    memcpy(pBlob, keyset.Coefficient.data(), keyset.Coefficient.size());
    pBlob += keyset.Coefficient.size();

    memcpy(pBlob, keyset.PrivateExponent.data(), keyset.PrivateExponent.size());

    swprintf_s(debugMsg, L"RSA2048Decrypt: Key blob size = %lu bytes (e:%u n:%u p:%u q:%u)",
      blobSize,
      keyBlob->cbPublicExp, keyBlob->cbModulus, keyBlob->cbPrime1, keyBlob->cbPrime2);
    logDebug(debugMsg);

    // Import key
    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAFULLPRIVATE_BLOB,
      &hKey, blobData.data(), blobSize, 0);
    if (status != 0) {
      swprintf_s(debugMsg, L"RSA2048Decrypt: BCryptImportKeyPair failed with 0x%08X", status);
      logDebug(debugMsg);
      BCryptCloseAlgorithmProvider(hAlg, 0);
      return result;
    }

    logDebug(L"RSA2048Decrypt: Key imported successfully");

    // Decrypt - RSA 2048 outputs 256 bytes
    ULONG decryptedSize = 0;
    result.resize(256);

    status = BCryptDecrypt(hKey, (PUCHAR)ciphertext, (ULONG)len, NULL,
      NULL, 0, result.data(), (ULONG)result.size(),
      &decryptedSize, BCRYPT_PAD_PKCS1);

    if (status == 0) {
      result.resize(decryptedSize);
      swprintf_s(debugMsg, L"RSA2048Decrypt: SUCCESS - decrypted %lu bytes", decryptedSize);
      logDebug(debugMsg);
    }
    else {
      swprintf_s(debugMsg, L"RSA2048Decrypt: BCryptDecrypt failed with 0x%08X", status);
      logDebug(debugMsg);
      result.clear();
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return result;
  }
  // AES CBC Decrypt
  bool AesCbcDecrypt(uint8_t* output, const uint8_t* input, uint32_t size,
    const uint8_t* key, const uint8_t* iv) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
      return false;

    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
      (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
      sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) {
      BCryptCloseAlgorithmProvider(hAlg, 0);
      return false;
    }

    ULONG keyObjSize = 0, dataSize = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjSize,
      sizeof(keyObjSize), &dataSize, 0);

    std::vector<uint8_t> keyObj(keyObjSize);

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjSize,
      (PUCHAR)key, 16, 0) != 0) {
      BCryptCloseAlgorithmProvider(hAlg, 0);
      return false;
    }

    std::vector<uint8_t> ivCopy(iv, iv + 16);
    ULONG bytesDecrypted = 0;

    NTSTATUS status = BCryptDecrypt(hKey, (PUCHAR)input, size, NULL,
      ivCopy.data(), 16, output, size,
      &bytesDecrypted, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return (status == 0);
  }
public:
  struct FileInfo {
    uint64_t  offset = 0;
    uint64_t  size = 0;
    uint32_t  flags1 = 0;
    uint32_t  flags2 = 0;
    uint32_t  type = 0;
    uint32_t  keyIndex = 0;
    bool      isEncrypted = false;
    std::string path;
  };

  PS5PKGHandler() {
    keyset = RSAKeyset::GetPkgDerivedKey3Keyset();
  }

  HRESULT ParseHeader(IInStream* stream) {
    RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));
    UInt32 read = 0;

    // Read and validate magic
    RINOK(stream->Read(&header.magic, 4, &read));
    header.magic = SwapEndian32(header.magic);

    if (header.magic != PKG_MAGIC_PS5) {
      // Log the actual magic for debugging
      wchar_t debugMsg[128];
      swprintf_s(debugMsg, L"PS5 ParseHeader: Invalid magic 0x%08X (expected 0x%08X)",
        header.magic, PKG_MAGIC_PS5);
      logDebug(debugMsg);
      return E_FAIL;
    }

    logDebug(L"PS5 ParseHeader: Magic validated successfully");

    // Read rest of header fields
    RINOK(stream->Read(&header.type, 4, &read));
    header.type = SwapEndian32(header.type);

    RINOK(stream->Read(&header.unk_0x08, 4, &read));
    header.unk_0x08 = SwapEndian32(header.unk_0x08);

    RINOK(stream->Read(&header.unk_0x0C, 4, &read));
    header.unk_0x0C = SwapEndian32(header.unk_0x0C);

    RINOK(stream->Read(&header.unk1_entries_num, 2, &read));
    header.unk1_entries_num = SwapEndian16(header.unk1_entries_num);

    RINOK(stream->Read(&header.table_entries_num, 2, &read));
    header.table_entries_num = SwapEndian16(header.table_entries_num);

    RINOK(stream->Read(&header.system_entries_num, 2, &read));
    header.system_entries_num = SwapEndian16(header.system_entries_num);

    RINOK(stream->Read(&header.unk2_entries_num, 2, &read));
    header.unk2_entries_num = SwapEndian16(header.unk2_entries_num);

    RINOK(stream->Read(&header.file_table_offset, 4, &read));
    header.file_table_offset = SwapEndian32(header.file_table_offset);

    RINOK(stream->Read(&header.main_entries_data_size, 4, &read));
    header.main_entries_data_size = SwapEndian32(header.main_entries_data_size);

    RINOK(stream->Read(&header.unk_0x20, 4, &read));
    header.unk_0x20 = SwapEndian32(header.unk_0x20);

    RINOK(stream->Read(&header.body_offset, 4, &read));
    header.body_offset = SwapEndian32(header.body_offset);

    RINOK(stream->Read(&header.unk_0x28, 4, &read));
    header.unk_0x28 = SwapEndian32(header.unk_0x28);

    RINOK(stream->Read(&header.body_size, 4, &read));
    header.body_size = SwapEndian32(header.body_size);

    RINOK(stream->Read(header.unk_0x30, 0x10, nullptr));
    RINOK(stream->Read(header.content_id, 0x30, nullptr));
    header.content_id[0x2F] = '\0';

    // Log parsed header info
    wchar_t debugMsg[256];
    swprintf_s(debugMsg, L"PS5 Header: type=0x%X, entries=%d, table_offset=0x%X, body_offset=0x%X",
      header.type, header.table_entries_num, header.file_table_offset, header.body_offset);
    logDebug(debugMsg);

    // Validate critical fields
    if (header.table_entries_num == 0 || header.table_entries_num > 10000) {
      logDebug(L"PS5 ParseHeader: Invalid entry count");
      return E_FAIL;
    }

    if (header.file_table_offset == 0 || header.file_table_offset > 0x10000000) {
      logDebug(L"PS5 ParseHeader: Invalid file table offset");
      return E_FAIL;
    }

    logDebug(L"PS5 ParseHeader: SUCCESS");
    return S_OK;
  }

  HRESULT ScanForRSAData(IInStream* stream) {
    logDebug(L"=== SCANNING FOR RSA ENCRYPTED DATA ===");

    wchar_t debugMsg[512];

    // Scan first 64KB of file for non-zero blocks
    const size_t SCAN_SIZE = 65536;
    const size_t BLOCK_SIZE = 0x180;
    std::vector<uint8_t> scanBuffer(SCAN_SIZE);

    RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));
    UInt32 read = 0;
    RINOK(stream->Read(scanBuffer.data(), SCAN_SIZE, &read));

    swprintf_s(debugMsg, L"Scanning first %zu bytes for non-zero 0x180-byte blocks...", read);
    logDebug(debugMsg);

    std::vector<uint64_t> candidateOffsets;

    for (size_t offset = 0; offset < read - BLOCK_SIZE; offset += 16) {
      // Check if this block has significant non-zero data
      int nonZeroCount = 0;
      for (size_t i = 0; i < BLOCK_SIZE && (offset + i) < read; i++) {
        if (scanBuffer[offset + i] != 0) {
          nonZeroCount++;
        }
      }

      // If block is mostly non-zero (>50% non-zero bytes)
      if (nonZeroCount > (BLOCK_SIZE / 2)) {
        candidateOffsets.push_back(offset);

        // Show first few candidates in detail
        if (candidateOffsets.size() <= 5) {
          swprintf_s(debugMsg,
            L"  Candidate at 0x%04zX (%d%% non-zero): %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
            offset,
            (nonZeroCount * 100) / BLOCK_SIZE,
            scanBuffer[offset + 0], scanBuffer[offset + 1], scanBuffer[offset + 2], scanBuffer[offset + 3],
            scanBuffer[offset + 4], scanBuffer[offset + 5], scanBuffer[offset + 6], scanBuffer[offset + 7],
            scanBuffer[offset + 8], scanBuffer[offset + 9], scanBuffer[offset + 10], scanBuffer[offset + 11],
            scanBuffer[offset + 12], scanBuffer[offset + 13], scanBuffer[offset + 14], scanBuffer[offset + 15]);
          logDebug(debugMsg);
        }
      }
    }

    swprintf_s(debugMsg, L"Found %zu potential RSA data blocks", candidateOffsets.size());
    logDebug(debugMsg);

    // Dump header region for inspection
    logDebug(L"=== HEADER REGION DUMP (0x0000 - 0x0100) ===");
    for (int line = 0; line < 16; line++) {
      swprintf_s(debugMsg,
        L"0x%04X: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
        line * 16,
        scanBuffer[line * 16 + 0], scanBuffer[line * 16 + 1], scanBuffer[line * 16 + 2], scanBuffer[line * 16 + 3],
        scanBuffer[line * 16 + 4], scanBuffer[line * 16 + 5], scanBuffer[line * 16 + 6], scanBuffer[line * 16 + 7],
        scanBuffer[line * 16 + 8], scanBuffer[line * 16 + 9], scanBuffer[line * 16 + 10], scanBuffer[line * 16 + 11],
        scanBuffer[line * 16 + 12], scanBuffer[line * 16 + 13], scanBuffer[line * 16 + 14], scanBuffer[line * 16 + 15]);
      logDebug(debugMsg);
    }

    // Dump region around 0x2580 (expected RSA location)
    logDebug(L"=== REGION AROUND 0x2580 (Expected RSA Data) ===");
    for (int line = 0; line < 16; line++) {
      size_t offset = 0x2580 + (line * 16);
      if (offset < read) {
        swprintf_s(debugMsg,
          L"0x%04zX: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
          offset,
          scanBuffer[offset + 0], scanBuffer[offset + 1], scanBuffer[offset + 2], scanBuffer[offset + 3],
          scanBuffer[offset + 4], scanBuffer[offset + 5], scanBuffer[offset + 6], scanBuffer[offset + 7],
          scanBuffer[offset + 8], scanBuffer[offset + 9], scanBuffer[offset + 10], scanBuffer[offset + 11],
          scanBuffer[offset + 12], scanBuffer[offset + 13], scanBuffer[offset + 14], scanBuffer[offset + 15]);
        logDebug(debugMsg);
      }
    }

    // Dump file table region
    logDebug(L"=== FILE TABLE REGION (0xBC96) ===");
    for (int line = 0; line < 16; line++) {
      size_t offset = 0xBC96 + (line * 16);
      if (offset < read) {
        swprintf_s(debugMsg,
          L"0x%04zX: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
          offset,
          scanBuffer[offset + 0], scanBuffer[offset + 1], scanBuffer[offset + 2], scanBuffer[offset + 3],
          scanBuffer[offset + 4], scanBuffer[offset + 5], scanBuffer[offset + 6], scanBuffer[offset + 7],
          scanBuffer[offset + 8], scanBuffer[offset + 9], scanBuffer[offset + 10], scanBuffer[offset + 11],
          scanBuffer[offset + 12], scanBuffer[offset + 13], scanBuffer[offset + 14], scanBuffer[offset + 15]);
        logDebug(debugMsg);
      }
    }

    logDebug(L"=== END SCAN ===");

    return S_OK;
  }

  // Complete ParseFileTable function
  HRESULT ParseFileTable(IInStream* stream, std::vector<FileInfo>& items,
    std::vector<uint8_t>& rsaDecryptedDataOut) {

    // DIAGNOSTIC: Scan for RSA data first
    RINOK(ScanForRSAData(stream));

    logDebug(L"PS5 ParseFileTable: Starting RSA decryption...");

    wchar_t debugMsg[256];

    const size_t RSA_DATA_SIZE = 0x180;

    // Try multiple possible RSA data locations
    std::vector<uint64_t> possibleOffsets = {
      0x2580,                    // Primary location (matches C# reference)
      0x2700,                    // Alternative location
      sizeof(PKG_HEADER_PS5),    // Right after header
      0x3000,                    // Another possibility
      (uint64_t)header.file_table_offset - RSA_DATA_SIZE  // Before file table
    };

    std::vector<uint8_t> encryptedData(RSA_DATA_SIZE);
    std::vector<uint8_t> decryptedRsaData;
    bool foundValidData = false;
    uint64_t usedOffset = 0;

    // Try each possible offset
    for (uint64_t offset : possibleOffsets) {
      RINOK(stream->Seek(offset, STREAM_SEEK_SET, nullptr));

      UInt32 read = 0;
      RINOK(stream->Read(encryptedData.data(), RSA_DATA_SIZE, &read));

      if (read != RSA_DATA_SIZE) {
        continue;
      }

      // Check if data is not all zeros
      bool hasNonZero = false;
      for (size_t i = 0; i < 16; i++) {
        if (encryptedData[i] != 0) {
          hasNonZero = true;
          break;
        }
      }

      if (!hasNonZero) {
        swprintf_s(debugMsg, L"PS5 ParseFileTable: Offset 0x%llX has all zeros, skipping", offset);
        logDebug(debugMsg);
        continue;
      }

      swprintf_s(debugMsg, L"PS5 ParseFileTable: Trying RSA data at offset 0x%llX: %02X %02X %02X %02X %02X %02X %02X %02X...",
        offset,
        encryptedData[0], encryptedData[1], encryptedData[2], encryptedData[3],
        encryptedData[4], encryptedData[5], encryptedData[6], encryptedData[7]);
      logDebug(debugMsg);

      // FIXED: Pass correct size to RSA decrypt
      decryptedRsaData = RSA2048Decrypt(encryptedData.data(), RSA_DATA_SIZE);

      if (!decryptedRsaData.empty() && decryptedRsaData.size() >= 0x20) {
        foundValidData = true;
        usedOffset = offset;
        swprintf_s(debugMsg, L"PS5 ParseFileTable: Successfully decrypted RSA data from offset 0x%llX", offset);
        logDebug(debugMsg);
        break;
      }
    }

    if (!foundValidData) {
      logDebug(L"PS5 ParseFileTable: ERROR - Could not find valid RSA encrypted data");
      logDebug(L"PS5 ParseFileTable: This PKG may use a different encryption scheme or be corrupted");
      return E_FAIL;  // Return error instead of continuing with dummy data
    }

    // Log decrypted data for verification
    swprintf_s(debugMsg, L"PS5 ParseFileTable: RSA output (%zu bytes): %02X %02X %02X %02X %02X %02X %02X %02X...",
      decryptedRsaData.size(),
      decryptedRsaData[0], decryptedRsaData[1], decryptedRsaData[2], decryptedRsaData[3],
      decryptedRsaData[4], decryptedRsaData[5], decryptedRsaData[6], decryptedRsaData[7]);
    logDebug(debugMsg);

    // Store first 0x20 bytes for later use
    rsaDecryptedDataOut.resize(0x20);
    memcpy(rsaDecryptedDataOut.data(), decryptedRsaData.data(), 0x20);

    // CRITICAL FIX: Re-read entry count and table offset from header
    uint32_t actual_entry_count = 0;
    uint32_t actual_file_table_offset = 0;

    RINOK(stream->Seek(0x10, STREAM_SEEK_SET, nullptr));
    UInt32 read = 0;
    RINOK(stream->Read(&actual_entry_count, 4, &read));
    actual_entry_count = SwapEndian32(actual_entry_count);

    RINOK(stream->Seek(0x18, STREAM_SEEK_SET, nullptr));
    RINOK(stream->Read(&actual_file_table_offset, 4, &read));
    actual_file_table_offset = SwapEndian32(actual_file_table_offset);

    swprintf_s(debugMsg, L"PS5 ParseFileTable: Re-read from header - entry_count=%u, table_offset=0x%X",
      actual_entry_count, actual_file_table_offset);
    logDebug(debugMsg);

    // Use the values from header if they seem more valid
    uint32_t entries_to_use = (actual_entry_count > 0 && actual_entry_count < 10000) ?
      actual_entry_count : header.table_entries_num;
    uint32_t offset_to_use = (actual_file_table_offset > 0 && actual_file_table_offset < 0x10000000) ?
      actual_file_table_offset : header.file_table_offset;

    swprintf_s(debugMsg, L"PS5 ParseFileTable: Using entry_count=%u, table_offset=0x%X",
      entries_to_use, offset_to_use);
    logDebug(debugMsg);

    // Parse file table
    logDebug(L"PS5 ParseFileTable: Reading file table...");
    RINOK(stream->Seek(offset_to_use, STREAM_SEEK_SET, nullptr));

    // Read first 64 bytes of file table for inspection
    std::vector<uint8_t> tablePreview(64);
    UInt32 previewRead = 0;
    stream->Read(tablePreview.data(), 64, &previewRead);

    swprintf_s(debugMsg, L"PS5 FileTable preview at 0x%X:", offset_to_use);
    logDebug(debugMsg);

    for (int line = 0; line < 4; line++) {
      swprintf_s(debugMsg, L"  [+0x%02X]: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
        line * 16,
        tablePreview[line * 16 + 0], tablePreview[line * 16 + 1], tablePreview[line * 16 + 2], tablePreview[line * 16 + 3],
        tablePreview[line * 16 + 4], tablePreview[line * 16 + 5], tablePreview[line * 16 + 6], tablePreview[line * 16 + 7],
        tablePreview[line * 16 + 8], tablePreview[line * 16 + 9], tablePreview[line * 16 + 10], tablePreview[line * 16 + 11],
        tablePreview[line * 16 + 12], tablePreview[line * 16 + 13], tablePreview[line * 16 + 14], tablePreview[line * 16 + 15]);
      logDebug(debugMsg);
    }

    // Seek back to start of file table
    RINOK(stream->Seek(offset_to_use, STREAM_SEEK_SET, nullptr));

    std::vector<PKG_TABLE_ENTRY_PS5> entries(entries_to_use);

    for (uint16_t i = 0; i < entries_to_use; i++) {
      UInt32 read = 0;
      RINOK(stream->Read(&entries[i].type, 4, &read));
      entries[i].type = SwapEndian32(entries[i].type);

      RINOK(stream->Read(&entries[i].unk1, 4, &read));
      entries[i].unk1 = SwapEndian32(entries[i].unk1);

      RINOK(stream->Read(&entries[i].flags1, 4, &read));
      entries[i].flags1 = SwapEndian32(entries[i].flags1);

      RINOK(stream->Read(&entries[i].flags2, 4, &read));
      entries[i].flags2 = SwapEndian32(entries[i].flags2);

      RINOK(stream->Read(&entries[i].offset, 4, &read));
      entries[i].offset = SwapEndian32(entries[i].offset);

      RINOK(stream->Read(&entries[i].size, 4, &read));
      entries[i].size = SwapEndian32(entries[i].size);

      RINOK(stream->Read(entries[i].padding, 8, nullptr));

      // Log first few entries for debugging
      if (i < 10) {
        swprintf_s(debugMsg, L"  Entry[%d]: type=0x%08X, flags1=0x%08X, flags2=0x%08X, offset=0x%08X, size=0x%08X",
          i, entries[i].type, entries[i].flags1, entries[i].flags2, entries[i].offset, entries[i].size);
        logDebug(debugMsg);
      }
    }

    logDebug(L"PS5 ParseFileTable: Creating file items...");

    int nonZeroCount = 0;
    for (uint16_t i = 0; i < entries_to_use; i++) {
      FileInfo fi;
      fi.offset = entries[i].offset;
      fi.size = entries[i].size;
      fi.type = entries[i].type;
      fi.flags1 = entries[i].flags1;
      fi.flags2 = entries[i].flags2;
      fi.keyIndex = (entries[i].flags2 & 0xF000) >> 12;
      fi.isEncrypted = ((entries[i].flags1 & 0x80000000) != 0);

      if (entries[i].type != 0) {
        nonZeroCount++;
      }

      char filename[64];
      sprintf_s(filename, "entry_0x%08X.bin", entries[i].type);
      fi.path = filename;

      items.push_back(std::move(fi));
    }

    swprintf_s(debugMsg, L"PS5 ParseFileTable: SUCCESS - parsed %d items (%d with non-zero type)",
      items.size(), nonZeroCount);
    logDebug(debugMsg);

    return S_OK;
  }

  HRESULT ExtractFileToStream(IInStream* inStream, const FileInfo& fi,
    ISequentialOutStream* outStream,
    const std::vector<uint8_t>& rsaDecryptedData) {
    if (fi.size == 0) return S_OK;

    uint32_t alignedSize = fi.size;
    if (alignedSize % 0x10 != 0) {
      alignedSize = alignedSize + 0x10 - (alignedSize % 0x10);
    }

    std::vector<uint8_t> fileData(alignedSize);
    UInt32 read = 0;

    RINOK(inStream->Seek(fi.offset, STREAM_SEEK_SET, nullptr));
    RINOK(inStream->Read(fileData.data(), alignedSize, &read));

    if (fi.isEncrypted) {
      std::vector<uint8_t> entryData(0x40);

      uint32_t* entryPtr = (uint32_t*)entryData.data();
      entryPtr[0] = SwapEndian32(fi.type);
      entryPtr[1] = 0;
      entryPtr[2] = SwapEndian32(fi.flags1);
      entryPtr[3] = SwapEndian32(fi.flags2);
      entryPtr[4] = SwapEndian32((uint32_t)fi.offset);
      entryPtr[5] = SwapEndian32((uint32_t)fi.size);

      memcpy(entryData.data() + 0x20, rsaDecryptedData.data(), 0x20);

      std::vector<uint8_t> hash = SHA3_256::HashData(entryData.data(), 0x40);

      uint8_t iv[16], key[16];
      memcpy(iv, hash.data(), 0x10);
      memcpy(key, hash.data() + 0x10, 0x10);

      std::vector<uint8_t> decryptedData(alignedSize);
      if (!AesCbcDecrypt(decryptedData.data(), fileData.data(),
        alignedSize, key, iv)) {
        return E_FAIL;
      }

      UInt32 written = 0;
      RINOK(outStream->Write(decryptedData.data(), fi.size, &written));
    }
    else {
      UInt32 written = 0;
      RINOK(outStream->Write(fileData.data(), fi.size, &written));
    }

    return S_OK;
  }

  const PKG_HEADER_PS5& GetHeader() const { return header; }
};