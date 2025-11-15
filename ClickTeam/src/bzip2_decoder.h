#ifndef BZIP2_DECODER_H
#define BZIP2_DECODER_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define BZ2_MAX_SELECTORS 18002
#define BZ2_MAX_GROUPS 6
#define BZ2_MAX_ALPHA_SIZE 258
#define BZ2_MAX_CODE_LEN 23

typedef struct {
  uint8_t* data;
  size_t length;
  size_t capacity;
} BZ2ByteVector;

static bool bz2_bytevector_push(BZ2ByteVector* vec, uint8_t byte) {
  if (vec->length >= vec->capacity) {
    size_t new_cap = vec->capacity == 0 ? 4096 : vec->capacity * 2;
    uint8_t* new_data = (uint8_t*)realloc(vec->data, new_cap);
    if (!new_data) return false;
    vec->data = new_data;
    vec->capacity = new_cap;
  }
  vec->data[vec->length++] = byte;
  return true;
}

typedef struct {
  const uint8_t* data;
  size_t size;
  size_t byte_pos;
  uint32_t bit_buffer;
  int bits_in_buffer;
} BZ2BitStream;

static void bz2_bitstream_init(BZ2BitStream* bs, const uint8_t* data, size_t size) {
  bs->data = data;
  bs->size = size;
  bs->byte_pos = 0;
  bs->bit_buffer = 0;
  bs->bits_in_buffer = 0;
}

static int bz2_read_bits(BZ2BitStream* bs, int n) {
  while (bs->bits_in_buffer < n) {
    if (bs->byte_pos >= bs->size) return -1;
    bs->bit_buffer = (bs->bit_buffer << 8) | bs->data[bs->byte_pos++];
    bs->bits_in_buffer += 8;
  }
  int result = (bs->bit_buffer >> (bs->bits_in_buffer - n)) & ((1 << n) - 1);
  bs->bits_in_buffer -= n;
  return result;
}

static int bz2_read_bit(BZ2BitStream* bs) {
  return bz2_read_bits(bs, 1);
}

// Count trailing zeros (portable version - replaces __builtin_ctz)
static int bz2_count_trailing_zeros(int value) {
  if (value == 0) return 32;
  int count = 0;
  while ((value & 1) == 0) {
    value >>= 1;
    count++;
  }
  return count;
}

// Burrows-Wheeler Transform inverse
static void bz2_inverse_bwt(uint8_t* data, int* tt, int origPtr, int blockSize) {
  int counts[256] = { 0 };

  // Count occurrences
  for (int i = 0; i < blockSize; i++) {
    counts[data[i]]++;
  }

  // Calculate cumulative counts
  int cumul[256];
  cumul[0] = 0;
  for (int i = 1; i < 256; i++) {
    cumul[i] = cumul[i - 1] + counts[i - 1];
  }

  // Build transformation vector
  for (int i = 0; i < blockSize; i++) {
    tt[cumul[data[i]]++] = i;
  }

  // Inverse transform
  uint8_t* temp = (uint8_t*)malloc(blockSize);
  if (!temp) return;

  int idx = origPtr;
  for (int i = 0; i < blockSize; i++) {
    temp[i] = data[idx];
    idx = tt[idx];
  }

  memcpy(data, temp, blockSize);
  free(temp);
}

// Inverse Move-to-Front transform
static void bz2_inverse_mtf(uint8_t* data, int blockSize) {
  uint8_t mtf[256];
  for (int i = 0; i < 256; i++) {
    mtf[i] = (uint8_t)i;
  }

  for (int i = 0; i < blockSize; i++) {
    uint8_t idx = data[i];
    uint8_t val = mtf[idx];
    data[i] = val;

    // Move to front
    for (int j = idx; j > 0; j--) {
      mtf[j] = mtf[j - 1];
    }
    mtf[0] = val;
  }
}

// Create Huffman decode tables
static int bz2_create_decode_tables(int* limit, int* base, int* perm,
  uint8_t* length, int minLen, int maxLen, int alphaSize) {
  int pp = 0;
  for (int i = minLen; i <= maxLen; i++) {
    for (int j = 0; j < alphaSize; j++) {
      if (length[j] == i) {
        perm[pp++] = j;
      }
    }
  }

  for (int i = 0; i < BZ2_MAX_CODE_LEN; i++) {
    base[i] = 0;
    limit[i] = 0;
  }

  int vec = 0;
  for (int i = minLen; i <= maxLen; i++) {
    int count = 0;
    for (int j = 0; j < alphaSize; j++) {
      if (length[j] == i) count++;
    }
    base[i] = vec;
    vec += count;
    limit[i] = vec - 1;
    vec <<= 1;
  }

  for (int i = minLen + 1; i <= maxLen; i++) {
    base[i] = ((limit[i - 1] + 1) << 1) - base[i];
  }

  return 0;
}

// Decode a block
static int bz2_decompress_block(BZ2BitStream* bs, BZ2ByteVector* output) {
  // Read block header
  int blockMagic1 = bz2_read_bits(bs, 24);
  int blockMagic2 = bz2_read_bits(bs, 24);
  if (blockMagic1 != 0x314159 || blockMagic2 != 0x265359) {
    return -1; // End of blocks or error
  }

  // Read CRC
  bz2_read_bits(bs, 32);

  // Read randomized flag
  int randomized = bz2_read_bit(bs);
  if (randomized) return -1; // Not supported

  // Read origPtr
  int origPtr = bz2_read_bits(bs, 24);

  // Read used bitmap
  int inUse16[16] = { 0 };
  for (int i = 0; i < 16; i++) {
    inUse16[i] = bz2_read_bit(bs);
  }

  bool inUse[256] = { false };
  int symTotal = 0;
  for (int i = 0; i < 16; i++) {
    if (inUse16[i]) {
      for (int j = 0; j < 16; j++) {
        if (bz2_read_bit(bs)) {
          inUse[i * 16 + j] = true;
          symTotal++;
        }
      }
    }
  }

  if (symTotal == 0) return -1;

  // Create symbol map
  uint8_t seqToUnseq[256];
  int idx = 0;
  for (int i = 0; i < 256; i++) {
    if (inUse[i]) {
      seqToUnseq[idx++] = (uint8_t)i;
    }
  }
  int alphaSize = symTotal + 2; // EOB + RUNA + RUNB

  // Read number of Huffman groups
  int nGroups = bz2_read_bits(bs, 3);
  if (nGroups < 2 || nGroups > 6) return -1;

  // Read number of selectors
  int nSelectors = bz2_read_bits(bs, 15);
  if (nSelectors < 1) return -1;

  // Read selector MTF values
  uint8_t selectorMtf[BZ2_MAX_SELECTORS];
  for (int i = 0; i < nSelectors; i++) {
    int j = 0;
    while (bz2_read_bit(bs)) {
      j++;
      if (j >= nGroups) return -1;
    }
    selectorMtf[i] = (uint8_t)j;
  }

  // Undo MTF on selectors
  uint8_t pos[BZ2_MAX_GROUPS];
  for (int i = 0; i < nGroups; i++) pos[i] = (uint8_t)i;

  uint8_t selector[BZ2_MAX_SELECTORS];
  for (int i = 0; i < nSelectors; i++) {
    uint8_t v = selectorMtf[i];
    uint8_t tmp = pos[v];
    while (v > 0) {
      pos[v] = pos[v - 1];
      v--;
    }
    pos[0] = tmp;
    selector[i] = tmp;
  }

  // Read Huffman code lengths
  uint8_t len[BZ2_MAX_GROUPS][BZ2_MAX_ALPHA_SIZE];
  for (int t = 0; t < nGroups; t++) {
    int curr = bz2_read_bits(bs, 5);
    for (int i = 0; i < alphaSize; i++) {
      while (1) {
        if (curr < 1 || curr > 20) return -1;
        if (!bz2_read_bit(bs)) break;
        if (bz2_read_bit(bs)) curr--;
        else curr++;
      }
      len[t][i] = (uint8_t)curr;
    }
  }

  // Create decode tables
  int limit[BZ2_MAX_GROUPS][BZ2_MAX_CODE_LEN];
  int base[BZ2_MAX_GROUPS][BZ2_MAX_CODE_LEN];
  int perm[BZ2_MAX_GROUPS][BZ2_MAX_ALPHA_SIZE];
  int minLens[BZ2_MAX_GROUPS];

  for (int t = 0; t < nGroups; t++) {
    int minLen = 32, maxLen = 0;
    for (int i = 0; i < alphaSize; i++) {
      if (len[t][i] > maxLen) maxLen = len[t][i];
      if (len[t][i] < minLen) minLen = len[t][i];
    }
    minLens[t] = minLen;
    bz2_create_decode_tables(limit[t], base[t], perm[t], len[t], minLen, maxLen, alphaSize);
  }

  // Decode block data
  uint8_t* blockData = (uint8_t*)malloc(900000);
  if (!blockData) return -1;
  int blockSize = 0;

  int groupNo = 0;
  int groupPos = 0;
  int nextSym = 0;
  int runLength = 0;

  while (1) {
    if (groupPos == 0) {
      groupNo = selector[nextSym];
      nextSym++;
      groupPos = 50;
    }
    groupPos--;

    int gSel = groupNo;
    int zn = minLens[gSel];
    int zvec = bz2_read_bits(bs, zn);

    while (zvec > limit[gSel][zn]) {
      if (zn > 20) {
        free(blockData);
        return -1;
      }
      zn++;
      int bit = bz2_read_bit(bs);
      if (bit < 0) {
        free(blockData);
        return -1;
      }
      zvec = (zvec << 1) | bit;
    }

    int sym = perm[gSel][zvec - base[gSel][zn]];

    if (sym == alphaSize - 1) break; // EOB

    if (sym == 0 || sym == 1) { // RUNA or RUNB
      if (runLength == 0) runLength = 1;
      runLength += (sym + 1) << (runLength == 1 ? 0 : bz2_count_trailing_zeros(runLength));
    }
    else {
      if (runLength > 0) {
        uint8_t ch = seqToUnseq[0];
        for (int i = 0; i < runLength; i++) {
          if (blockSize >= 900000) {
            free(blockData);
            return -1;
          }
          blockData[blockSize++] = ch;
        }
        runLength = 0;
      }

      if (blockSize >= 900000) {
        free(blockData);
        return -1;
      }
      blockData[blockSize++] = seqToUnseq[sym - 1];
    }
  }

  // Handle final run
  if (runLength > 0) {
    uint8_t ch = seqToUnseq[0];
    for (int i = 0; i < runLength; i++) {
      if (blockSize >= 900000) {
        free(blockData);
        return -1;
      }
      blockData[blockSize++] = ch;
    }
  }

  // Inverse MTF
  bz2_inverse_mtf(blockData, blockSize);

  // Inverse BWT
  int* tt = (int*)malloc(blockSize * sizeof(int));
  if (!tt) {
    free(blockData);
    return -1;
  }
  bz2_inverse_bwt(blockData, tt, origPtr, blockSize);
  free(tt);

  // Add to output
  for (int i = 0; i < blockSize; i++) {
    if (!bz2_bytevector_push(output, blockData[i])) {
      free(blockData);
      return -1;
    }
  }

  free(blockData);
  return 0;
}

// Main decompression function
static int bzip2_decompress(const uint8_t* input, size_t input_size, BZ2ByteVector* output) {
  if (input_size < 10) return -1;

  // Check magic "BZh"
  if (input[0] != 'B' || input[1] != 'Z' || input[2] != 'h') return -1;

  // Check block size (1-9)
  int blockSize100k = input[3] - '0';
  if (blockSize100k < 1 || blockSize100k > 9) return -1;

  BZ2BitStream bs;
  bz2_bitstream_init(&bs, input + 4, input_size - 4);

  // Decompress all blocks
  while (1) {
    int result = bz2_decompress_block(&bs, output);
    if (result < 0) {
      // Check for stream end marker
      int magic1 = bz2_read_bits(&bs, 24);
      int magic2 = bz2_read_bits(&bs, 24);
      if (magic1 == 0x177245 && magic2 == 0x385090) {
        // Stream end marker found
        return 0;
      }
      return -1;
    }
  }

  return 0;
}

#endif /* BZIP2_DECODER_H */