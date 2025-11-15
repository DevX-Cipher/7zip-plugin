#ifndef ZLIB_DECODER_H
#define ZLIB_DECODER_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>

typedef struct {
  const uint8_t* data;
  size_t size;
  size_t byte_pos;
  uint32_t bit_buffer;
  int bits_in_buffer;
} BitStream;

typedef struct {
  uint8_t* data;
  size_t length;
  size_t size;
} ByteVector;

static ByteVector* bytevector_create(size_t initial_size) {
  ByteVector* bv = (ByteVector*)malloc(sizeof(ByteVector));
  if (!bv) return NULL;
  bv->data = (uint8_t*)malloc(initial_size);
  if (!bv->data) { free(bv); return NULL; }
  bv->length = 0;
  bv->size = initial_size;
  return bv;
}

static void bytevector_free(ByteVector* bv) {
  if (!bv) return;
  if (bv->data) free(bv->data);
  free(bv);
}

static int bytevector_push(ByteVector* bv, uint8_t val) {
  if (bv->length >= bv->size) {
    size_t new_size = bv->size ? bv->size * 2 : 256;
    uint8_t* tmp = (uint8_t*)realloc(bv->data, new_size);
    if (!tmp) return 0;
    bv->data = tmp;
    bv->size = new_size;
  }
  bv->data[bv->length++] = val;
  return 1;
}

static void bitstream_init(BitStream* bs, const uint8_t* data, size_t size) {
  bs->data = data;
  bs->size = size;
  bs->byte_pos = 0;
  bs->bit_buffer = 0;
  bs->bits_in_buffer = 0;
}

static int bitstream_read_bits(BitStream* bs, int n) {
  while (bs->bits_in_buffer < n) {
    if (bs->byte_pos >= bs->size) return -1;
    bs->bit_buffer |= (uint32_t)bs->data[bs->byte_pos++] << bs->bits_in_buffer;
    bs->bits_in_buffer += 8;
  }
  int result = bs->bit_buffer & ((1 << n) - 1);
  bs->bit_buffer >>= n;
  bs->bits_in_buffer -= n;
  return result;
}

static int bitstream_read_byte_aligned(BitStream* bs) {
  bs->bit_buffer = 0;
  bs->bits_in_buffer = 0;
  if (bs->byte_pos >= bs->size) return -1;
  return bs->data[bs->byte_pos++];
}

static void bitstream_align_to_byte(BitStream* bs) {
  bs->bit_buffer = 0;
  bs->bits_in_buffer = 0;
}

typedef struct {
  int max_code[16];
  int offset[16];
  uint16_t symbols[288];
} HuffmanTable;

static void huffman_build(HuffmanTable* table, const uint8_t* lengths, int n) {
  int bl_count[16] = { 0 };
  for (int i = 0; i < n; i++) {
    if (lengths[i] > 0 && lengths[i] < 16) bl_count[lengths[i]]++;
  }

  int code = 0;
  bl_count[0] = 0;
  int next_code[16] = { 0 };
  for (int bits = 1; bits < 16; bits++) {
    code = (code + bl_count[bits - 1]) << 1;
    next_code[bits] = code;
  }

  for (int bits = 0; bits < 16; bits++) {
    table->max_code[bits] = -1;
    table->offset[bits] = 0;
  }

  int sym_idx = 0;
  for (int bits = 1; bits < 16; bits++) {
    table->offset[bits] = sym_idx - next_code[bits];
    for (int i = 0; i < n; i++) {
      if (lengths[i] == bits) {
        table->symbols[sym_idx++] = i;
        table->max_code[bits] = next_code[bits]++;
      }
    }
  }
}

static int huffman_decode(const HuffmanTable* table, BitStream* bs) {
  int code = 0;
  for (int len = 1; len < 16; len++) {
    int bit = bitstream_read_bits(bs, 1);
    if (bit < 0) return -1;
    code = (code << 1) | bit;
    if (code <= table->max_code[len] && table->max_code[len] >= 0) {
      return table->symbols[table->offset[len] + code];
    }
  }
  return -1;
}

static uint32_t adler32(const uint8_t* data, size_t len) {
  uint32_t a = 1, b = 0;
  const uint32_t MOD_ADLER = 65521;
  for (size_t i = 0; i < len; i++) {
    a = (a + data[i]) % MOD_ADLER;
    b = (b + a) % MOD_ADLER;
  }
  return (b << 16) | a;
}

static const uint16_t length_base[29] = {
    3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,
    35,43,51,59,67,83,99,115,131,163,195,227,258
};
static const uint8_t length_extra[29] = {
    0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,
    3,3,3,3,4,4,4,4,5,5,5,5,0
};
static const uint16_t dist_base[30] = {
    1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,
    257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577
};
static const uint8_t dist_extra[30] = {
    0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,
    7,7,8,8,9,9,10,10,11,11,12,12,13,13
};

static void init_fixed_tables(uint8_t* lit_lengths, uint8_t* dist_lengths) {
  for (int i = 0; i <= 143; i++) lit_lengths[i] = 8;
  for (int i = 144; i <= 255; i++) lit_lengths[i] = 9;
  for (int i = 256; i <= 279; i++) lit_lengths[i] = 7;
  for (int i = 280; i <= 287; i++) lit_lengths[i] = 8;
  for (int i = 0; i < 32; i++) dist_lengths[i] = 5;
}

static int decode_dynamic_tables(BitStream* bs, uint8_t* lit_lengths, uint8_t* dist_lengths) {
  int hlit = bitstream_read_bits(bs, 5);
  if (hlit < 0) return -1; hlit += 257;
  int hdist = bitstream_read_bits(bs, 5);
  if (hdist < 0) return -1; hdist += 1;
  int hclen = bitstream_read_bits(bs, 4);
  if (hclen < 0) return -1; hclen += 4;

  const uint8_t cl_order[19] = { 16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15 };
  uint8_t cl_lengths[19] = { 0 };
  for (int i = 0; i < hclen; i++) {
    int len = bitstream_read_bits(bs, 3);
    if (len < 0) return -1;
    cl_lengths[cl_order[i]] = (uint8_t)len;
  }

  HuffmanTable cl_table;
  huffman_build(&cl_table, cl_lengths, 19);

  uint8_t all_lengths[320] = { 0 };
  int idx = 0, total = hlit + hdist;

  while (idx < total) {
    int sym = huffman_decode(&cl_table, bs);
    if (sym < 0) return -1;
    if (sym < 16) all_lengths[idx++] = (uint8_t)sym;
    else if (sym == 16) {
      if (idx == 0) return -1;
      int repeat = bitstream_read_bits(bs, 2);
      if (repeat < 0) return -1;
      repeat += 3;
      uint8_t val = all_lengths[idx - 1];
      while (repeat-- > 0 && idx < total) all_lengths[idx++] = val;
    }
    else if (sym == 17) {
      int repeat = bitstream_read_bits(bs, 3);
      if (repeat < 0) return -1;
      repeat += 3;
      while (repeat-- > 0 && idx < total) all_lengths[idx++] = 0;
    }
    else if (sym == 18) {
      int repeat = bitstream_read_bits(bs, 7);
      if (repeat < 0) return -1;
      repeat += 11;
      while (repeat-- > 0 && idx < total) all_lengths[idx++] = 0;
    }
    else return -1;
  }

  for (int i = 0; i < hlit; i++) lit_lengths[i] = all_lengths[i];
  for (int i = 0; i < hdist; i++) dist_lengths[i] = all_lengths[hlit + i];

  return 0;
}

static int decode_block(BitStream* bs, ByteVector* output, const uint8_t* lit_lengths, const uint8_t* dist_lengths) {
  HuffmanTable lit_table, dist_table;
  huffman_build(&lit_table, lit_lengths, 288);
  huffman_build(&dist_table, dist_lengths, 32);

  while (1) {
    int symbol = huffman_decode(&lit_table, bs);
    if (symbol < 0) return -1;
    if (symbol < 256) {
      if (!bytevector_push(output, (uint8_t)symbol)) return -1;
    }
    else if (symbol == 256) return 0;
    else if (symbol <= 285) {
      int len_code = symbol - 257;
      if (len_code >= 29) return -1;

      int length = length_base[len_code];
      int extra_bits = length_extra[len_code];
      if (extra_bits > 0) {
        int extra = bitstream_read_bits(bs, extra_bits);
        if (extra < 0) return -1;
        length += extra;
      }

      int dist_code = huffman_decode(&dist_table, bs);
      if (dist_code < 0 || dist_code >= 30) return -1;
      int distance = dist_base[dist_code];
      extra_bits = dist_extra[dist_code];
      if (extra_bits > 0) {
        int extra = bitstream_read_bits(bs, extra_bits);
        if (extra < 0) return -1;
        distance += extra;
      }

      if (distance > (int)output->length || distance <= 0) return -1;
      size_t copy_pos = output->length - distance;
      for (int i = 0; i < length; i++) {
        if (!bytevector_push(output, output->data[copy_pos + i])) return -1;
      }
    }
    else return -1;
  }
}

static int zlib_decompress_deflate(const uint8_t* input, size_t size,
  ByteVector* output, size_t* bytes_consumed) {
  BitStream bs;
  bitstream_init(&bs, input, size);
  int is_final = 0;

  while (!is_final) {
    is_final = bitstream_read_bits(&bs, 1);
    if (is_final < 0) return -1;

    int type = bitstream_read_bits(&bs, 2);
    if (type < 0) return -1;

    if (type == 0) {
      bitstream_align_to_byte(&bs);
      int len_lo = bitstream_read_byte_aligned(&bs);
      int len_hi = bitstream_read_byte_aligned(&bs);
      int nlen_lo = bitstream_read_byte_aligned(&bs);
      int nlen_hi = bitstream_read_byte_aligned(&bs);
      if (len_lo < 0 || len_hi < 0 || nlen_lo < 0 || nlen_hi < 0) return -1;
      uint16_t len = (uint16_t)(len_lo | (len_hi << 8));
      uint16_t nlen = (uint16_t)(nlen_lo | (nlen_hi << 8));
      if (len != (uint16_t)~nlen) return -1;
      for (int i = 0; i < len; i++) {
        int b = bitstream_read_byte_aligned(&bs);
        if (b < 0) return -1;
        if (!bytevector_push(output, (uint8_t)b)) return -1;
      }
    }
    else if (type == 1) {
      uint8_t lit[288], dist[32];
      init_fixed_tables(lit, dist);
      if (decode_block(&bs, output, lit, dist) < 0) return -1;
    }
    else if (type == 2) {
      uint8_t lit[288] = { 0 }, dist[32] = { 0 };
      if (decode_dynamic_tables(&bs, lit, dist) < 0) return -1;
      if (decode_block(&bs, output, lit, dist) < 0) return -1;
    }
    else {
      return -1;
    }
  }

  if (bytes_consumed) *bytes_consumed = bs.byte_pos;
  return 0;
}

static int zlib_decompress(const uint8_t* input, size_t input_size, ByteVector* output) {
  if (input_size < 6) return -1;
  uint8_t cmf = input[0], flg = input[1];
  if ((cmf & 0x0F) != 8) return -1;
  if (((cmf << 8) + flg) % 31 != 0) return -1;
  if (flg & 0x20) return -1;

  if (input_size < 6) return -1;
  const uint8_t* deflate_data = input + 2;
  size_t deflate_size = input_size - 6;
  size_t consumed = 0;

  if (zlib_decompress_deflate(deflate_data, deflate_size, output, &consumed) < 0)
    return -1;

  if (input_size >= 6 + 4) {
    uint32_t stored_checksum =
      ((uint32_t)input[input_size - 4] << 24) |
      ((uint32_t)input[input_size - 3] << 16) |
      ((uint32_t)input[input_size - 2] << 8) |
      ((uint32_t)input[input_size - 1]);
    uint32_t computed = adler32(output->data, output->length);
    if (stored_checksum != computed) return -1;
  }

  return 0;
}

static int zlib_decompress_no_checksum(const uint8_t* input, size_t input_size, ByteVector* output, size_t* bytes_consumed) {
  if (input_size < 2) return -1;
  uint8_t cmf = input[0], flg = input[1];
  if ((cmf & 0x0F) != 8) return -1;
  if (((cmf << 8) + flg) % 31 != 0) return -1;
  if (flg & 0x20) return -1;

  // Skip zlib header and just decompress the DEFLATE data
  const uint8_t* deflate_data = input + 2;
  size_t deflate_size = input_size - 2;
  size_t consumed = 0;

  int result = zlib_decompress_deflate(deflate_data, deflate_size, output, &consumed);
  if (bytes_consumed) {
    *bytes_consumed = consumed + 2;
  }
  return result;
}

#endif /* ZLIB_DECODER_H */
