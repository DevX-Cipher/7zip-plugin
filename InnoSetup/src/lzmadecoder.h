#ifndef LZMA_DECODER_H
#define LZMA_DECODER_H


#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "xbinary.h"

/* ------------------------------------------------------------------ */
/* Output container                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
  uint8_t* data;
  size_t length;
  size_t capacity;
} LZMAByteVector;

static bool lzma_bytevector_reserve(LZMAByteVector* vec, size_t size) {
  if (vec->capacity < size) {
    uint8_t* new_data = (uint8_t*)realloc(vec->data, size ? size : 1);
    if (!new_data) return false;
    vec->data = new_data;
    vec->capacity = size;
  }
  return true;
}

static bool lzma_bytevector_push(LZMAByteVector* vec, uint8_t byte) {
  if (vec->length >= vec->capacity) {
    size_t new_cap = vec->capacity == 0 ? 65536 : vec->capacity * 2;
    if (!lzma_bytevector_reserve(vec, new_cap)) return false;
  }
  vec->data[vec->length++] = byte;
  return true;
}

/* ------------------------------------------------------------------ */
/* Bit stream / range coder                                            */
/* ------------------------------------------------------------------ */

typedef struct {
  const uint8_t* data;
  size_t size;
  size_t pos;
} LZMAStream;

typedef struct {
  uint32_t range;
  uint32_t code;
  LZMAStream* stream;
} LZMARangeDecoder;

typedef uint16_t LZMAProb;

#define LZMA_PROB_INIT ((1u << 11) / 2)          /* bit-model probabilities live in [0, 2048) */
#define LZMA_NUM_BIT_MODEL_TOTAL_BITS 11
#define LZMA_NUM_MOVE_BITS 5
#define LZMA_TOP_VALUE (1u << 24)

static inline uint8_t lzma_stream_next(LZMAStream* s) {
  if (s->pos < s->size) return s->data[s->pos++];
  return 0; /* tolerate reading past the end near the stream's tail */
}

static bool lzma_range_decoder_init(LZMARangeDecoder* rd, LZMAStream* stream) {
  rd->range = 0xFFFFFFFFu;
  rd->code = 0;
  rd->stream = stream;

  if (stream->pos + 5 > stream->size) return false;

  stream->pos++; /* the leading byte of an LZMA stream is always 0; skip it */
  for (int i = 0; i < 4; i++) {
    rd->code = (rd->code << 8) | stream->data[stream->pos++];
  }
  return true;
}

static inline void lzma_range_decoder_normalize(LZMARangeDecoder* rd) {
  if (rd->range < LZMA_TOP_VALUE) {
    rd->range <<= 8;
    rd->code = (rd->code << 8) | lzma_stream_next(rd->stream);
  }
}

static inline int lzma_decode_bit(LZMARangeDecoder* rd, LZMAProb* prob) {
  uint32_t bound = (rd->range >> LZMA_NUM_BIT_MODEL_TOTAL_BITS) * (uint32_t)(*prob);
  int bit;
  if (rd->code < bound) {
    rd->range = bound;
    *prob = (LZMAProb)(*prob + (((1u << LZMA_NUM_BIT_MODEL_TOTAL_BITS) - *prob) >> LZMA_NUM_MOVE_BITS));
    bit = 0;
  }
  else {
    rd->range -= bound;
    rd->code -= bound;
    *prob = (LZMAProb)(*prob - (*prob >> LZMA_NUM_MOVE_BITS));
    bit = 1;
  }
  lzma_range_decoder_normalize(rd);
  return bit;
}

static inline uint32_t lzma_bittree_decode(LZMARangeDecoder* rd, LZMAProb* probs, int num_bits) {
  uint32_t m = 1;
  for (int i = 0; i < num_bits; i++) {
    m = (m << 1) | (uint32_t)lzma_decode_bit(rd, &probs[m]);
  }
  return m - (1u << num_bits);
}

static inline uint32_t lzma_bittree_reverse_decode(LZMARangeDecoder* rd, LZMAProb* probs, int num_bits) {
  uint32_t m = 1, sym = 0;
  for (int i = 0; i < num_bits; i++) {
    int bit = lzma_decode_bit(rd, &probs[m]);
    m = (m << 1) | (uint32_t)bit;
    sym |= (uint32_t)bit << i;
  }
  return sym;
}

static inline uint32_t lzma_direct_bits_decode(LZMARangeDecoder* rd, int num_bits) {
  uint32_t res = 0;
  for (int i = 0; i < num_bits; i++) {
    rd->range >>= 1;
    rd->code -= rd->range;
    uint32_t t = 0u - (rd->code >> 31);
    rd->code += rd->range & t;
    lzma_range_decoder_normalize(rd);
    res = (res << 1) | (t + 1);
  }
  return res;
}

/* ------------------------------------------------------------------ */
/* LZMA model constants                                                */
/* ------------------------------------------------------------------ */

#define kNumStates 12
#define kNumPosBitsMax 4
#define kNumPosStatesMax (1 << kNumPosBitsMax)
#define kNumLenToPosStates 4
#define kNumAlignBits 4
#define kAlignTableSize (1 << kNumAlignBits)
#define kStartPosModelIndex 4
#define kEndPosModelIndex 14
#define kNumFullDistances (1 << (kEndPosModelIndex >> 1))
#define kMatchMinLen 2
#define kNumLenLowBits 3
#define kNumLenMidBits 3
#define kNumLenHighBits 8
#define kNumLenLowSymbols (1 << kNumLenLowBits)
#define kNumLenMidSymbols (1 << kNumLenMidBits)
#define kNumLenHighSymbols (1 << kNumLenHighBits)
#define kNumPosSlotBits 6

typedef struct {
  uint8_t lc, lp, pb;
  uint32_t dict_size;
  uint64_t uncompressed_size;
  bool unknown_size;
} LZMAProps;

typedef struct {
  LZMAProb choice;
  LZMAProb choice2;
  LZMAProb low[kNumPosStatesMax][kNumLenLowSymbols];
  LZMAProb mid[kNumPosStatesMax][kNumLenMidSymbols];
  LZMAProb high[kNumLenHighSymbols];
} LZMALenDecoder;

typedef struct {
  LZMAProb is_match[kNumStates << kNumPosBitsMax];
  LZMAProb is_rep[kNumStates];
  LZMAProb is_rep_g0[kNumStates];
  LZMAProb is_rep_g1[kNumStates];
  LZMAProb is_rep_g2[kNumStates];
  LZMAProb is_rep0_long[kNumStates << kNumPosBitsMax];
  LZMAProb pos_slot[kNumLenToPosStates][1 << kNumPosSlotBits];
  LZMAProb spec_pos[kNumFullDistances - kEndPosModelIndex];
  LZMAProb align[kAlignTableSize];
  LZMALenDecoder len_decoder;
  LZMALenDecoder rep_len_decoder;
  LZMAProb* literal;   /* 0x300 << (lc + lp) entries */
} LZMAProbs;

/* ------------------------------------------------------------------ */
/* Header parsing                                                      */
/* ------------------------------------------------------------------ */

static bool lzma_parse_properties(LZMAProps* props, const uint8_t* data, size_t size) {
  if (size < 13) return false;

  uint32_t d = data[0];
  if (d >= 9 * 5 * 5) return false;

  /* Canonical LZMA property byte: d = (pb * 5 + lp) * 9 + lc */
  props->lc = (uint8_t)(d % 9);
  d /= 9;
  props->lp = (uint8_t)(d % 5);
  props->pb = (uint8_t)(d / 5);

  props->dict_size = (uint32_t)data[1] | ((uint32_t)data[2] << 8) |
    ((uint32_t)data[3] << 16) | ((uint32_t)data[4] << 24);
  if (props->dict_size < (1u << 12)) props->dict_size = (1u << 12);

  uint64_t usize = 0;
  for (int i = 0; i < 8; i++) usize |= ((uint64_t)data[5 + i]) << (i * 8);

  props->unknown_size = (usize == UINT64_MAX);
  props->uncompressed_size = usize;
  return true;
}

/* ------------------------------------------------------------------ */
/* Probability table setup                                             */
/* ------------------------------------------------------------------ */

static bool lzma_probs_init(LZMAProbs* p, const LZMAProps* props) {
  memset(p, 0, sizeof(*p));

  size_t n = ((size_t)0x300) << (props->lc + props->lp);
  p->literal = (LZMAProb*)malloc(n * sizeof(LZMAProb));
  if (!p->literal) return false;

  for (size_t i = 0; i < (size_t)(kNumStates << kNumPosBitsMax); i++) {
    p->is_match[i] = LZMA_PROB_INIT;
    p->is_rep0_long[i] = LZMA_PROB_INIT;
  }
  for (int i = 0; i < kNumStates; i++) {
    p->is_rep[i] = LZMA_PROB_INIT;
    p->is_rep_g0[i] = LZMA_PROB_INIT;
    p->is_rep_g1[i] = LZMA_PROB_INIT;
    p->is_rep_g2[i] = LZMA_PROB_INIT;
  }
  for (int i = 0; i < kNumLenToPosStates; i++)
    for (int j = 0; j < (1 << kNumPosSlotBits); j++)
      p->pos_slot[i][j] = LZMA_PROB_INIT;
  for (size_t i = 0; i < kNumFullDistances - kEndPosModelIndex; i++) p->spec_pos[i] = LZMA_PROB_INIT;
  for (int i = 0; i < kAlignTableSize; i++) p->align[i] = LZMA_PROB_INIT;

  LZMALenDecoder* lens[2] = { &p->len_decoder, &p->rep_len_decoder };
  for (int k = 0; k < 2; k++) {
    lens[k]->choice = LZMA_PROB_INIT;
    lens[k]->choice2 = LZMA_PROB_INIT;
    for (int ps = 0; ps < kNumPosStatesMax; ps++) {
      for (int i = 0; i < kNumLenLowSymbols; i++) lens[k]->low[ps][i] = LZMA_PROB_INIT;
      for (int i = 0; i < kNumLenMidSymbols; i++) lens[k]->mid[ps][i] = LZMA_PROB_INIT;
    }
    for (int i = 0; i < kNumLenHighSymbols; i++) lens[k]->high[i] = LZMA_PROB_INIT;
  }

  for (size_t i = 0; i < n; i++) p->literal[i] = LZMA_PROB_INIT;
  return true;
}

static void lzma_probs_free(LZMAProbs* p) {
  free(p->literal);
  p->literal = NULL;
}

/* ------------------------------------------------------------------ */
/* State machine                                                       */
/* ------------------------------------------------------------------ */

static inline int lzma_state_update_literal(int state) {
  if (state < 4) return 0;
  if (state < 10) return state - 3;
  return state - 6;
}
static inline int lzma_state_update_match(int state) { return state < 7 ? 7 : 10; }
static inline int lzma_state_update_rep(int state) { return state < 7 ? 8 : 11; }
static inline int lzma_state_update_short_rep(int state) { return state < 7 ? 9 : 11; }
static inline bool lzma_state_is_after_literal(int state) { return state < 7; }

/* ------------------------------------------------------------------ */
/* Length decoding                                                      */
/* ------------------------------------------------------------------ */

static uint32_t lzma_len_decode(LZMARangeDecoder* rd, LZMALenDecoder* lc, int pos_state) {
  if (!lzma_decode_bit(rd, &lc->choice)) {
    return kMatchMinLen + lzma_bittree_decode(rd, lc->low[pos_state], kNumLenLowBits);
  }
  if (!lzma_decode_bit(rd, &lc->choice2)) {
    return kMatchMinLen + kNumLenLowSymbols + lzma_bittree_decode(rd, lc->mid[pos_state], kNumLenMidBits);
  }
  return kMatchMinLen + kNumLenLowSymbols + kNumLenMidSymbols +
    lzma_bittree_decode(rd, lc->high, kNumLenHighBits);
}

/* ------------------------------------------------------------------ */
/* Distance (position slot) decoding                                   */
/* ------------------------------------------------------------------ */

static uint32_t lzma_decode_distance(LZMARangeDecoder* rd, LZMAProbs* p, uint32_t len_minus_min) {
  uint32_t len_state = len_minus_min < kNumLenToPosStates ? len_minus_min : (uint32_t)(kNumLenToPosStates - 1);
  uint32_t pos_slot = lzma_bittree_decode(rd, p->pos_slot[len_state], kNumPosSlotBits);

  if (pos_slot < kStartPosModelIndex) return pos_slot;

  uint32_t num_direct_bits = (pos_slot >> 1) - 1;
  uint32_t dist = (2 | (pos_slot & 1)) << num_direct_bits;

  if (pos_slot < kEndPosModelIndex) {
    dist += lzma_bittree_reverse_decode(rd, p->spec_pos + dist - pos_slot - 1, (int)num_direct_bits);
  }
  else {
    dist += lzma_direct_bits_decode(rd, (int)(num_direct_bits - kNumAlignBits)) << kNumAlignBits;
    dist += lzma_bittree_reverse_decode(rd, p->align, kNumAlignBits);
  }
  return dist;
}

/* ------------------------------------------------------------------ */
/* Literal decoding                                                     */
/* ------------------------------------------------------------------ */

static uint8_t lzma_decode_literal(LZMARangeDecoder* rd, LZMAProbs* p, const LZMAProps* props,
  uint64_t out_pos, uint8_t prev_byte, uint8_t match_byte, int state) {
  uint32_t lit_state = ((uint32_t)(out_pos & ((1u << props->lp) - 1)) << props->lc) |
    (uint32_t)(prev_byte >> (8 - props->lc));
  LZMAProb* probs = p->literal + ((size_t)0x300 * lit_state);

  uint32_t symbol = 1;
  if (!lzma_state_is_after_literal(state)) {
    while (symbol < 0x100) {
      uint32_t match_bit = ((uint32_t)match_byte >> 7) & 1;
      match_byte = (uint8_t)(match_byte << 1);
      int bit = lzma_decode_bit(rd, &probs[((1 + match_bit) << 8) + symbol]);
      symbol = (symbol << 1) | (uint32_t)bit;
      if (match_bit != (uint32_t)bit) break;
    }
  }
  while (symbol < 0x100) {
    symbol = (symbol << 1) | (uint32_t)lzma_decode_bit(rd, &probs[symbol]);
  }
  return (uint8_t)symbol;
}

/* ------------------------------------------------------------------ */
/* Persistent LZMA1 decoder state (reusable across LZMA2 chunks)       */
/* ------------------------------------------------------------------ */

typedef struct {
  LZMAProps props;
  LZMAProbs probs;
  bool probs_valid;
  int state;
  uint32_t rep0, rep1, rep2, rep3; /* stored as (distance - 1) */
} LZMACoreState;

static void lzma_core_state_free(LZMACoreState* cs) {
  if (cs->probs_valid) {
    lzma_probs_free(&cs->probs);
    cs->probs_valid = false;
  }
}

/* Resets range-coder state (state=0, reps=0). Does NOT touch dictionary
   contents (the output buffer) -- callers control dict reset separately
   by simply not resetting out_pos/output. */
static void lzma_core_state_reset(LZMACoreState* cs) {
  cs->state = 0;
  cs->rep0 = cs->rep1 = cs->rep2 = cs->rep3 = 0;
}

/* (Re)allocates the probability tables for new lc/lp/pb properties.
   Safe to call again with the same lc/lp -- just reinitializes probs. */
static bool lzma_core_state_set_props(LZMACoreState* cs, uint8_t lc, uint8_t lp, uint8_t pb) {
  lzma_core_state_free(cs);
  memset(&cs->props, 0, sizeof(cs->props));
  cs->props.lc = lc;
  cs->props.lp = lp;
  cs->props.pb = pb;
  if (!lzma_probs_init(&cs->probs, &cs->props)) return false;
  cs->probs_valid = true;
  return true;
}

/*
 * Decodes exactly `chunk_uncompressed_size` bytes of plain LZMA1 body
 * (NO 13-byte header -- range coder is initialized directly from `stream`)
 * into output->data starting at output->length, using/updating the
 * persistent state in `cs`. output must already have room reserved
 * (via lzma_bytevector_reserve) for length + chunk_uncompressed_size.
 *
 * This is the engine shared by lzma_decompress() (single-shot .lzma) and
 * the LZMA2 chunk loop below.
 */
static int lzma_core_decode_chunk(LZMACoreState* cs, LZMAStream* stream,
  LZMAByteVector* output, uint64_t chunk_uncompressed_size) {
  if (!cs->probs_valid) return -1;

  LZMARangeDecoder rd;
  if (!lzma_range_decoder_init(&rd, stream)) return -1;

  uint32_t pb_mask = (1u << cs->props.pb) - 1;
  uint64_t out_pos = output->length;
  uint64_t out_limit = out_pos + chunk_uncompressed_size;
  int status = 0;

  while (out_pos < out_limit) {
    uint32_t pos_state = (uint32_t)(out_pos & pb_mask);

    if (!lzma_decode_bit(&rd, &cs->probs.is_match[(cs->state << kNumPosBitsMax) + pos_state])) {
      /* literal */
      uint8_t prev_byte = out_pos == 0 ? 0 : output->data[out_pos - 1];
      uint8_t match_byte = 0;
      if (!lzma_state_is_after_literal(cs->state)) {
        if ((uint64_t)cs->rep0 + 1 > out_pos) { status = -1; break; }
        match_byte = output->data[out_pos - cs->rep0 - 1];
      }
      uint8_t sym = lzma_decode_literal(&rd, &cs->probs, &cs->props, out_pos, prev_byte, match_byte, cs->state);
      output->data[out_pos++] = sym;
      cs->state = lzma_state_update_literal(cs->state);
      continue;
    }

    uint32_t len;

    if (!lzma_decode_bit(&rd, &cs->probs.is_rep[cs->state])) {
      /* new match: shift the rep history and decode a fresh distance */
      cs->rep3 = cs->rep2; cs->rep2 = cs->rep1; cs->rep1 = cs->rep0;
      len = lzma_len_decode(&rd, &cs->probs.len_decoder, (int)pos_state);
      cs->state = lzma_state_update_match(cs->state);
      cs->rep0 = lzma_decode_distance(&rd, &cs->probs, len - kMatchMinLen);

      if (cs->rep0 == 0xFFFFFFFFu) break; /* end-of-stream marker */
      if ((uint64_t)cs->rep0 + 1 > out_pos) { status = -1; break; }
    }
    else {
      if (out_pos == 0) { status = -1; break; }
      if (!lzma_decode_bit(&rd, &cs->probs.is_rep_g0[cs->state])) {
        if (!lzma_decode_bit(&rd, &cs->probs.is_rep0_long[(cs->state << kNumPosBitsMax) + pos_state])) {
          /* short rep: copy exactly one byte from rep0, no length decode */
          cs->state = lzma_state_update_short_rep(cs->state);
          if ((uint64_t)cs->rep0 + 1 > out_pos) { status = -1; break; }
          output->data[out_pos] = output->data[out_pos - cs->rep0 - 1];
          out_pos++;
          continue;
        }
        /* distance stays rep0; fall through to length decode below */
      }
      else {
        uint32_t dist;
        if (!lzma_decode_bit(&rd, &cs->probs.is_rep_g1[cs->state])) {
          dist = cs->rep1;
        }
        else {
          if (!lzma_decode_bit(&rd, &cs->probs.is_rep_g2[cs->state])) {
            dist = cs->rep2;
          }
          else {
            dist = cs->rep3;
            cs->rep3 = cs->rep2;
          }
          cs->rep2 = cs->rep1;
        }
        cs->rep1 = cs->rep0;
        cs->rep0 = dist;
      }
      len = lzma_len_decode(&rd, &cs->probs.rep_len_decoder, (int)pos_state);
      cs->state = lzma_state_update_rep(cs->state);
    }

    if ((uint64_t)cs->rep0 + 1 > out_pos) { status = -1; break; }

    uint64_t copy_len = len;
    if (out_pos + copy_len > out_limit) copy_len = out_limit - out_pos;
    for (uint64_t i = 0; i < copy_len; i++) {
      output->data[out_pos] = output->data[out_pos - cs->rep0 - 1];
      out_pos++;
    }
  }

  output->length = (size_t)out_pos;
  return status;
}

/* ------------------------------------------------------------------ */
/* Top-level decompression: plain .lzma (LZMA_Alone) format             */
/* ------------------------------------------------------------------ */

static int lzma_decompress(const uint8_t* input, size_t input_size,
  LZMAByteVector* output, size_t max_output_size) {
  LZMAProps props;
  if (!lzma_parse_properties(&props, input, input_size)) return -1;
  if ((unsigned)props.lc + props.lp > 4) return -1;

  uint64_t uncompressed_size = props.unknown_size ? (uint64_t)max_output_size : props.uncompressed_size;
  if (uncompressed_size > max_output_size) return -1;

  if (!lzma_bytevector_reserve(output, (size_t)uncompressed_size)) return -1;
  output->length = 0;

  LZMAStream stream;
  stream.data = input + 13;
  stream.size = input_size - 13;
  stream.pos = 0;

  LZMACoreState cs;
  memset(&cs, 0, sizeof(cs));
  if (!lzma_core_state_set_props(&cs, props.lc, props.lp, props.pb)) return -1;
  lzma_core_state_reset(&cs);

  int status = lzma_core_decode_chunk(&cs, &stream, output, uncompressed_size);
  lzma_core_state_free(&cs);
  return status;
}



static int lzma2_decompress(const uint8_t* input, size_t input_size,
  LZMAByteVector* output, size_t max_output_size) {
  if (!lzma_bytevector_reserve(output, output->length ? output->length : 4096)) return -1;
  output->length = 0;

  LZMAStream stream;
  stream.data = input;
  stream.size = input_size;
  stream.pos = 0;

  LZMACoreState cs;
  memset(&cs, 0, sizeof(cs));
  bool have_props = false;

  int status = 0;

  for (;;) {
    if (stream.pos >= stream.size) { status = -1; break; } /* truncated: missing terminator */

    uint8_t control = stream.data[stream.pos++];
    if (control == 0x00) break; /* end of LZMA2 stream */

    if (control < 0x80) {
      /* uncompressed chunk: control must be 1 (reset dict) or 2 (no reset) */
      if (control != 0x01 && control != 0x02) { status = -1; break; }
      if (stream.pos + 2 > stream.size) { status = -1; break; }
      uint32_t unpack_size = ((uint32_t)stream.data[stream.pos] << 8 | stream.data[stream.pos + 1]) + 1;
      stream.pos += 2;

      if (stream.pos + unpack_size > stream.size) { status = -1; break; }
      if (output->length + unpack_size > max_output_size) { status = -1; break; }
      if (!lzma_bytevector_reserve(output, output->length + unpack_size)) { status = -1; break; }

      memcpy(output->data + output->length, stream.data + stream.pos, unpack_size);
      output->length += unpack_size;
      stream.pos += unpack_size;
      continue;
    }

    /* LZMA chunk: control bit layout 1RRuuuuu */
    unsigned reset_kind = (control >> 5) & 0x3; /* 0=none,1=state,2=state+props,3=state+props+dict */
    if (stream.pos + 2 > stream.size) { status = -1; break; }
    uint32_t unpack_size = (((uint32_t)(control & 0x1F) << 16) |
      ((uint32_t)stream.data[stream.pos] << 8) |
      (uint32_t)stream.data[stream.pos + 1]) + 1;
    stream.pos += 2;

    if (stream.pos + 2 > stream.size) { status = -1; break; }
    uint32_t pack_size = ((uint32_t)stream.data[stream.pos] << 8 | stream.data[stream.pos + 1]) + 1;
    stream.pos += 2;

    if (reset_kind >= 2) {
      if (stream.pos + 1 > stream.size) { status = -1; break; }
      uint8_t prop_byte = stream.data[stream.pos++];
      if (prop_byte >= 9 * 5 * 5) { status = -1; break; }
      uint8_t lc = (uint8_t)(prop_byte % 9);
      uint8_t rest = (uint8_t)(prop_byte / 9);
      uint8_t lp = (uint8_t)(rest % 5);
      uint8_t pb = (uint8_t)(rest / 5);
      if ((unsigned)lc + lp > 4) { status = -1; break; }
      if (!lzma_core_state_set_props(&cs, lc, lp, pb)) { status = -1; break; }
      have_props = true;
    }

    if (!have_props) { status = -1; break; } /* first LZMA chunk must set properties */

    if (reset_kind >= 1) {
      lzma_core_state_reset(&cs);
    }
    /* reset_kind == 3 also means "reset dictionary": since we keep the
       whole output as one buffer, prior bytes remain addressable; a real
       bounded-window implementation would clear its window here. */

    if (stream.pos + pack_size > stream.size) { status = -1; break; }
    if (output->length + unpack_size > max_output_size) { status = -1; break; }
    if (!lzma_bytevector_reserve(output, output->length + unpack_size)) { status = -1; break; }

    LZMAStream chunk_stream;
    chunk_stream.data = stream.data + stream.pos;
    chunk_stream.size = pack_size;
    chunk_stream.pos = 0;

    int chunk_status = lzma_core_decode_chunk(&cs, &chunk_stream, output, unpack_size);
    stream.pos += pack_size;

    if (chunk_status != 0) { status = chunk_status; break; }
  }

  lzma_core_state_free(&cs);
  return status;
}

#endif /* LZMA_DECODER_H */