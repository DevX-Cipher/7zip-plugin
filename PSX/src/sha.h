
class SHA1
{
private:
  uint32_t state[5];
  uint32_t count[2];
  uint8_t buffer[64];

  static uint32_t rol(uint32_t value, uint32_t bits) {
    return (value << bits) | (value >> (32 - bits));
  }

  void transform(const uint8_t block[64]) {
    uint32_t a, b, c, d, e;
    uint32_t w[80];

    // Prepare message schedule
    for (int i = 0; i < 16; i++) {
      w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) |
        (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }
    for (int i = 16; i < 80; i++) {
      w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    // Initialize working variables
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

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

      uint32_t temp = rol(a, 5) + f + e + k + w[i];
      e = d;
      d = c;
      c = rol(b, 30);
      b = a;
      a = temp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
  }

public:
  SHA1() {
    reset();
  }

  void reset() {
    state[0] = 0x67452301;
    state[1] = 0xEFCDAB89;
    state[2] = 0x98BADCFE;
    state[3] = 0x10325476;
    state[4] = 0xC3D2E1F0;
    count[0] = 0;
    count[1] = 0;
  }

  void update(const uint8_t* data, size_t len) {
    uint32_t i, index, partLen;

    // Compute number of bytes mod 64
    index = (uint32_t)((count[0] >> 3) & 0x3F);

    // Update number of bits
    if ((count[0] += ((uint32_t)len << 3)) < ((uint32_t)len << 3))
      count[1]++;
    count[1] += ((uint32_t)len >> 29);

    partLen = 64 - index;

    // Transform as many times as possible
    if (len >= partLen) {
      memcpy(&buffer[index], data, partLen);
      transform(buffer);

      for (i = partLen; i + 63 < len; i += 64)
        transform(&data[i]);

      index = 0;
    }
    else {
      i = 0;
    }

    // Buffer remaining input
    memcpy(&buffer[index], &data[i], len - i);
  }

  void finalize(uint8_t digest[20]) {
    uint8_t finalcount[8];
    uint8_t c;

    for (int i = 0; i < 8; i++) {
      finalcount[i] = (uint8_t)((count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
    }

    c = 0200;
    update(&c, 1);

    while ((count[0] & 504) != 448) {
      c = 0000;
      update(&c, 1);
    }

    update(finalcount, 8);

    for (int i = 0; i < 20; i++) {
      digest[i] = (uint8_t)((state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
  }
};