#pragma once
#include "lzmadecoder.h"
#include "zlibdecoder.h"
#include <vector>
#include <cstdint>
#include <cstring>

namespace UpxSdkCodecs {

  inline bool LzmaDecodeRaw(const uint8_t* pSrc, size_t nSrcSize,
    uint8_t lc, uint8_t lp, uint8_t pb,
    std::vector<uint8_t>& out, size_t expectedSize)
  {
    LZMACoreState cs;
    memset(&cs, 0, sizeof(cs));
    if (!lzma_core_state_set_props(&cs, lc, lp, pb)) {
      return false;
    }
    lzma_core_state_reset(&cs);

    LZMAStream stream;
    stream.data = pSrc;
    stream.size = nSrcSize;
    stream.pos = 0;

    out.assign(expectedSize, 0);

    LZMAByteVector outVec;
    outVec.data = out.data();       
    outVec.length = 0;
    outVec.capacity = expectedSize; 

    int rc = lzma_core_decode_chunk(&cs, &stream, &outVec, expectedSize);
    lzma_core_state_free(&cs);

    bool ok = (rc == 0) && (outVec.length == expectedSize);
    out.resize(outVec.length);
    return ok;
  }

  inline bool DeflateDecodeRaw(const uint8_t* pSrc, size_t nSrcSize,
    std::vector<uint8_t>& out, size_t expectedSize)
  {
    out.assign(expectedSize, 0);

    ByteVector outVec;
    bytevector_init_fixed(&outVec, out.data(), static_cast<uint32_t>(expectedSize));

    size_t consumed = 0;
    int rc = zlib_decompress_deflate(pSrc, static_cast<uint32_t>(nSrcSize), &outVec, &consumed);

    bool ok = (rc == 0);
    out.resize(outVec.length);
    return ok;
  }

} // namespace UpxSdkCodecs