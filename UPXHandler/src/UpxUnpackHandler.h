#pragma once
#include "upx_types_xupx.h"
#include "upx_pe_unpack.h"
#include "UpxSdkCodecs.h"

#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <array>

class UpxUnpackHandler {
public:
  struct Item {
    std::string displayName;
    std::vector<uint8_t> data;   
    uint32_t uncompressedSize = 0;
    uint32_t compressedSize = 0;
    bool ok = false;
    std::string statusNote;       
  };

  std::vector<Item> items;

  bool Open(IInStream* stream, const std::string& baseName = "unpacked") {
    items.clear();

    UInt64 streamLength = 0;
    if (stream->Seek(0, STREAM_SEEK_END, &streamLength) != S_OK) return false;
    if (stream->Seek(0, STREAM_SEEK_SET, nullptr) != S_OK) return false;

    fileData_.resize(static_cast<size_t>(streamLength));
    if (!fileData_.empty()) {
      UInt32 totalRead = 0;
      while (totalRead < fileData_.size()) {
        UInt32 chunk = 0;
        HRESULT hr = stream->Read(fileData_.data() + totalRead,
          static_cast<UInt32>(fileData_.size() - totalRead), &chunk);
        if (hr != S_OK || chunk == 0) break;
        totalRead += chunk;
      }
      if (totalRead != fileData_.size()) return false;
    }

    bool bIsPE = (fileData_.size() >= 2 && fileData_[0] == 'M' && fileData_[1] == 'Z');
    if (!bIsPE) return false;

    XUPX::INTERNAL_INFO info;
    if (!detectPEInfo(&info) && !detectGenericInfo(&info)) {
      return false;
    }
    info_ = info;
    info_.bIsValid = true;

    Item item;
    item.displayName = baseName + "-unpacked.exe";
    item.compressedSize = info_.c_len;
    item.uncompressedSize = info_.u_file_size ? info_.u_file_size : info_.u_len;

    bool decompressed = DecompressPayload(item);
    if (decompressed) {
      TryReconstructPE(item);
      item.ok = true;
    }
    else {
      item.ok = false;
      if (item.statusNote.empty()) item.statusNote = "decompression failed";
    }

    items.push_back(std::move(item));
    return true;
  }

private:
  std::vector<uint8_t> fileData_;
  XUPX::INTERNAL_INFO info_{};

  static constexpr size_t HEADER_SEARCH_SIZE = 0x1000;
  static constexpr size_t PACK_HEADER_SIZE = 36;
  static constexpr size_t MIN_PACK_HEADER_SIZE = 20;

  static uint32_t rd32(const uint8_t* p, bool be = false) {
    if (be) {
      return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
        (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
    }
    return (static_cast<uint32_t>(p[3]) << 24) | (static_cast<uint32_t>(p[2]) << 16) |
      (static_cast<uint32_t>(p[1]) << 8) | static_cast<uint32_t>(p[0]);
  }

  XUPX::INTERNAL_INFO readPackHeader(const uint8_t* h, size_t n, bool bigEndian) {
    XUPX::INTERNAL_INFO result{};
    if (n >= 8) {
      std::memcpy(result.magic, h, 4);
      result.version = h[4];
      result.format = h[5];
      result.method = h[6];
      result.level = h[7];
    }

    if (result.format < 128) {
      if (n >= 12) {
        result.u_adler = rd32(h + 8, bigEndian);
        result.c_adler = rd32(h + 12, bigEndian);
      }
      if (n >= 32) {
        result.u_len = rd32(h + 16, bigEndian);
        result.c_len = rd32(h + 20, bigEndian);
        result.u_file_size = rd32(h + 24, bigEndian);
        result.off_filter = 28;
        result.filter_cto = h[29];
        result.n_mru = (h[30] ? 1 + h[30] : 0);
      }
    }
    else if (n >= 32) {
      result.u_len = rd32(h + 8, bigEndian);
      result.c_len = rd32(h + 12, bigEndian);
      result.u_adler = rd32(h + 16, bigEndian);
      result.c_adler = rd32(h + 20, bigEndian);
      result.u_file_size = rd32(h + 24, bigEndian);
      result.off_filter = 28;
      result.filter_cto = h[29];
      result.n_mru = (h[30] ? 1 + h[30] : 0);
    }

    if (result.version <= 3) result.nPackHeaderSize = 24;
    else if (result.version <= 9) result.nPackHeaderSize = 28;
    else result.nPackHeaderSize = 32;

    if ((result.version > 10) && (result.off_filter < n)) {
      result.filter = h[result.off_filter];
    }
    return result;
  }

  bool isPackHeaderValid(const XUPX::INTERNAL_INFO& info) const {
    return info.magic[0] == 'U' && info.magic[1] == 'P' &&
      info.magic[2] == 'X' && info.magic[3] == '!';
  }

  bool detectPEInfo(XUPX::INTERNAL_INFO* pInfo) {
    if (fileData_.size() < MIN_PACK_HEADER_SIZE) return false;

    size_t searchSize = (HEADER_SEARCH_SIZE < fileData_.size())
      ? HEADER_SEARCH_SIZE
      : fileData_.size();

    for (size_t i = 0; i + 4 <= searchSize; i++) {
      if (!(fileData_[i] == 'U' && fileData_[i + 1] == 'P' &&
        fileData_[i + 2] == 'X' && fileData_[i + 3] == '!')) {
        continue;
      }

      if (i + PACK_HEADER_SIZE > fileData_.size()) break;

      XUPX::INTERNAL_INFO candidate =
        readPackHeader(fileData_.data() + i, PACK_HEADER_SIZE, false);

      if (!isPackHeaderValid(candidate)) continue;

      candidate.nHeaderOffset = static_cast<int64_t>(i);
      candidate.nDataOffset = static_cast<int64_t>(i + candidate.nPackHeaderSize);

      if (static_cast<size_t>(candidate.nDataOffset)
        + sizeof(XUPX::p_info)
        + sizeof(XUPX::b_info)
        <= fileData_.size()) {

        const XUPX::p_info* pPInfo =
          reinterpret_cast<const XUPX::p_info*>(fileData_.data() + candidate.nDataOffset);

        const XUPX::b_info* pBInfo =
          reinterpret_cast<const XUPX::b_info*>(fileData_.data() + candidate.nDataOffset + sizeof(XUPX::p_info));

        candidate.u_len = rd32(reinterpret_cast<const uint8_t*>(&pPInfo->p_filesize), false);
        candidate.c_len = rd32(reinterpret_cast<const uint8_t*>(&pBInfo->sz_cpr), false);
        candidate.method = pBInfo->b_method;
        candidate.filter = pBInfo->b_ftid;
        candidate.filter_cto = pBInfo->b_cto8;
      }

      if (candidate.c_len == 0 || candidate.u_len == 0 ||
        candidate.c_len > fileData_.size() ||
        candidate.u_len > fileData_.size() * 100) {
        continue;
      }

      *pInfo = candidate;
      return true;
    }

    return false;
  }

  bool detectGenericInfo(XUPX::INTERNAL_INFO* pInfo) {
    size_t searchSize = (HEADER_SEARCH_SIZE < fileData_.size())
      ? HEADER_SEARCH_SIZE
      : fileData_.size();

    for (size_t i = 0; i + MIN_PACK_HEADER_SIZE <= searchSize; i++) {
      if (fileData_[i] == 'U' && fileData_[i + 1] == 'P' &&
        fileData_[i + 2] == 'X' && fileData_[i + 3] == '!') {

        XUPX::INTERNAL_INFO info =
          readPackHeader(fileData_.data() + i, PACK_HEADER_SIZE, false);

        if (isPackHeaderValid(info)) {
          info.nHeaderOffset = static_cast<int64_t>(i);
          info.nDataOffset = static_cast<int64_t>(i + info.nPackHeaderSize);
          *pInfo = info;
          return true;
        }
      }
    }
    return false;
  }

  bool DecompressPayload(Item& item) {
    if (!info_.c_len || !info_.u_len) {
      item.statusNote = "empty compressed/uncompressed length";
      return false;
    }
    if (static_cast<size_t>(info_.nDataOffset) + info_.c_len > fileData_.size()) {
      item.statusNote = "compressed data runs past end of file";
      return false;
    }

    const uint8_t* pSrc = fileData_.data() + info_.nDataOffset;
    uint32_t srcSize = info_.c_len;
    size_t expected = info_.u_len;

    switch (info_.method) {
    case XUPX::UPX_M_LZMA: {
      if (srcSize < 3) { item.statusNote = "LZMA payload too short"; return false; }
      uint8_t pb = pSrc[0] & 7;
      uint8_t lp = pSrc[1] >> 4;
      uint8_t lc = pSrc[1] & 0x0F;
      if (pb >= 5 || lp >= 5 || lc >= 9) { item.statusNote = "bad LZMA props"; return false; }
      if ((pSrc[0] >> 3) != (lc + lp)) { item.statusNote = "LZMA props checksum mismatch"; return false; }

      bool ok = UpxSdkCodecs::LzmaDecodeRaw(pSrc + 2, srcSize - 2, lc, lp, pb, item.data, expected);
      if (!ok) item.statusNote = "SDK LZMA decode failed";
      return ok;
    }
    case XUPX::UPX_M_DEFLATE: {
      bool ok = UpxSdkCodecs::DeflateDecodeRaw(pSrc, srcSize, item.data, expected);
      if (!ok) item.statusNote = "SDK Deflate decode failed";
      return ok;
    }
    case XUPX::UPX_M_NRV2B_LE32:
    case XUPX::UPX_M_NRV2B_8:
    case XUPX::UPX_M_NRV2B_LE16:
    case XUPX::UPX_M_NRV2D_LE32:
    case XUPX::UPX_M_NRV2D_8:
    case XUPX::UPX_M_NRV2D_LE16:
    case XUPX::UPX_M_NRV2E_LE32:
    case XUPX::UPX_M_NRV2E_8:
    case XUPX::UPX_M_NRV2E_LE16:
      item.statusNote = "NRV2x (UCL) method not supported - SDK has no UCL decoder";
      return false;
    default:
      item.statusNote = "unknown UPX method";
      return false;
    }
  }

  void TryReconstructPE(Item& item) {
    UpxPE::UnpackPEParams params;
    params.packedFile = &fileData_;
    params.payload = &item.data;
    params.filter = info_.filter;
    params.filterCTO = info_.filter_cto;
    params.applyFilter = [](uint8_t* pData, int64_t nDataSize, uint8_t nFilter,
      uint8_t nFilterCTO, uint32_t nAddValue) {
        return ApplyPEFilterStatic(pData, nDataSize, nFilter, nFilterCTO, nAddValue);
      };

    std::vector<uint8_t> reconstructed;
    if (UpxPE::unpackPE(params, &reconstructed)) {
      item.data.swap(reconstructed);
    }
  }

  static bool ApplyPEFilterStatic(uint8_t* pData, int64_t nDataSize, uint8_t nFilter,
    uint8_t /*nFilterCTO*/, uint32_t nAddValue) {
    if (!pData || nDataSize <= 0) return false;
    if (nFilter == 0) return true;

    auto rd32be = [](const uint8_t* p) {
      return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
        (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
      };
    auto wr32be = [](uint8_t* p, uint32_t v) {
      p[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
      p[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
      p[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
      p[3] = static_cast<uint8_t>(v & 0xFF);
      };

    if (nFilter == 0x14) {
      for (int64_t i = 0; i < nDataSize - 5; i++) {
        if (pData[i] == 0xe8) {
          uint32_t jc = rd32be(pData + i + 1);
          wr32be(pData + i + 1, jc - static_cast<uint32_t>(i) - 1 - nAddValue);
          i += 4;
        }
      }
    }
    else if (nFilter == 0x16) {
      for (int64_t i = 0; i < nDataSize - 5; i++) {
        if (pData[i] == 0xe8 || pData[i] == 0xe9) {
          uint32_t jc = rd32be(pData + i + 1);
          wr32be(pData + i + 1, jc - static_cast<uint32_t>(i) - 1 - nAddValue);
          i += 4;
        }
      }
    }
    return true;
  }
};
