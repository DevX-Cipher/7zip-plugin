#pragma once
#include <windows.h>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <string>
#include "PS3_PKG_Crypto.h"

// ---------------------------------------------------------------------
// PS3 PKG constants
// ---------------------------------------------------------------------
#define PKG_MAGIC_PS3 0x7F504B47  // PS3 PKG
#define PS3_SELF      0x53434500

enum PKG_TYPE {
  PKG_TYPE_PS3 = 0x0001,
  PKG_TYPE_PSP = 0x0002,
  PKG_TYPE_PSV = 0x0003,
  PKG_TYPE_PSM = 0x0004
};

enum PKG_ENTRY_TYPE {
  ENTRY_TYPE_NPDRM = 0x1,
  ENTRY_TYPE_NPDRMEDAT = 0x3,
  ENTRY_TYPE_REGULAR = 0x4,
  ENTRY_TYPE_FOLDER = 0x5,
};

// ---------------------------------------------------------------------
// PS3 PKG header (packed)
// ---------------------------------------------------------------------
#pragma pack(push, 1)
struct PKG_HEADER_PS3 {
  uint32_t magic;                // 0x00
  uint16_t pkg_revision;         // 0x04
  uint16_t pkg_type;             // 0x06
  uint32_t pkg_metadata_offset;  // 0x08
  uint32_t pkg_metadata_count;   // 0x0C
  uint32_t pkg_metadata_size;    // 0x10
  uint32_t item_count;           // 0x14
  uint64_t total_size;           // 0x18
  uint64_t data_offset;          // 0x20
  uint64_t data_size;            // 0x28
  char     content_id[0x30];     // 0x30
  uint8_t  digest[0x10];         // 0x60
  uint8_t  pkg_data_riv[0x10];   // 0x70
};

struct PKG_FILE_ENTRY_PS3 {
  uint32_t name_offset;
  uint32_t name_size;
  uint64_t data_offset;
  uint64_t data_size;
  uint32_t flags;
  uint32_t padding;
};
#pragma pack(pop)

// ---------------------------------------------------------------------
// PS3 PKG Handler Class
// ---------------------------------------------------------------------
class PS3PKGHandler {
private:
  PKG_HEADER_PS3 header = {};
  bool isEncrypted = false;

  uint32_t SwapEndian32(uint32_t v) { return _byteswap_ulong(v); }
  uint64_t SwapEndian64(uint64_t v) { return _byteswap_uint64(v); }
  uint16_t SwapEndian16(uint16_t v) { return _byteswap_ushort(v); }

  void DecryptData(uint8_t* data, size_t size, uint64_t relativeOffset) {
    if (!isEncrypted || size == 0) return;
    try {
      PS3Crypto::DecryptPS3PKG(
        data,
        size,
        relativeOffset,
        header.digest,
        header.pkg_type
      );
    }
    catch (...) {
      // Decryption failed
    }
  }

  HRESULT ReadAndDecryptBlock(
    IInStream* stream,
    UInt64 absOffset,
    size_t size,
    std::vector<uint8_t>& buf)
  {
    buf.resize(size);
    UInt32 read = 0;

    RINOK(stream->Seek(absOffset, STREAM_SEEK_SET, nullptr));
    RINOK(stream->Read(buf.data(), static_cast<UInt32>(size), &read));
    if (read != size) return E_FAIL;

    if (isEncrypted) {
      uint64_t rel = absOffset - header.data_offset;
      DecryptData(buf.data(), size, rel);
    }

    return S_OK;
  }

public:
  struct FileInfo {
    uint64_t  offset = 0;
    uint64_t  size = 0;
    uint32_t  flags = 0;
    uint32_t  type = 0;
    std::string path;
    std::vector<uint8_t> fileData;
    bool      isFolder = false;
    int64_t   fileTime1 = 0;
    int64_t   fileTime2 = 0;
    int64_t   fileTime3 = 0;
  };

  HRESULT ParseHeader(IInStream* stream) {
    RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));

    UInt32 read = 0;

    RINOK(stream->Read(&header.magic, 4, &read));
    header.magic = SwapEndian32(header.magic);
    if (header.magic != PKG_MAGIC_PS3) return E_FAIL;

    RINOK(stream->Read(&header.pkg_revision, 2, &read));
    header.pkg_revision = SwapEndian16(header.pkg_revision);

    RINOK(stream->Read(&header.pkg_type, 2, &read));
    header.pkg_type = SwapEndian16(header.pkg_type);

    RINOK(stream->Read(&header.pkg_metadata_offset, 4, &read));
    header.pkg_metadata_offset = SwapEndian32(header.pkg_metadata_offset);

    RINOK(stream->Read(&header.pkg_metadata_count, 4, &read));
    header.pkg_metadata_count = SwapEndian32(header.pkg_metadata_count);

    RINOK(stream->Read(&header.pkg_metadata_size, 4, &read));
    header.pkg_metadata_size = SwapEndian32(header.pkg_metadata_size);

    RINOK(stream->Read(&header.item_count, 4, &read));
    header.item_count = SwapEndian32(header.item_count);

    RINOK(stream->Read(&header.total_size, 8, &read));
    header.total_size = SwapEndian64(header.total_size);

    RINOK(stream->Read(&header.data_offset, 8, &read));
    header.data_offset = SwapEndian64(header.data_offset);

    RINOK(stream->Read(&header.data_size, 8, &read));
    header.data_size = SwapEndian64(header.data_size);

    RINOK(stream->Read(header.content_id, 0x30, nullptr));
    header.content_id[0x2F] = '\0';

    RINOK(stream->Read(header.digest, 0x10, nullptr));
    RINOK(stream->Read(header.pkg_data_riv, 0x10, nullptr));

    isEncrypted = (header.pkg_type == PKG_TYPE_PS3);
    return S_OK;
  }

  HRESULT ParseFileTable(IInStream* stream, std::vector<FileInfo>& items) {
    uint64_t tableStart = header.data_offset;
    std::vector<uint8_t> sizeBuf;

    RINOK(ReadAndDecryptBlock(stream, tableStart, 32, sizeBuf));

    uint64_t tableSize1 = SwapEndian64(*(uint64_t*)(sizeBuf.data() + 8));
    uint64_t tableSize2 = SwapEndian64(*(uint64_t*)(sizeBuf.data() + 16));

    uint64_t tableSize = (tableSize2 > 0 && tableSize2 < header.data_size) ? tableSize2 : tableSize1;

    if (tableSize == 0 || tableSize > header.data_size) return E_FAIL;

    std::vector<uint8_t> tableData;
    RINOK(ReadAndDecryptBlock(stream, tableStart, tableSize, tableData));

    const size_t ENTRY_SIZE = 32;
    size_t nameReadOffset = header.item_count * ENTRY_SIZE;

    for (uint32_t i = 0; i < header.item_count; i++) {
      size_t entryPos = i * ENTRY_SIZE;

      if (entryPos + ENTRY_SIZE > tableData.size()) break;

      const uint8_t* p = tableData.data() + entryPos;

      uint32_t nameLen = SwapEndian32(*(uint32_t*)(p + 0x04));
      uint64_t dataOff = SwapEndian64(*(uint64_t*)(p + 0x08));
      uint64_t dataSz = SwapEndian64(*(uint64_t*)(p + 0x10));
      uint32_t flags = SwapEndian32(*(uint32_t*)(p + 0x18));

      if (nameLen == 0 || nameLen > 4096) continue;
      if (dataOff > header.data_size) continue;

      FileInfo fi;
      fi.offset = header.data_offset + dataOff;
      fi.size = dataSz;
      fi.flags = flags;
      fi.type = (flags >> 24) & 0xFF;
      fi.isFolder = (fi.type == ENTRY_TYPE_FOLDER);

      if (nameReadOffset < tableData.size() && nameReadOffset + nameLen <= tableData.size()) {
        const char* namePtr = reinterpret_cast<const char*>(tableData.data() + nameReadOffset);
        fi.path.assign(namePtr, nameLen);
        size_t nul = fi.path.find('\0');
        if (nul != std::string::npos) fi.path.resize(nul);
        std::replace(fi.path.begin(), fi.path.end(), '\\', '/');
      }
      else {
        fi.path = "file_" + std::to_string(i);
      }

      items.push_back(std::move(fi));

      nameReadOffset += nameLen;
      while (nameReadOffset % 16 != 0) nameReadOffset++;
    }

    return S_OK;
  }

  HRESULT ExtractFileData(IInStream* stream, FileInfo& fi) {
    if (fi.isFolder || fi.size == 0) return S_OK;

    fi.fileData.resize(fi.size);
    UInt32 read = 0;
    RINOK(stream->Seek(fi.offset, STREAM_SEEK_SET, nullptr));
    RINOK(stream->Read(fi.fileData.data(), static_cast<UInt32>(fi.size), &read));
    if (read != fi.size) return E_FAIL;

    if (isEncrypted) {
      uint64_t rel = fi.offset - header.data_offset;
      DecryptData(fi.fileData.data(), fi.size, rel);
    }
    return S_OK;
  }

  const PKG_HEADER_PS3& GetHeader() const { return header; }
  bool IsEncrypted() const { return isEncrypted; }
};