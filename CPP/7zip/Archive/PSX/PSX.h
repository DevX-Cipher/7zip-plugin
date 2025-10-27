#define NOMINMAX
#include <windows.h>
#undef min
#undef max
#include <algorithm>
#include <vector>
#include <string>
#include <sstream>
#include <cstdint>
#include <map>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <ctime>
#include <chrono>
#include <shlobj.h>
#include "PS3_PKG_Crypto.h"

// ---------------------------------------------------------------------
// Debug logging
// ---------------------------------------------------------------------
#ifdef _DEBUG
#define LOG(msg) logDebug(msg)
static void logDebug(const std::string& message);
#else
#define LOG(msg)
#endif

// ---------------------------------------------------------------------
// PKG constants
// ---------------------------------------------------------------------
#define PKG_MAGIC_PS3 0x7F504B47  // PS3 PKG
#define PKG_MAGIC_PS4 0x7F434E54  // PS4 PKG (.CNT)

enum PKG_FORMAT {
  PKG_FORMAT_UNKNOWN = 0,
  PKG_FORMAT_PS3 = 1,
  PKG_FORMAT_PS4 = 2
};

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

// PS4 PKG entry types
enum PS4_PKG_ENTRY_TYPES {
  PS4_PKG_ENTRY_TYPE_DIGEST_TABLE = 0x0001,
  PS4_PKG_ENTRY_TYPE_0x800 = 0x0010,
  PS4_PKG_ENTRY_TYPE_0x200 = 0x0020,
  PS4_PKG_ENTRY_TYPE_0x180 = 0x0080,
  PS4_PKG_ENTRY_TYPE_META_TABLE = 0x0100,
  PS4_PKG_ENTRY_TYPE_NAME_TABLE = 0x0200,
  PS4_PKG_ENTRY_TYPE_LICENSE = 0x0400,
  PS4_PKG_ENTRY_TYPE_FILE1 = 0x1000,
  PS4_PKG_ENTRY_TYPE_FILE2 = 0x1200
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

// ---------------------------------------------------------------------
// PS4 PKG header (packed)
// ---------------------------------------------------------------------
struct PKG_HEADER_PS4 {
  uint32_t magic;                    // 0x00
  uint32_t type;                     // 0x04
  uint32_t unk_0x08;                 // 0x08
  uint32_t unk_0x0C;                 // 0x0C
  uint16_t unk1_entries_num;         // 0x10
  uint16_t table_entries_num;        // 0x12
  uint16_t system_entries_num;       // 0x14
  uint16_t unk2_entries_num;         // 0x16
  uint32_t file_table_offset;        // 0x18
  uint32_t main_entries_data_size;   // 0x1C
  uint32_t unk_0x20;                 // 0x20
  uint32_t body_offset;              // 0x24
  uint32_t unk_0x28;                 // 0x28
  uint32_t body_size;                // 0x2C
  uint8_t  unk_0x30[0x10];           // 0x30
  uint8_t  content_id[0x30];         // 0x40
  uint32_t unk_0x70;                 // 0x70
  uint32_t unk_0x74;                 // 0x74
  uint32_t unk_0x78;                 // 0x78
  uint32_t unk_0x7C;                 // 0x7C
  uint32_t date;                     // 0x80
  uint32_t time;                     // 0x84
  uint32_t unk_0x88;                 // 0x88
  uint32_t unk_0x8C;                 // 0x8C
  uint8_t  unk_0x90[0x70];           // 0x90
  uint8_t  main_entries1_digest[0x20];     // 0x100
  uint8_t  main_entries2_digest[0x20];     // 0x120
  uint8_t  digest_table_digest[0x20];      // 0x140
  uint8_t  body_digest[0x20];              // 0x160
};

struct PKG_CONTENT_HEADER_PS4 {
  uint32_t unk_0x400;                // 0x400
  uint32_t unk_0x404;                // 0x404
  uint32_t unk_0x408;                // 0x408
  uint32_t unk_0x40C;                // 0x40C
  uint32_t unk_0x410;                // 0x410
  uint32_t content_offset;           // 0x414
  uint32_t unk_0x418;                // 0x418
  uint32_t content_size;             // 0x41C
  uint32_t unk_0x420;                // 0x420
  uint32_t unk_0x424;                // 0x424
  uint32_t unk_0x428;                // 0x428
  uint32_t unk_0x42C;                // 0x42C
  uint32_t unk_0x430;                // 0x430
  uint32_t unk_0x434;                // 0x434
  uint32_t unk_0x438;                // 0x438
  uint32_t unk_0x43C;                // 0x43C
  uint8_t  content_digest[0x20];     // 0x440
  uint8_t  content_one_block_digest[0x20]; // 0x460
};

struct PKG_TABLE_ENTRY_PS4 {
  uint32_t type;
  uint32_t unk1;
  uint32_t flags1;
  uint32_t flags2;
  uint32_t offset;
  uint32_t size;
  uint32_t unk2;
  uint32_t unk3;
};

#pragma pack(pop)


// ---------------------------------------------------------------------
// Unified Handler class
// ---------------------------------------------------------------------
class UnifiedPKGHandler {
  UInt64      archiveSize = 0;
  PKG_FORMAT  pkgFormat = PKG_FORMAT_UNKNOWN;

  // PS3 structures
  PKG_HEADER_PS3  ps3Header = {};
  bool            isPS3Encrypted = false;

  // PS4 structures
  PKG_HEADER_PS4  ps4Header = {};
  PKG_CONTENT_HEADER_PS4 ps4ContentHeader = {};

public:
  // -----------------------------------------------------------------
  // File entry description (unified for both formats)
  // -----------------------------------------------------------------
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

    FileInfo() = default;
  };

  std::vector<FileInfo> items;
  CMyComPtr<IArchiveOpenVolumeCallback> volCallback;

  HRESULT Open(IInStream* stream, const UInt64* fileSize, IArchiveOpenCallback* callback);
  HRESULT DetectFormat(IInStream* stream);

  // PS3 methods
  HRESULT ParsePS3PKGHeader(IInStream* stream);
  HRESULT ParsePS3FileTable(IInStream* stream);
  HRESULT ExtractPS3FileData(IInStream* stream, FileInfo& fi);

  // PS4 methods
  HRESULT ParsePS4PKGHeader(IInStream* stream);
  HRESULT ParsePS4FileTable(IInStream* stream);
  HRESULT ExtractPS4FileData(IInStream* stream, FileInfo& fi);

  // SFO EDITOR INTEGRATION
  HRESULT EditSFOFile(FileInfo& sfoFile);

  PKG_FORMAT GetFormat() const { return pkgFormat; }
  const PKG_HEADER_PS3& GetPS3Header() const { return ps3Header; }
  const PKG_HEADER_PS4& GetPS4Header() const { return ps4Header; }

private:
  HRESULT ReadBytes(IInStream* stream, void* buffer, uint32_t size);
  uint32_t SwapEndian32(uint32_t v) { return _byteswap_ulong(v); }
  uint64_t SwapEndian64(uint64_t v) { return _byteswap_uint64(v); }
  uint16_t SwapEndian16(uint16_t v) { return _byteswap_ushort(v); }
  void DecryptPS3Data(uint8_t* data, size_t size, uint64_t relativeOffset);
  const char* GetPS4EntryName(uint32_t type);
};

// ---------------------------------------------------------------------
// Read helpers
// ---------------------------------------------------------------------
static HRESULT readUint16BE(IInStream* stream, uint16_t* value) {
  UInt32 read = 0;
  HRESULT hr = stream->Read(value, 2, &read);
  if (SUCCEEDED(hr) && read == 2) *value = _byteswap_ushort(*value);
  return hr;
}

static HRESULT readUint32BE(IInStream* stream, uint32_t* value) {
  UInt32 read = 0;
  HRESULT hr = stream->Read(value, 4, &read);
  if (SUCCEEDED(hr) && read == 4) *value = _byteswap_ulong(*value);
  return hr;
}

static HRESULT readUint64BE(IInStream* stream, uint64_t* value) {
  UInt32 read = 0;
  HRESULT hr = stream->Read(value, 8, &read);
  if (SUCCEEDED(hr) && read == 8) *value = _byteswap_uint64(*value);
  return hr;
}

// ---------------------------------------------------------------------
// Debug logger
// ---------------------------------------------------------------------
#ifdef _DEBUG
static void logDebug(const std::string& message) {
  static std::string logPath;
  if (logPath.empty()) {
    wchar_t desktop[MAX_PATH] = {};
    SHGetFolderPathW(nullptr, CSIDL_DESKTOP, nullptr, 0, desktop);
    std::wstring wpath = std::wstring(desktop) + L"\\unified_pkg_debug.log";
    int sz = WideCharToMultiByte(CP_UTF8, 0, wpath.c_str(), -1, nullptr, 0, nullptr, nullptr);
    logPath.resize(sz - 1);
    WideCharToMultiByte(CP_UTF8, 0, wpath.c_str(), -1, &logPath[0], sz - 1, nullptr, nullptr);
  }
  std::ofstream f(logPath, std::ios::app);
  auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  char t[64]; ctime_s(t, 64, &now); t[strcspn(t, "\n")] = 0;
  f << "[" << t << "] " << message << "\n";
}
#endif

// =====================================================================
// SFO EDITOR IMPLEMENTATION
// =====================================================================


// ---------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------
HRESULT UnifiedPKGHandler::DetectFormat(IInStream* stream) {
  uint32_t magic;
  RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));
  RINOK(readUint32BE(stream, &magic));

  if (magic == PKG_MAGIC_PS3) {
    pkgFormat = PKG_FORMAT_PS3;
    LOG("Detected PS3 PKG format");
    return S_OK;
  }
  else if (magic == PKG_MAGIC_PS4) {
    pkgFormat = PKG_FORMAT_PS4;
    LOG("Detected PS4 PKG format");
    return S_OK;
  }

  LOG("Unknown PKG format - magic: 0x" + std::to_string(magic));
  return E_FAIL;
}

// =====================================================================
// PS3 PKG IMPLEMENTATION
// =====================================================================

void UnifiedPKGHandler::DecryptPS3Data(uint8_t* data, size_t size, uint64_t relativeOffset) {
  if (!isPS3Encrypted || size == 0) return;
  try {
    PS3Crypto::DecryptPS3PKG(
      data,
      size,
      relativeOffset,
      ps3Header.digest,
      ps3Header.pkg_type
    );
    LOG("PS3: Decrypted " + std::to_string(size) + " bytes @ rel:0x" +
      std::to_string(relativeOffset));
  }
  catch (...) {
    LOG("PS3: Decrypt FAILED @ rel:0x" + std::to_string(relativeOffset));
  }
}

static HRESULT ReadAndDecryptPS3Block(
  IInStream* stream,
  UInt64 absOffset,
  size_t size,
  std::vector<uint8_t>& buf,
  bool encrypted,
  const PKG_HEADER_PS3& hdr)
{
  buf.resize(size);
  UInt32 read = 0;

  RINOK(stream->Seek(absOffset, STREAM_SEEK_SET, nullptr));
  RINOK(stream->Read(buf.data(), static_cast<UInt32>(size), &read));
  if (read != size) {
    LOG("PS3: Short read: " + std::to_string(read) + "/" + std::to_string(size));
    return E_FAIL;
  }

  if (encrypted) {
    uint64_t rel = absOffset - hdr.data_offset;
    try {
      PS3Crypto::DecryptPS3PKG(
        buf.data(),
        size,
        rel,
        hdr.digest,
        hdr.pkg_type
      );
      LOG("PS3: Decrypt block abs:0x" + std::to_string(absOffset) +
        " rel:0x" + std::to_string(rel) +
        " size:" + std::to_string(size));
    }
    catch (...) {
      LOG("PS3: DECRYPTION FAILED!");
      return E_FAIL;
    }
  }

  return S_OK;
}

HRESULT UnifiedPKGHandler::ParsePS3PKGHeader(IInStream* stream) {
  RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));
  RINOK(readUint32BE(stream, &ps3Header.magic));
  if (ps3Header.magic != PKG_MAGIC_PS3) {
    LOG("PS3: Invalid magic 0x" + std::to_string(ps3Header.magic));
    return E_FAIL;
  }

  RINOK(readUint16BE(stream, &ps3Header.pkg_revision));
  RINOK(readUint16BE(stream, &ps3Header.pkg_type));
  RINOK(readUint32BE(stream, &ps3Header.pkg_metadata_offset));
  RINOK(readUint32BE(stream, &ps3Header.pkg_metadata_count));
  RINOK(readUint32BE(stream, &ps3Header.pkg_metadata_size));
  RINOK(readUint32BE(stream, &ps3Header.item_count));
  RINOK(readUint64BE(stream, &ps3Header.total_size));
  RINOK(readUint64BE(stream, &ps3Header.data_offset));
  RINOK(readUint64BE(stream, &ps3Header.data_size));
  RINOK(stream->Read(ps3Header.content_id, 0x30, nullptr));
  ps3Header.content_id[0x2F] = '\0';
  RINOK(stream->Read(ps3Header.digest, 0x10, nullptr));
  RINOK(stream->Read(ps3Header.pkg_data_riv, 0x10, nullptr));

  isPS3Encrypted = (ps3Header.pkg_type == PKG_TYPE_PS3);
  LOG("PS3: Header OK | Items:" + std::to_string(ps3Header.item_count) +
    " | Data @0x" + std::to_string(ps3Header.data_offset) +
    " | Size:" + std::to_string(ps3Header.data_size) +
    " | Encrypted:" + (isPS3Encrypted ? "YES" : "NO"));
  return S_OK;
}

HRESULT UnifiedPKGHandler::ParsePS3FileTable(IInStream* stream) {
  LOG("PS3: Parsing file table...");

  uint64_t tableStart = ps3Header.data_offset;
  std::vector<uint8_t> sizeBuf;

  RINOK(ReadAndDecryptPS3Block(stream, tableStart, 32, sizeBuf, isPS3Encrypted, ps3Header));

  uint64_t tableSize1 = SwapEndian64(*(uint64_t*)(sizeBuf.data() + 8));
  uint64_t tableSize2 = SwapEndian64(*(uint64_t*)(sizeBuf.data() + 16));

  uint64_t tableSize = (tableSize2 > 0 && tableSize2 < ps3Header.data_size) ? tableSize2 : tableSize1;

  if (tableSize == 0 || tableSize > ps3Header.data_size) {
    LOG("PS3: ERROR: Invalid table size!");
    return E_FAIL;
  }

  LOG("PS3: Using table size: " + std::to_string(tableSize) + " bytes");

  std::vector<uint8_t> tableData;
  RINOK(ReadAndDecryptPS3Block(stream, tableStart, tableSize, tableData, isPS3Encrypted, ps3Header));

  const size_t ENTRY_SIZE = 32;
  size_t nameReadOffset = ps3Header.item_count * ENTRY_SIZE;

  LOG("PS3: Parsing " + std::to_string(ps3Header.item_count) + " entries");

  for (uint32_t i = 0; i < ps3Header.item_count; i++) {
    size_t entryPos = i * ENTRY_SIZE;

    if (entryPos + ENTRY_SIZE > tableData.size()) {
      LOG("PS3: Entry " + std::to_string(i) + ": out of bounds");
      break;
    }

    const uint8_t* p = tableData.data() + entryPos;

    uint32_t nameLen = SwapEndian32(*(uint32_t*)(p + 0x04));
    uint64_t dataOff = SwapEndian64(*(uint64_t*)(p + 0x08));
    uint64_t dataSz = SwapEndian64(*(uint64_t*)(p + 0x10));
    uint32_t flags = SwapEndian32(*(uint32_t*)(p + 0x18));

    if (nameLen == 0 || nameLen > 4096) continue;
    if (dataOff > ps3Header.data_size) continue;

    FileInfo fi;
    fi.offset = ps3Header.data_offset + dataOff;
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

  LOG("PS3: Successfully parsed " + std::to_string(items.size()) + " entries");
  return S_OK;
}

HRESULT UnifiedPKGHandler::ExtractPS3FileData(IInStream* stream, FileInfo& fi) {
  if (fi.isFolder || fi.size == 0) return S_OK;

  fi.fileData.resize(fi.size);
  UInt32 read = 0;
  RINOK(stream->Seek(fi.offset, STREAM_SEEK_SET, nullptr));
  RINOK(stream->Read(fi.fileData.data(), static_cast<UInt32>(fi.size), &read));
  if (read != fi.size) return E_FAIL;

  if (isPS3Encrypted) {
    uint64_t rel = fi.offset - ps3Header.data_offset;
    DecryptPS3Data(fi.fileData.data(), fi.size, rel);
  }
  return S_OK;
}

// =====================================================================
// PS4 PKG IMPLEMENTATION
// =====================================================================

const char* UnifiedPKGHandler::GetPS4EntryName(uint32_t type) {
  switch (type) {
  case 0x0001: return "digest_table.bin";
  case 0x0010: return "entry_keys.bin";
  case 0x0020: return "image_key.bin";
  case 0x0080: return "general_digests.bin";
  case 0x0100: return "metas.bin";
  case 0x0200: return "entry_names.bin";
  case 0x0400: return "license.dat";
  case 0x0401: return "license.info";
  case 0x1000: return "param.sfo";
  case 0x1001: return "playgo-chunk.dat";
  case 0x1002: return "playgo-chunk.sha";
  case 0x1003: return "playgo-manifest.xml";
  case 0x1004: return "pronunciation.xml";
  case 0x1005: return "pronunciation.sig";
  case 0x1006: return "pic1.png";
  case 0x1008: return "app/playgo-chunk.dat";
  case 0x1200: return "icon0.png";
  case 0x1220: return "pic0.png";
  case 0x1240: return "snd0.at9";
  case 0x1260: return "changeinfo/changeinfo.xml";
  default: return nullptr;
  }
}

HRESULT UnifiedPKGHandler::ParsePS4PKGHeader(IInStream* stream) {
  RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));

  // Read main header (0x180 bytes)
  RINOK(readUint32BE(stream, &ps4Header.magic));
  if (ps4Header.magic != PKG_MAGIC_PS4) {
    LOG("PS4: Invalid magic 0x" + std::to_string(ps4Header.magic));
    return E_FAIL;
  }

  RINOK(readUint32BE(stream, &ps4Header.type));
  RINOK(readUint32BE(stream, &ps4Header.unk_0x08));
  RINOK(readUint32BE(stream, &ps4Header.unk_0x0C));
  RINOK(readUint16BE(stream, &ps4Header.unk1_entries_num));
  RINOK(readUint16BE(stream, &ps4Header.table_entries_num));
  RINOK(readUint16BE(stream, &ps4Header.system_entries_num));
  RINOK(readUint16BE(stream, &ps4Header.unk2_entries_num));
  RINOK(readUint32BE(stream, &ps4Header.file_table_offset));
  RINOK(readUint32BE(stream, &ps4Header.main_entries_data_size));
  RINOK(readUint32BE(stream, &ps4Header.unk_0x20));
  RINOK(readUint32BE(stream, &ps4Header.body_offset));
  RINOK(readUint32BE(stream, &ps4Header.unk_0x28));
  RINOK(readUint32BE(stream, &ps4Header.body_size));

  RINOK(stream->Read(ps4Header.unk_0x30, 0x10, nullptr));
  RINOK(stream->Read(ps4Header.content_id, 0x30, nullptr));
  ps4Header.content_id[0x2F] = '\0';

  RINOK(readUint32BE(stream, &ps4Header.unk_0x70));
  RINOK(readUint32BE(stream, &ps4Header.unk_0x74));
  RINOK(readUint32BE(stream, &ps4Header.unk_0x78));
  RINOK(readUint32BE(stream, &ps4Header.unk_0x7C));
  RINOK(readUint32BE(stream, &ps4Header.date));
  RINOK(readUint32BE(stream, &ps4Header.time));
  RINOK(readUint32BE(stream, &ps4Header.unk_0x88));
  RINOK(readUint32BE(stream, &ps4Header.unk_0x8C));

  RINOK(stream->Read(ps4Header.unk_0x90, 0x70, nullptr));
  RINOK(stream->Read(ps4Header.main_entries1_digest, 0x20, nullptr));
  RINOK(stream->Read(ps4Header.main_entries2_digest, 0x20, nullptr));
  RINOK(stream->Read(ps4Header.digest_table_digest, 0x20, nullptr));
  RINOK(stream->Read(ps4Header.body_digest, 0x20, nullptr));

  // Read content header at 0x400
  RINOK(stream->Seek(0x400, STREAM_SEEK_SET, nullptr));
  RINOK(readUint32BE(stream, &ps4ContentHeader.unk_0x400));
  RINOK(readUint32BE(stream, &ps4ContentHeader.unk_0x404));
  RINOK(readUint32BE(stream, &ps4ContentHeader.unk_0x408));
  RINOK(readUint32BE(stream, &ps4ContentHeader.unk_0x40C));
  RINOK(readUint32BE(stream, &ps4ContentHeader.unk_0x410));
  RINOK(readUint32BE(stream, &ps4ContentHeader.content_offset));
  RINOK(readUint32BE(stream, &ps4ContentHeader.unk_0x418));
  RINOK(readUint32BE(stream, &ps4ContentHeader.content_size));
  RINOK(stream->Seek(0x440, STREAM_SEEK_SET, nullptr));
  RINOK(stream->Read(ps4ContentHeader.content_digest, 0x20, nullptr));
  RINOK(stream->Read(ps4ContentHeader.content_one_block_digest, 0x20, nullptr));

  LOG("PS4: Header OK | Entries:" + std::to_string(ps4Header.table_entries_num) +
    " | Table @0x" + std::to_string(ps4Header.file_table_offset) +
    " | Content @0x" + std::to_string(ps4ContentHeader.content_offset) +
    " | Content Size:" + std::to_string(ps4ContentHeader.content_size));

  return S_OK;
}

HRESULT UnifiedPKGHandler::ParsePS4FileTable(IInStream* stream) {
  LOG("PS4: Parsing file table...");

  // Read table entries
  RINOK(stream->Seek(ps4Header.file_table_offset, STREAM_SEEK_SET, nullptr));

  std::vector<PKG_TABLE_ENTRY_PS4> entries(ps4Header.table_entries_num);
  std::vector<std::string> nameTable;

  // Read all entries
  for (uint16_t i = 0; i < ps4Header.table_entries_num; i++) {
    RINOK(readUint32BE(stream, &entries[i].type));
    RINOK(readUint32BE(stream, &entries[i].unk1));
    RINOK(readUint32BE(stream, &entries[i].flags1));
    RINOK(readUint32BE(stream, &entries[i].flags2));
    RINOK(readUint32BE(stream, &entries[i].offset));
    RINOK(readUint32BE(stream, &entries[i].size));
    RINOK(readUint32BE(stream, &entries[i].unk2));
    RINOK(readUint32BE(stream, &entries[i].unk3));

    LOG("PS4: Entry[" + std::to_string(i) + "] type=0x" +
      std::to_string(entries[i].type) + " offset=0x" +
      std::to_string(entries[i].offset) + " size=" +
      std::to_string(entries[i].size));
  }

  // Find and parse name table
  for (uint16_t i = 0; i < ps4Header.table_entries_num; i++) {
    if (entries[i].type == PS4_PKG_ENTRY_TYPE_NAME_TABLE) {
      LOG("PS4: Found name table at 0x" + std::to_string(entries[i].offset));
      RINOK(stream->Seek(entries[i].offset + 1, STREAM_SEEK_SET, nullptr));

      std::vector<uint8_t> nameData(entries[i].size);
      UInt32 read = 0;
      RINOK(stream->Read(nameData.data(), entries[i].size, &read));

      // Parse null-terminated strings
      size_t pos = 0;
      while (pos < nameData.size()) {
        const char* str = reinterpret_cast<const char*>(nameData.data() + pos);
        size_t len = strnlen(str, nameData.size() - pos);
        if (len == 0) break;
        nameTable.push_back(std::string(str, len));
        LOG("PS4: Name[" + std::to_string(nameTable.size() - 1) + "]: " + nameTable.back());
        pos += len + 1;
      }
      break;
    }
  }

  // Create file entries
  int fileIndex = 0;
  int unknownCount = 0;

  for (uint16_t i = 0; i < ps4Header.table_entries_num; i++) {
    FileInfo fi;
    fi.offset = entries[i].offset;
    fi.size = entries[i].size;
    fi.type = entries[i].type;
    fi.flags = entries[i].flags1;
    fi.isFolder = false;

    // Check if this is a file entry
    bool isFile = ((entries[i].type & PS4_PKG_ENTRY_TYPE_FILE1) == PS4_PKG_ENTRY_TYPE_FILE1) ||
      ((entries[i].type & PS4_PKG_ENTRY_TYPE_FILE2) == PS4_PKG_ENTRY_TYPE_FILE2);

    // Get name
    const char* predefinedName = GetPS4EntryName(entries[i].type);
    if (predefinedName != nullptr) {
      fi.path = predefinedName;
    }
    else if (isFile && fileIndex < nameTable.size()) {
      fi.path = nameTable[fileIndex];
    }
    else {
      fi.path = "unknown_entry_0x" + std::to_string(entries[i].type) + "_" +
        std::to_string(unknownCount++) + ".bin";
    }

    if (isFile) fileIndex++;

    // Normalize path
    std::replace(fi.path.begin(), fi.path.end(), '\\', '/');

    LOG("PS4: Added entry: " + fi.path);
    items.push_back(std::move(fi));
  }

  LOG("PS4: Successfully parsed " + std::to_string(items.size()) + " entries");
  return S_OK;
}

HRESULT UnifiedPKGHandler::ExtractPS4FileData(IInStream* stream, FileInfo& fi) {
  if (fi.isFolder || fi.size == 0) return S_OK;

  fi.fileData.resize(fi.size);
  UInt32 read = 0;
  RINOK(stream->Seek(fi.offset, STREAM_SEEK_SET, nullptr));
  RINOK(stream->Read(fi.fileData.data(), static_cast<UInt32>(fi.size), &read));
  if (read != fi.size) {
    LOG("PS4: Failed to read file data for: " + fi.path);
    return E_FAIL;
  }

  // PS4 debug PKGs are typically unencrypted
  // If encryption is needed, implement here

  LOG("PS4: Extracted " + fi.path + " (" + std::to_string(fi.size) + " bytes)");
  return S_OK;
}

// =====================================================================
// UNIFIED OPEN METHOD
// =====================================================================

HRESULT UnifiedPKGHandler::Open(IInStream* stream, const UInt64* fileSize, IArchiveOpenCallback* callback) {
  RINOK(stream->Seek(0, STREAM_SEEK_END, &archiveSize));
  RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));

  // Detect format
  RINOK(DetectFormat(stream));

  // Parse based on format
  if (pkgFormat == PKG_FORMAT_PS3) {
    LOG("Opening as PS3 PKG...");
    RINOK(ParsePS3PKGHeader(stream));
    RINOK(ParsePS3FileTable(stream));

    for (auto& item : items) {
      RINOK(ExtractPS3FileData(stream, item));
      if (callback) {
        UInt64 done = item.offset + item.size;
        callback->SetCompleted(nullptr, &done);
      }
    }
  }
  else if (pkgFormat == PKG_FORMAT_PS4) {
    LOG("Opening as PS4 PKG...");
    RINOK(ParsePS4PKGHeader(stream));
    RINOK(ParsePS4FileTable(stream));

    for (auto& item : items) {
      RINOK(ExtractPS4FileData(stream, item));
      if (callback) {
        UInt64 done = item.offset + item.size;
        callback->SetCompleted(nullptr, &done);
      }
    }
  }
  else {
    LOG("ERROR: Unknown PKG format");
    return E_FAIL;
  }

  LOG("OPEN SUCCESS – " + std::to_string(items.size()) + " files");
  return S_OK;
}