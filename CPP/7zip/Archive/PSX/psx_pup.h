#pragma once
#include <windows.h>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <string>
#include <sstream>
#include <iomanip>
#include <map>

#include "log.h"

// ---------------------------------------------------------------------
// PUP constants
// ---------------------------------------------------------------------
#define PS3_PUP_MAGIC 0x53434555  // 'SCEU' - PS3 PUP magic
#define PS4_PUP_MAGIC 0x53455500  // PS4 PUP magic (first 4 bytes, but we check full signature)
#define PS3_SELF      0x53434500
#define TAR_GZ        0x1F8B0800

// ---------------------------------------------------------------------
// PS3 PUP structures (packed)
// ---------------------------------------------------------------------
#pragma pack(push, 1)
struct PS3_PUP_HEADER {
  uint32_t magic;                // 0x00 - 'SCEU' (0x53434555)
  uint32_t package_version;      // 0x04
  uint32_t image_version;        // 0x08
  uint32_t file_count;           // 0x0C
  uint32_t header_length;        // 0x10
  uint32_t data_length;          // 0x14
  uint64_t reserved;             // 0x18
};

struct PS3_PUP_FILE_ENTRY {
  uint64_t entry_id;             // 0x00
  uint64_t data_offset;          // 0x08
  uint64_t data_length;          // 0x10
  uint64_t reserved;             // 0x18
};

struct PS3_PUP_FILE_HASH {
  uint64_t entry_id;             // 0x00
  uint8_t  hash[0x14];           // 0x08 - SHA1 hash (20 bytes)
  uint32_t reserved;             // 0x1C
};

// ---------------------------------------------------------------------
// PS4 PUP structures (packed)
// ---------------------------------------------------------------------
struct PS4_PUP_HEADER {
  uint32_t magic;                // 0x00
  uint32_t unknown04;            // 0x04
  uint16_t unknown08;            // 0x08
  uint8_t  flags;                // 0x0A
  uint8_t  unknown0B;            // 0x0B
  uint16_t header_size;          // 0x0C
  uint16_t hash_size;            // 0x0E
  int64_t  file_size;            // 0x10
  uint16_t entry_count;          // 0x18
  uint16_t hash_count;           // 0x1A
  uint32_t unknown1C;            // 0x1C
};

struct PS4_PUP_ENTRY {
  uint32_t flags;                // 0x00
  uint32_t reserved;             // 0x04
  int64_t  offset;               // 0x08
  int64_t  compressed_size;      // 0x10
  int64_t  uncompressed_size;    // 0x18
};

struct PS4_BLOCK_INFO {
  uint32_t offset;
  uint32_t size;
};
#pragma pack(pop)

// ---------------------------------------------------------------------
// Unified PUP Handler Class
// ---------------------------------------------------------------------
class PUPHandler {
private:
  enum PUPType {
    PUP_TYPE_UNKNOWN,
    PUP_TYPE_PS3,
    PUP_TYPE_PS4
  };

  PUPType pupType = PUP_TYPE_UNKNOWN;

  // PS3 data
  PS3_PUP_HEADER ps3Header = {};
  std::vector<PS3_PUP_FILE_ENTRY> ps3FileEntries;
  std::vector<PS3_PUP_FILE_HASH> ps3FileHashes;

  // PS4 data
  PS4_PUP_HEADER ps4Header = {};
  std::vector<PS4_PUP_ENTRY> ps4Entries;

  UInt64 archiveSize = 0;

  uint32_t SwapEndian32(uint32_t v) { return _byteswap_ulong(v); }
  uint64_t SwapEndian64(uint64_t v) { return _byteswap_uint64(v); }
  uint16_t SwapEndian16(uint16_t v) { return _byteswap_ushort(v); }

  // PS3 file naming
  const char* GetPS3FileName(uint64_t entryId) {
    switch (entryId) {
    case 0x100: return "version.txt";
    case 0x101: return "license.xml";
    case 0x102: return "promo_flags.txt";
    case 0x103: return "update_flags.txt";
    case 0x104: return "patch_data.pkg";
    case 0x200: return "ps3swu.self";
    case 0x201: return "vsh.tar";
    case 0x202: return "dots.txt";
    case 0x203: return "patch_data.pkg";
    case 0x300: return "update_files.tar";
    case 0x501: return "sdk_version.txt";
    case 0x601: return "updater_frontend.dat";
    case 0x602: return "edata.tar";
    case 0x000: return "dev_flash";
    case 0x001: return "dev_flash2";
    case 0x002: return "dev_flash3";
    default: return nullptr;
    }
  }

  // PS4 file naming
  std::string GetPS4FileName(uint32_t id) {
    static std::map<uint32_t, std::string> fileNames = {
      {3, "wlan_firmware.bin"},
      {5, "secure_modules.bin"},
      {6, "fs/system.img"},
      {8, "fs/eap.img"},
      {9, "fs/recovery.img"},
      {11, "fs/preinst.img"},
      {12, "fs/system_ex.img"},
      {34, "torus2_firmware.bin"},
      {257, "eula.xml"},
      {512, "orbis_swu.elf"},
      {514, "orbis_swu.self"},
      {3337, "cp_firmware.bin"}
    };

    static std::map<uint32_t, std::string> deviceNames = {
      {1, "sflash0s0x32b"}, {13, "sflash0s0x32b"}, {32, "sflash0s0x32b"},
      {36, "sflash0s0x32b"}, {40, "sflash0s0x32b"}, {42, "sflash0s0x32b"},
      {44, "sflash0s0x32b"}, {46, "sflash0s0x32b"},
      {2, "sflash0s0x33"}, {14, "sflash0s0x33"}, {33, "sflash0s0x33"},
      {37, "sflash0s0x33"}, {43, "sflash0s0x33"},
      {3, "sflash0s0x38"}, {34, "sflash0s0x38"}, {48, "sflash0s0x38"},
      {4, "sflash0s1.cryptx2b"}, {35, "sflash0s1.cryptx2b"},
      {38, "sflash0s1.cryptx2b"}, {39, "sflash0s1.cryptx2b"},
      {45, "sflash0s1.cryptx2b"},
      {5, "sflash0s1.cryptx3b"},
      {10, "sflash0s1.cryptx40"},
      {9, "da0x0.crypt"}, {11, "da0x1.crypt"}, {7, "da0x2"},
      {8, "da0x3.crypt"}, {6, "da0x4b.crypt"}, {12, "da0x5b.crypt"},
      {3328, "sc_fw_update0"}, {3336, "sc_fw_update0"}, {3335, "sc_fw_update0"},
      {3329, "cd0"}, {3330, "da0"},
      {16, "sbram0"}, {17, "sbram0"}, {18, "sbram0"}, {19, "sbram0"},
      {20, "sbram0"}, {21, "sbram0"}, {22, "sbram0"},
      {3337, "cpfirm"},
      {15, "test"}, {782, "test"}, {783, "test"},
      {769, "update"}, {770, "update"}
    };

    auto fnIt = fileNames.find(id);
    if (fnIt != fileNames.end()) {
      return fnIt->second;
    }

    auto devIt = deviceNames.find(id);
    if (devIt != deviceNames.end()) {
      std::stringstream ss;
      ss << "devices/" << id << "__" << devIt->second << ".bin";
      return ss.str();
    }

    std::stringstream ss;
    ss << "unknown/" << id << ".bin";
    return ss.str();
  }

  std::string GenerateFileName(uint64_t entryId, IInStream* stream, uint64_t offset, uint64_t size) {
    std::stringstream ss;
    ss << "file_0x" << std::hex << std::setw(3) << std::setfill('0') << entryId;

    if (size >= 4) {
      std::vector<uint8_t> headerBytes(4);
      UInt64 currentPos;

      if (SUCCEEDED(stream->Seek(0, STREAM_SEEK_CUR, &currentPos))) {
        if (SUCCEEDED(stream->Seek(offset, STREAM_SEEK_SET, nullptr))) {
          UInt32 bytesRead = 0;
          if (SUCCEEDED(stream->Read(headerBytes.data(), 4, &bytesRead)) && bytesRead == 4) {
            uint32_t magic = (headerBytes[0] << 24) | (headerBytes[1] << 16) |
              (headerBytes[2] << 8) | headerBytes[3];

            if (magic == 0x7F504B47) ss << ".pkg";
            else if (magic == PS3_SELF) ss << ".self";
            else if (magic == TAR_GZ) ss << ".tar.gz";
            else if (headerBytes[0] == 0x75 && headerBytes[1] == 0x73 &&
              headerBytes[2] == 0x74 && headerBytes[3] == 0x61) ss << ".tar";
            else ss << ".bin";
          }
          else {
            ss << ".bin";
          }
          stream->Seek(currentPos, STREAM_SEEK_SET, nullptr);
        }
        else {
          ss << ".bin";
        }
      }
      else {
        ss << ".bin";
      }
    }
    else {
      ss << ".bin";
    }

    return ss.str();
  }

  HRESULT ParsePS3Header(IInStream* stream, UInt64 fileSize) {
    archiveSize = fileSize;
    RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));

    uint8_t headerBytes[48];
    UInt32 bytesRead = 0;
    RINOK(stream->Read(headerBytes, 48, &bytesRead));
    if (bytesRead != 48) return E_FAIL;

    ps3Header.magic = (headerBytes[0] << 24) | (headerBytes[1] << 16) |
      (headerBytes[2] << 8) | headerBytes[3];

    if (ps3Header.magic != PS3_PUP_MAGIC) return E_FAIL;

    ps3Header.package_version = (headerBytes[4] << 24) | (headerBytes[5] << 16) |
      (headerBytes[6] << 8) | headerBytes[7];
    ps3Header.image_version = (headerBytes[20] << 24) | (headerBytes[21] << 16) |
      (headerBytes[22] << 8) | headerBytes[23];
    ps3Header.file_count = (headerBytes[28] << 24) | (headerBytes[29] << 16) |
      (headerBytes[30] << 8) | headerBytes[31];
    ps3Header.header_length = (headerBytes[36] << 24) | (headerBytes[37] << 16) |
      (headerBytes[38] << 8) | headerBytes[39];
    ps3Header.data_length = (headerBytes[44] << 24) | (headerBytes[45] << 16) |
      (headerBytes[46] << 8) | headerBytes[47];

    if (ps3Header.file_count == 0 || ps3Header.file_count > 100) return E_FAIL;
    if (ps3Header.header_length == 0 || ps3Header.header_length > archiveSize) return E_FAIL;

    pupType = PUP_TYPE_PS3;
    return S_OK;
  }

  HRESULT ParsePS4Header(IInStream* stream, UInt64 fileSize) {
    archiveSize = fileSize;
    RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));

    uint8_t headerBytes[0x20];
    UInt32 bytesRead = 0;
    RINOK(stream->Read(headerBytes, 0x20, &bytesRead));
    if (bytesRead != 0x20) return E_FAIL;

    // Read all fields in little-endian
    ps4Header.magic = headerBytes[0] | (headerBytes[1] << 8) |
      (headerBytes[2] << 16) | (headerBytes[3] << 24);
    ps4Header.unknown04 = headerBytes[4] | (headerBytes[5] << 8) |
      (headerBytes[6] << 16) | (headerBytes[7] << 24);
    ps4Header.unknown08 = headerBytes[8] | (headerBytes[9] << 8);
    ps4Header.flags = headerBytes[10];
    ps4Header.unknown0B = headerBytes[11];
    ps4Header.header_size = headerBytes[12] | (headerBytes[13] << 8);
    ps4Header.hash_size = headerBytes[14] | (headerBytes[15] << 8);

    ps4Header.file_size = 0;
    for (int i = 0; i < 8; i++) {
      ps4Header.file_size |= ((int64_t)headerBytes[16 + i] << (i * 8));
    }

    ps4Header.entry_count = headerBytes[24] | (headerBytes[25] << 8);
    ps4Header.hash_count = headerBytes[26] | (headerBytes[27] << 8);
    ps4Header.unknown1C = headerBytes[28] | (headerBytes[29] << 8) |
      (headerBytes[30] << 16) | (headerBytes[31] << 24);

    logDebug(
      "PS4 PUP Header: entry_count=", ps4Header.entry_count,
      ", header_size=0x", std::hex, ps4Header.header_size, std::dec,
      ", hash_count=", ps4Header.hash_count,
      ", file_size=", ps4Header.file_size
    );

    if (ps4Header.entry_count == 0) {
      logDebug("REJECT: entry_count is 0");

      return E_FAIL;
    }

    if (ps4Header.header_size < 0x20) {
      logDebug("REJECT: header_size too small");

      return E_FAIL;
    }
    pupType = PUP_TYPE_PS4;

    logDebug("PS4 PUP header accepted");


    return S_OK;
  }

public:
  struct FileInfo {
    uint64_t  offset = 0;
    uint64_t  size = 0;
    uint64_t  uncompressed_size = 0;
    uint64_t  entryId = 0;
    uint32_t  type = 0;
    uint32_t  flags = 0;
    std::string path;
    std::vector<uint8_t> fileData;
    bool      isFolder = false;
    bool      isCompressed = false;
    bool      isBlocked = false;
    int64_t   fileTime1 = 0;
    int64_t   fileTime2 = 0;
    int64_t   fileTime3 = 0;
  };

  HRESULT ParseHeader(IInStream* stream, UInt64 fileSize) {
    logDebug("Entered ParseHeader()");

    uint8_t magicBytes[4];
    UInt32 bytesRead = 0;

    RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));
    RINOK(stream->Read(magicBytes, 4, &bytesRead));

    logDebug("Read first 4 bytes from stream");

    if (bytesRead != 4) {
      logDebug("Failed: bytesRead != 4");
      return E_FAIL;
    }

    uint32_t magic = (magicBytes[0] << 24) | (magicBytes[1] << 16) |
      (magicBytes[2] << 8) | magicBytes[3];

    char buf[128];
    sprintf_s(buf, "Magic bytes = 0x%08X", magic);
    logDebug(buf);

    if (magic == PS3_PUP_MAGIC) {
      logDebug("Detected PS3 PUP file, parsing PS3 header...");
      return ParsePS3Header(stream, fileSize);
    }

    logDebug("Trying to parse as PS4 PUP...");

    HRESULT result = ParsePS4Header(stream, fileSize);

    if (SUCCEEDED(result)) {
      logDebug(buf, "PS4 header parsed successfully. Entry count: %d", ps4Header.entry_count);
      logDebug("PS4 PUP format accepted");
      return S_OK;
    }

    logDebug("Header parsing failed - not a valid PUP file");
    return E_FAIL;
  }

  HRESULT ParseFileTable(IInStream* stream, std::vector<FileInfo>& items) {
    if (pupType == PUP_TYPE_PS3) {
      return ParsePS3FileTable(stream, items);
    }
    else if (pupType == PUP_TYPE_PS4) {
      return ParsePS4FileTable(stream, items);
    }
    return E_FAIL;
  }

  HRESULT ParsePS3FileTable(IInStream* stream, std::vector<FileInfo>& items) {
    const uint64_t FILE_ENTRIES_OFFSET = 0x30;
    RINOK(stream->Seek(FILE_ENTRIES_OFFSET, STREAM_SEEK_SET, nullptr));

    ps3FileEntries.resize(ps3Header.file_count);

    for (uint32_t i = 0; i < ps3Header.file_count; i++) {
      uint8_t entryBytes[0x20];
      UInt32 bytesRead = 0;
      RINOK(stream->Read(entryBytes, 0x20, &bytesRead));
      if (bytesRead != 0x20) return E_FAIL;

      ps3FileEntries[i].entry_id =
        ((uint64_t)entryBytes[0] << 56) | ((uint64_t)entryBytes[1] << 48) |
        ((uint64_t)entryBytes[2] << 40) | ((uint64_t)entryBytes[3] << 32) |
        ((uint64_t)entryBytes[4] << 24) | ((uint64_t)entryBytes[5] << 16) |
        ((uint64_t)entryBytes[6] << 8) | (uint64_t)entryBytes[7];

      ps3FileEntries[i].data_offset =
        ((uint64_t)entryBytes[8] << 56) | ((uint64_t)entryBytes[9] << 48) |
        ((uint64_t)entryBytes[10] << 40) | ((uint64_t)entryBytes[11] << 32) |
        ((uint64_t)entryBytes[12] << 24) | ((uint64_t)entryBytes[13] << 16) |
        ((uint64_t)entryBytes[14] << 8) | (uint64_t)entryBytes[15];

      ps3FileEntries[i].data_length =
        ((uint64_t)entryBytes[16] << 56) | ((uint64_t)entryBytes[17] << 48) |
        ((uint64_t)entryBytes[18] << 40) | ((uint64_t)entryBytes[19] << 32) |
        ((uint64_t)entryBytes[20] << 24) | ((uint64_t)entryBytes[21] << 16) |
        ((uint64_t)entryBytes[22] << 8) | (uint64_t)entryBytes[23];

      if (ps3FileEntries[i].data_offset < ps3Header.header_length) continue;
      if (ps3FileEntries[i].data_offset > archiveSize) return E_FAIL;
    }

    for (uint32_t i = 0; i < ps3Header.file_count; i++) {
      FileInfo fi;
      fi.offset = ps3FileEntries[i].data_offset;
      fi.size = ps3FileEntries[i].data_length;
      fi.uncompressed_size = ps3FileEntries[i].data_length;
      fi.entryId = ps3FileEntries[i].entry_id;
      fi.type = static_cast<uint32_t>(ps3FileEntries[i].entry_id);
      fi.isFolder = false;
      fi.isCompressed = false;

      const char* predefinedName = GetPS3FileName(ps3FileEntries[i].entry_id);
      if (predefinedName != nullptr) {
        fi.path = predefinedName;
      }
      else {
        fi.path = GenerateFileName(ps3FileEntries[i].entry_id, stream, fi.offset, fi.size);
      }

      std::replace(fi.path.begin(), fi.path.end(), '\\', '/');
      items.push_back(std::move(fi));
    }

    return S_OK;
  }

  HRESULT ParsePS4FileTable(IInStream* stream, std::vector<FileInfo>& items) {
    const uint64_t ENTRIES_OFFSET = 0x20;
    logDebug("ParsePS4FileTable: Starting...");
    logDebug(" Entry count: %d, offset: 0x%llX", ps4Header.entry_count, ENTRIES_OFFSET);

    RINOK(stream->Seek(ENTRIES_OFFSET, STREAM_SEEK_SET, nullptr));
    ps4Entries.resize(ps4Header.entry_count);

    // Read all entries
    for (uint16_t i = 0; i < ps4Header.entry_count; i++) {
      uint8_t entryBytes[0x20];
      UInt32 bytesRead = 0;
      HRESULT hr = stream->Read(entryBytes, 0x20, &bytesRead);
      if (FAILED(hr) || bytesRead != 0x20) {
        logDebug(" ERROR reading entry %d: hr=0x%X, bytesRead=%d", i, hr, bytesRead);
        return E_FAIL;
      }

      // Read fields in little-endian
      ps4Entries[i].flags = entryBytes[0] | (entryBytes[1] << 8) |
        (entryBytes[2] << 16) | (entryBytes[3] << 24);
      ps4Entries[i].offset = 0;
      for (int j = 0; j < 8; j++)
        ps4Entries[i].offset |= ((int64_t)entryBytes[8 + j] << (j * 8));
      ps4Entries[i].compressed_size = 0;
      for (int j = 0; j < 8; j++)
        ps4Entries[i].compressed_size |= ((int64_t)entryBytes[16 + j] << (j * 8));
      ps4Entries[i].uncompressed_size = 0;
      for (int j = 0; j < 8; j++)
        ps4Entries[i].uncompressed_size |= ((int64_t)entryBytes[24 + j] << (j * 8));

      if (i < 10) {
        uint32_t entry_id = ps4Entries[i].flags >> 20;
        bool isTable = (ps4Entries[i].flags & 1) != 0;
        bool isCompressed = (ps4Entries[i].flags & 8) != 0;
        bool isBlocked = (ps4Entries[i].flags & 0x800) != 0;
        logDebug(" Entry %d: flags=0x%X, id=%u, offset=0x%llX, comp=%lld, uncomp=%lld, table=%d, comp=%d, blocked=%d",
          i, ps4Entries[i].flags, entry_id, ps4Entries[i].offset,
          ps4Entries[i].compressed_size, ps4Entries[i].uncompressed_size,
          isTable, isCompressed, isBlocked);
      }
    }

    // Build table entry map
    std::vector<int> tableEntries(ps4Header.entry_count, -2);
    for (uint16_t i = 0; i < ps4Header.entry_count; i++) {
      auto& entry = ps4Entries[i];
      bool isBlocked = (entry.flags & 0x800) != 0;
      if (!isBlocked) {
        tableEntries[i] = -2;
        continue;
      }

      uint32_t entry_id = entry.flags >> 20;
      if (((entry_id | 0x100) & 0xF00) == 0xF00) {
        logDebug(" WARNING: Invalid blocked entry ID at index %d", i);
        continue;
      }

      int tableIndex = -1;
      for (uint16_t j = 0; j < ps4Header.entry_count; j++) {
        if ((ps4Entries[j].flags & 1) != 0) {
          uint32_t table_id = ps4Entries[j].flags >> 20;
          if (table_id == i) {
            tableIndex = j;
            break;
          }
        }
      }

      if (tableIndex < 0) {
        logDebug(" WARNING: No table found for blocked entry at index %d", i);
        continue;
      }

      if (tableEntries[tableIndex] != -2) {
        logDebug(" WARNING: Table index %d already assigned", tableIndex);
        continue;
      }

      tableEntries[tableIndex] = i;
    }

    logDebug("ParsePS4FileTable: Building file list...");

    int fileCount = 0;
    for (uint16_t i = 0; i < ps4Header.entry_count; i++) {
      auto& entry = ps4Entries[i];
      uint32_t special = entry.flags & 0xF0000000;
      if (special == 0xE0000000 || special == 0xF0000000) {
        logDebug(" Skipping special entry %d (flags=0x%X)", i, entry.flags);
        continue;
      }

      bool isTableEntry = (entry.flags & 1) != 0;
      if (isTableEntry) {
        if (tableEntries[i] < 0) {
          logDebug(" Skipping unused table entry %d", i);
        }
        else {
          logDebug(" Skipping table entry %d (used by entry %d)", i, tableEntries[i]);
        }
        continue;
      }

      FileInfo fi;
      fi.offset = entry.offset;
      fi.size = entry.compressed_size;
      fi.uncompressed_size = entry.uncompressed_size;
      fi.entryId = entry.flags >> 20;
      fi.type = entry.flags;
      fi.flags = entry.flags;
      fi.isFolder = false;
      fi.isCompressed = (entry.flags & 8) != 0;
      fi.isBlocked = (entry.flags & 0x800) != 0;

      fi.path = GetPS4FileName(static_cast<uint32_t>(fi.entryId));
      std::replace(fi.path.begin(), fi.path.end(), '\\', '/');

      logDebug(" Added file %d: %s (id=%llu, size=%lld, compressed=%d, blocked=%d)",
        fileCount, fi.path.c_str(), fi.entryId, fi.size, fi.isCompressed, fi.isBlocked);

      items.push_back(std::move(fi));
      fileCount++;
    }

    logDebug("ParsePS4FileTable: Complete - %d files extracted from %d entries",
      fileCount, ps4Header.entry_count);

    return S_OK;
  }

  HRESULT ExtractFileData(IInStream* stream, FileInfo& fi) {
    if (fi.isFolder || fi.size == 0) return S_OK;

    if (fi.size > archiveSize) return E_FAIL;
    if (fi.offset >= archiveSize || fi.offset + fi.size > archiveSize) return E_FAIL;

    fi.fileData.resize(fi.uncompressed_size > 0 ? fi.uncompressed_size : fi.size);

    RINOK(stream->Seek(fi.offset, STREAM_SEEK_SET, nullptr));

    if (pupType == PUP_TYPE_PS3 || !fi.isCompressed) {
      const size_t CHUNK_SIZE = 1024 * 1024;
      size_t totalRead = 0;

      while (totalRead < fi.size) {
        size_t toRead = std::min(CHUNK_SIZE, fi.size - totalRead);
        UInt32 read = 0;

        HRESULT hr = stream->Read(fi.fileData.data() + totalRead, static_cast<UInt32>(toRead), &read);
        if (FAILED(hr)) return hr;
        if (read == 0) return E_FAIL;

        totalRead += read;
      }

      if (totalRead != fi.size) return E_FAIL;
    }
    else {
     
      return E_NOTIMPL;
    }

    return S_OK;
  }

  bool IsPS3() const { return pupType == PUP_TYPE_PS3; }
  bool IsPS4() const { return pupType == PUP_TYPE_PS4; }

  const PS3_PUP_HEADER& GetPS3Header() const { return ps3Header; }
  const PS4_PUP_HEADER& GetPS4Header() const { return ps4Header; }
};