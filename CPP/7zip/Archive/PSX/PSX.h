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

#include "ps3_pkg.h"
#include "ps4_pkg.h"
#include "psx_pup.h"
#include "log.h"

// ---------------------------------------------------------------------
// Common PKG/PUP constants
// ---------------------------------------------------------------------
#define TAR_GZ 0x1F8B0800
#define PS3_PUP_MAGIC 0x53434555 // 'SCEU' - PS3 PUP magic
#define PS4_PUP_MAGIC 0x53455500 // PS4 PUP magic 

enum PKG_FORMAT {
  PKG_FORMAT_UNKNOWN = 0,
  PKG_FORMAT_PS3 = 1,
  PKG_FORMAT_PS4 = 2,
  PKG_FORMAT_PS3_PUP = 3,
  PKG_FORMAT_PS4_PUP = 4
};

// ---------------------------------------------------------------------
// Unified Handler class
// ---------------------------------------------------------------------
class PSXHandler {
  UInt64 archiveSize = 0;
  PKG_FORMAT pkgFormat = PKG_FORMAT_UNKNOWN;

  // Handler instances
  PS3PKGHandler ps3Handler;
  PS4PKGHandler ps4Handler;
  PUPHandler pupHandler;

public:
  // -----------------------------------------------------------------
  // File entry description (unified for all formats)
  // -----------------------------------------------------------------
  struct FileInfo {
    uint64_t offset = 0;
    uint64_t size = 0;
    uint64_t uncompressed_size = 0;
    uint32_t flags = 0;
    uint32_t type = 0;
    uint64_t entryId = 0; // For PUP files
    std::string path;
    std::vector<uint8_t> fileData;
    bool isFolder = false;
    bool isCompressed = false;
    bool isBlocked = false;
    int64_t fileTime1 = 0;
    int64_t fileTime2 = 0;
    int64_t fileTime3 = 0;

    FileInfo() = default;
    FileInfo(const FileInfo&) = default;
    FileInfo& operator=(const FileInfo&) = default;
    FileInfo(FileInfo&&) = default;
    FileInfo& operator=(FileInfo&&) = default;
  };

  std::vector<FileInfo> items;
  CMyComPtr<IArchiveOpenVolumeCallback> volCallback;

  HRESULT Open(IInStream* stream, const UInt64* fileSize, IArchiveOpenCallback* callback);
  HRESULT DetectFormat(IInStream* stream);


  // SFO EDITOR INTEGRATION
  HRESULT EditSFOFile(FileInfo& sfoFile);

  PKG_FORMAT GetFormat() const { return pkgFormat; }
  const PKG_HEADER_PS3& GetPS3Header() const { return ps3Handler.GetHeader(); }
  const PKG_HEADER_PS4& GetPS4Header() const { return ps4Handler.GetHeader(); }

  // PUP header accessors
  const PS3_PUP_HEADER& GetPS3PUPHeader() const { return pupHandler.GetPS3Header(); }
  const PS4_PUP_HEADER& GetPS4PUPHeader() const { return pupHandler.GetPS4Header(); }
  bool IsPUPPS3() const { return pupHandler.IsPS3(); }
  bool IsPUPPS4() const { return pupHandler.IsPS4(); }

private:
  HRESULT ReadBytes(IInStream* stream, void* buffer, uint32_t size);
  uint32_t SwapEndian32(uint32_t v) { return _byteswap_ulong(v); }
  uint64_t SwapEndian64(uint64_t v) { return _byteswap_uint64(v); }
  uint16_t SwapEndian16(uint16_t v) { return _byteswap_ushort(v); }
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
// Format detection
// ---------------------------------------------------------------------
HRESULT PSXHandler::DetectFormat(IInStream* stream) {
  uint8_t magicBytes[4];
  UInt32 bytesRead = 0;

  // Make sure we're at the start
  RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));
  RINOK(stream->Read(magicBytes, 4, &bytesRead));

  if (bytesRead != 4) {
    logDebug("DetectFormat: Failed to read 4 bytes");
    return E_FAIL;
  }

  // Check big-endian magic (PS3 formats)
  uint32_t magicBE = ((uint32_t)magicBytes[0] << 24) |
    ((uint32_t)magicBytes[1] << 16) |
    ((uint32_t)magicBytes[2] << 8) |
    ((uint32_t)magicBytes[3]);

  // Check little-endian magic (PS4 formats)
  uint32_t magicLE = ((uint32_t)magicBytes[0]) |
    ((uint32_t)magicBytes[1] << 8) |
    ((uint32_t)magicBytes[2] << 16) |
    ((uint32_t)magicBytes[3] << 24);

  logDebug(
    "DetectFormat: Magic bytes: ",
    std::hex, std::uppercase,
    std::setw(2), std::setfill('0'), static_cast<int>(magicBytes[0]), " ",
    std::setw(2), std::setfill('0'), static_cast<int>(magicBytes[1]), " ",
    std::setw(2), std::setfill('0'), static_cast<int>(magicBytes[2]), " ",
    std::setw(2), std::setfill('0'), static_cast<int>(magicBytes[3]),
    " (BE: 0x", magicBE, ", LE: 0x", magicLE, ")",
    std::dec, std::nouppercase
  );

  if (magicBE == PKG_MAGIC_PS3) {
    pkgFormat = PKG_FORMAT_PS3;
    logDebug("Detected PS3 PKG format");
    return S_OK;
  }
  else if (magicBE == PKG_MAGIC_PS4) {
    pkgFormat = PKG_FORMAT_PS4;
    logDebug("Detected PS4 PKG format");
    return S_OK;
  }
  else if (magicBE == PS3_PUP_MAGIC) {
    pkgFormat = PKG_FORMAT_PS3_PUP;
    logDebug("Detected PS3 PUP format");
    return S_OK;
  }

  // For PS4 PUP, we need to check the header structure
  // Read full header (32 bytes)
  uint8_t headerBytes[0x20];
  RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));
  RINOK(stream->Read(headerBytes, 0x20, &bytesRead));

  if (bytesRead != 0x20) {
    logDebug("DetectFormat: Failed to read header");
    return E_FAIL;
  }

  // Validate PS4 PUP structure
  uint16_t header_size = headerBytes[0x0C] | (headerBytes[0x0D] << 8);
  uint16_t entry_count = headerBytes[0x18] | (headerBytes[0x19] << 8);
  uint16_t hash_count = headerBytes[0x1A] | (headerBytes[0x1B] << 8);

  logDebug(
    "PS4 PUP check: header_size=0x", std::hex, header_size, std::dec,
    ", entry_count=", entry_count,
    ", hash_count=", hash_count
  );


  bool headerSizeOK = (header_size >= 0x20 && header_size <= 0x100000);
  bool entryCountOK = (entry_count > 0 && entry_count <= 5000);
  bool hashCountOK = (hash_count <= 5000);

  if (headerSizeOK && entryCountOK && hashCountOK) {
    pkgFormat = PKG_FORMAT_PS4_PUP;
    logDebug("Detected PS4 PUP format by structure validation");
    return S_OK;
  }

  logDebug("Unknown PKG format - not PS3/PS4 PKG/PUP");
  return E_FAIL;
}

// =====================================================================
// PSXHandler OPEN METHOD
// =====================================================================
HRESULT PSXHandler::Open(IInStream* stream, const uint64_t* fileSize, IArchiveOpenCallback* callback) {
  // Determine archive size
  RINOK(stream->Seek(0, STREAM_SEEK_END, &archiveSize));
  RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));

  // Detect format
  RINOK(DetectFormat(stream));

  items.clear();

  if (pkgFormat == PKG_FORMAT_PS3) {
    logDebug("Opening as PS3 PKG...");
    RINOK(ps3Handler.ParseHeader(stream));

    std::vector<PS3PKGHandler::FileInfo> ps3Items;
    RINOK(ps3Handler.ParseFileTable(stream, ps3Items));

    items.reserve(ps3Items.size());
    for (const auto& src : ps3Items) {
      FileInfo fi;
      fi.offset = src.offset;
      fi.size = src.size;
      fi.flags = src.flags;
      fi.type = src.type;
      fi.path = src.path;
      fi.isFolder = src.isFolder;
      fi.fileTime1 = src.fileTime1;
      fi.fileTime2 = src.fileTime2;
      fi.fileTime3 = src.fileTime3;
      items.push_back(std::move(fi));
    }

    // Extract file data
    for (auto& item : items) {
      PS3PKGHandler::FileInfo ps3Item;
      ps3Item.offset = item.offset;
      ps3Item.size = item.size;
      ps3Item.isFolder = item.isFolder;
      RINOK(ps3Handler.ExtractFileData(stream, ps3Item));
      item.fileData = std::move(ps3Item.fileData);

      if (callback) {
        uint64_t done = item.offset + item.size;
        callback->SetCompleted(nullptr, &done);
      }
    }
  }
  else if (pkgFormat == PKG_FORMAT_PS4) {
    logDebug("Opening as PS4 PKG...");
    RINOK(ps4Handler.ParseHeader(stream));

    std::vector<PS4PKGHandler::FileInfo> ps4Items;
    RINOK(ps4Handler.ParseFileTable(stream, ps4Items));

    items.reserve(ps4Items.size());
    for (const auto& src : ps4Items) {
      FileInfo fi;
      fi.offset = src.offset;
      fi.size = src.size;
      fi.flags = src.flags;
      fi.type = src.type;
      fi.path = src.path;
      fi.isFolder = src.isFolder;
      fi.fileTime1 = src.fileTime1;
      fi.fileTime2 = src.fileTime2;
      fi.fileTime3 = src.fileTime3;
      items.push_back(std::move(fi));
    }

    // Extract file data
    for (auto& item : items) {
      PS4PKGHandler::FileInfo ps4Item;
      ps4Item.offset = item.offset;
      ps4Item.size = item.size;
      ps4Item.isFolder = item.isFolder;
      RINOK(ps4Handler.ExtractFileData(stream, ps4Item));
      item.fileData = std::move(ps4Item.fileData);

      if (callback) {
        uint64_t done = item.offset + item.size;
        callback->SetCompleted(nullptr, &done);
      }
    }
  }
  else if (pkgFormat == PKG_FORMAT_PS3_PUP || pkgFormat == PKG_FORMAT_PS4_PUP) {
    const char* pupType = (pkgFormat == PKG_FORMAT_PS3_PUP) ? "PS3 PUP" : "PS4 PUP";
    logDebug(std::string("Opening as ") + pupType + "...");

    RINOK(pupHandler.ParseHeader(stream, archiveSize));

    // Use a local vector for PUP items
    std::vector<PUPHandler::FileInfo> pupItems;
    RINOK(pupHandler.ParseFileTable(stream, pupItems));

    items.reserve(pupItems.size());
    for (const auto& pupItem : pupItems) {
      FileInfo fi;
      fi.offset = pupItem.offset;
      fi.size = pupItem.size;
      fi.uncompressed_size = pupItem.uncompressed_size;
      fi.entryId = pupItem.entryId;
      fi.type = pupItem.type;
      fi.flags = pupItem.flags;
      fi.path = pupItem.path;
      fi.isFolder = pupItem.isFolder;
      fi.isCompressed = pupItem.isCompressed;
      fi.isBlocked = pupItem.isBlocked;
      fi.fileTime1 = pupItem.fileTime1;
      fi.fileTime2 = pupItem.fileTime2;
      fi.fileTime3 = pupItem.fileTime3;
      items.push_back(std::move(fi));
    }

    // Extract file data for each PUP item
    for (auto& item : items) {
      PUPHandler::FileInfo pupItem;
      pupItem.offset = item.offset;
      pupItem.size = item.size;
      pupItem.uncompressed_size = item.uncompressed_size;
      pupItem.entryId = item.entryId;
      pupItem.type = item.type;
      pupItem.flags = item.flags;
      pupItem.isFolder = item.isFolder;
      pupItem.isCompressed = item.isCompressed;
      pupItem.isBlocked = item.isBlocked;

      HRESULT hr = pupHandler.ExtractFileData(stream, pupItem);

      // For PS4 PUP compressed files, extraction may not be implemented
      if (hr == E_NOTIMPL && pupItem.isCompressed) {
        logDebug("WARNING: Skipping compressed PS4 PUP file: " + item.path);
        // Create placeholder data or skip
        item.fileData.clear();
      }
      else {
        RINOK(hr);
        item.fileData = std::move(pupItem.fileData);
      }

      if (callback) {
        uint64_t done = item.offset + item.size;
        callback->SetCompleted(nullptr, &done);
      }
    }
  }
  else {
    logDebug("ERROR: Unknown format");
    return E_FAIL;
  }

  logDebug("OPEN SUCCESS – " + std::to_string(items.size()) + " files");
  return S_OK;
}


HRESULT PSXHandler::ReadBytes(IInStream* stream, void* buffer, uint32_t size) {
  UInt32 read = 0;
  RINOK(stream->Read(buffer, size, &read));
  return (read == size) ? S_OK : E_FAIL;
}

// ---------------------------------------------------------------------
// SFO EDITOR STUB
// ---------------------------------------------------------------------
HRESULT PSXHandler::EditSFOFile(FileInfo& sfoFile) {
  // TODO: Implement SFO editing
  return S_OK;
}