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
#include "ps5_pkg.h"
#include "log.h"

// ---------------------------------------------------------------------
// Common PKG/PUP constants
// ---------------------------------------------------------------------

enum PKG_FORMAT {
  PKG_FORMAT_UNKNOWN = 0,
  PKG_FORMAT_PS3 = 1,
  PKG_FORMAT_PS4 = 2,
  PKG_FORMAT_PS5 = 3,
  PKG_FORMAT_PS3_PUP = 4,
  PKG_FORMAT_PS4_PUP = 5,
  PKG_FORMAT_PS5_PUP = 6
};

// ---------------------------------------------------------------------
// Unified Handler class
// ---------------------------------------------------------------------
class PSXHandler {
  UInt64 archiveSize = 0;
  PKG_FORMAT pkgFormat = PKG_FORMAT_UNKNOWN;
  std::vector<Byte> m_cachedData;
  bool m_isUpdateMode = false;
  CMyComPtr<IInStream> m_stream;
  bool m_streamReleased = false;
  std::vector<uint8_t> m_ps5RsaDecryptedData;

  // Handler instances
  PS3PKGHandler ps3Handler;
  PS4PKGHandler ps4Handler;
	PS5PKGHandler ps5Handler;
  PUPHandler    pupHandler;

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

    // PS5-specific
    uint32_t flags1 = 0;
    uint32_t flags2 = 0;
    uint8_t keyIndex = 0;
    bool isEncrypted = false;

    uint64_t entryId = 0;
    std::string path;
    int tableIndex = -1;
    uint16_t entryIndex = 0;
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
  HRESULT ExtractFile(size_t index, ISequentialOutStream* outStream, IArchiveExtractCallback* callback = nullptr);

  void ReleaseStream() {
    if (m_stream && !m_streamReleased) {
      m_stream.Release();
      m_streamReleased = true;
      logDebug(L"PSXHandler: Stream released");
    }
  }
  void Close() {
    ps3Handler = PS3PKGHandler();
    ps4Handler = PS4PKGHandler();
    ps5Handler = PS5PKGHandler();
    pupHandler = PUPHandler();

    items.clear();
    m_cachedData.clear();
    m_ps5RsaDecryptedData.clear();

    ReleaseStream();

    pkgFormat = PKG_FORMAT_UNKNOWN;
    archiveSize = 0;
    m_isUpdateMode = false;

    logDebug(L"PSXHandler: Full cleanup completed");
  }

 
  // SFO EDITOR INTEGRATION
  HRESULT EditSFOFile(FileInfo& sfoFile);

	// PKG header accessors
  PKG_FORMAT GetFormat() const { return pkgFormat; }
  const PKG_HEADER_PS3& GetPS3Header() const { return ps3Handler.GetHeader(); }
  const PKG_HEADER_PS4& GetPS4Header() const { return ps4Handler.GetHeader(); }
	const PKG_HEADER_PS5& GetPS5Header() const { return ps5Handler.GetHeader(); }

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

HRESULT PSXHandler::DetectFormat(IInStream* stream) {
  uint8_t magicBytes[4];
  UInt32 bytesRead = 0;

  RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));
  RINOK(stream->Read(magicBytes, 4, &bytesRead));

  if (bytesRead != 4) {
    logDebug(L"DetectFormat: Failed to read 4 bytes");
    return E_FAIL;
  }

  // Convert to big/little endian
  uint32_t magicBE = (magicBytes[0] << 24) | (magicBytes[1] << 16) |
    (magicBytes[2] << 8) | magicBytes[3];
  uint32_t magicLE = magicBytes[0] | (magicBytes[1] << 8) |
    (magicBytes[2] << 16) | (magicBytes[3] << 24);

  // Diagnostic output
  wchar_t debugMsg[256];
  swprintf_s(debugMsg,
    L"DetectFormat: Raw=[%02X %02X %02X %02X] BE=0x%08X LE=0x%08X",
    magicBytes[0], magicBytes[1], magicBytes[2], magicBytes[3], magicBE, magicLE);
  logDebug(debugMsg);

  // Check against known formats
  struct FormatCheck {
    uint32_t magic;
    bool useBE;
    PKG_FORMAT format;
    const wchar_t* name;
  };

  const FormatCheck formats[] = {
    {PKG_MAGIC_PS3, true, PKG_FORMAT_PS3, L"PS3 PKG"},
    {PKG_MAGIC_PS4, true, PKG_FORMAT_PS4, L"PS4 PKG"},
    {PKG_MAGIC_PS5, true, PKG_FORMAT_PS5, L"PS5 PKG"},
    {PS3_PUP_MAGIC, true, PKG_FORMAT_PS3_PUP, L"PS3 PUP"},
    {PS4_PUP_MAGIC, false, PKG_FORMAT_PS4_PUP, L"PS4 PUP"},
    {PS5_PUP_MAGIC, false, PKG_FORMAT_PS5_PUP, L"PS5 PUP"}
  };

  for (const auto& fmt : formats) {
    uint32_t magic = fmt.useBE ? magicBE : magicLE;
    if (magic == fmt.magic) {
      pkgFormat = fmt.format;
      swprintf_s(debugMsg, L"Detected %s format (0x%08X)", fmt.name, fmt.magic);
      logDebug(debugMsg);
      return S_OK;
    }
  }

  // Heuristic detection for PUP files without exact magic
  uint8_t header[0x20];
  RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));
  RINOK(stream->Read(header, 0x20, &bytesRead));

  if (bytesRead == 0x20) {
    uint16_t entry_count = header[0x18] | (header[0x19] << 8);
    uint16_t header_size = header[0x0C] | (header[0x0D] << 8);
    uint16_t hash_count = header[0x1A] | (header[0x1B] << 8);

    if (header_size >= 0x20 && header_size <= 0x100000 &&
      entry_count > 0 && entry_count <= 5000 &&
      hash_count <= 5000) {
      pkgFormat = entry_count > 500 ? PKG_FORMAT_PS5_PUP : PKG_FORMAT_PS4_PUP;
      swprintf_s(debugMsg, L"Detected %s PUP format (heuristic)",
        entry_count > 500 ? L"PS5" : L"PS4");
      logDebug(debugMsg);
      return S_OK;
    }
  }

  logDebug(L"DetectFormat: Unknown format");
  return E_FAIL;
}

HRESULT PSXHandler::Open(IInStream* stream, const uint64_t* fileSize, IArchiveOpenCallback* callback) {
  m_stream = stream;

  // Determine archive size
  RINOK(stream->Seek(0, STREAM_SEEK_END, &archiveSize));
  RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));

  // Detect format
  RINOK(DetectFormat(stream));

  items.clear();

  if (pkgFormat == PKG_FORMAT_PS3) {
    logDebug(L"Opening as PS3 PKG...");
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

    logDebug(L"PS3 PKG: Loaded " + std::to_wstring(items.size()));
  }
  else if (pkgFormat == PKG_FORMAT_PS4) {
    logDebug(L"Opening as PS4 PKG...");

    HRESULT hr = ps4Handler.ParseHeader(stream);
    if (FAILED(hr)) {
      wchar_t debugMsg[128];
      swprintf_s(debugMsg, L"PS4 PKG: ParseHeader failed with error 0x%08X", hr);
      logDebug(debugMsg);
      return hr;
    }

    logDebug(L"PS4 PKG: Header parsed successfully");

    std::vector<PS4PKGHandler::FileInfo> ps4Items;
    hr = ps4Handler.ParseFileTable(stream, ps4Items);

    if (FAILED(hr)) {
      wchar_t debugMsg[128];
      swprintf_s(debugMsg, L"PS4 PKG: ParseFileTable failed with error 0x%08X", hr);
      logDebug(debugMsg);
      return hr;
    }

    wchar_t debugMsg[256];
    swprintf_s(debugMsg, L"PS4 PKG: ParseFileTable returned %zu items", ps4Items.size());
    logDebug(debugMsg);

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

    swprintf_s(debugMsg, L"PS4 PKG: Loaded %zu total items (metadata + PFS files)", items.size());
    logDebug(debugMsg);
  }

  else if (pkgFormat == PKG_FORMAT_PS5) {
    logDebug(L"Opening as PS5 PKG...");

    HRESULT hr = ps5Handler.ParseHeader(stream);
    if (FAILED(hr)) {
      wchar_t debugMsg[128];
      swprintf_s(debugMsg, L"PS5 PKG: ParseHeader failed with error 0x%08X", hr);
      logDebug(debugMsg);
      return hr;
    }

    logDebug(L"PS5 PKG: Header parsed successfully");

    std::vector<PS5PKGHandler::FileInfo> ps5Items;
    hr = ps5Handler.ParseFileTable(stream, ps5Items, m_ps5RsaDecryptedData);

    if (FAILED(hr)) {
      wchar_t debugMsg[128];
      swprintf_s(debugMsg, L"PS5 PKG: ParseFileTable failed with error 0x%08X", hr);
      logDebug(debugMsg);
      return hr;
    }

    logDebug(L"PS5 PKG: File table parsed successfully");

    items.reserve(ps5Items.size());
    for (const auto& src : ps5Items) {
      FileInfo fi;
      fi.offset = src.offset;
      fi.size = src.size;
      fi.type = src.type;
      fi.flags1 = src.flags1;
      fi.flags2 = src.flags2;
      fi.keyIndex = src.keyIndex;
      fi.isEncrypted = src.isEncrypted;
      fi.path = src.path;
      items.push_back(std::move(fi));
    }

    logDebug(std::wstring(L"PS5 PKG: Loaded ") + std::to_wstring(items.size()) + L" entries");
  }

  else if (pkgFormat == PKG_FORMAT_PS3_PUP || pkgFormat == PKG_FORMAT_PS4_PUP || pkgFormat == PKG_FORMAT_PS5_PUP) {
    const char* pupType =
      (pkgFormat == PKG_FORMAT_PS3_PUP) ? "PS3 PUP" :
      (pkgFormat == PKG_FORMAT_PS4_PUP) ? "PS4 PUP" : "PS5 PUP";

    logDebug(
      std::wstring(L"Opening as ") +
      std::wstring(pupType, pupType + strlen(pupType)) +
      L"..."
    );

    RINOK(pupHandler.ParseHeader(stream, archiveSize));

    std::vector<PUPHandler::FileInfo> pupItems;
    RINOK(pupHandler.ParseFileTable(stream, pupItems));

    items.reserve(pupItems.size());
    for (const auto& pupItem : pupItems) {
      FileInfo fi;
      fi.offset = pupItem.offset;
      fi.size = pupItem.size;
      fi.uncompressed_size = pupItem.uncompressed_size;
      fi.entryId = pupItem.entryId;
      fi.entryIndex = pupItem.entryIndex;
      fi.tableIndex = pupItem.tableIndex;
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

    logDebug(
      std::wstring(L"") +
      std::wstring(pupType, pupType + strlen(pupType)) +
      L": Loaded " +
      std::to_wstring(items.size())
    );

  }
  else {
    logDebug(L"ERROR: Unknown format");
    return E_FAIL;
  }

  logDebug(std::wstring(L"OPEN SUCCESS – ") + std::to_wstring(items.size()));
  return S_OK;
}

HRESULT PSXHandler::ExtractFile(size_t index, ISequentialOutStream* outStream, IArchiveExtractCallback* callback) {
  if (index >= items.size()) {
    logDebug(L"ExtractFile: Invalid index " + std::to_wstring(index));
    return E_FAIL;
  }

  if (!m_stream) {
    logDebug(L"ExtractFile: No stream available");
    return E_FAIL;
  }

  FileInfo& item = items[index];

  if (item.isFolder) {
    logDebug(L"ExtractFile: Skipping folder: " + std::wstring(item.path.begin(), item.path.end()));
    return S_OK;
  }

  uint64_t displaySize = (item.uncompressed_size > 0) ? item.uncompressed_size : item.size;
  logDebug(
    L"ExtractFile: Extracting [" + std::to_wstring(index) + L"] " +
    std::wstring(item.path.begin(), item.path.end()) +
    L" (" + std::to_wstring(displaySize) + L" bytes)"
  );

  HRESULT hr = S_OK;

  switch (pkgFormat) {
  case PKG_FORMAT_PS3: {
    // Create proper PS3PKGHandler::FileInfo structure
    PS3PKGHandler::FileInfo ps3Item;
    ps3Item.offset = item.offset;
    ps3Item.size = item.size;
    ps3Item.flags = item.flags;
    ps3Item.type = item.type;
    ps3Item.path = item.path;
    ps3Item.isFolder = item.isFolder;
    ps3Item.fileTime1 = item.fileTime1;
    ps3Item.fileTime2 = item.fileTime2;
    ps3Item.fileTime3 = item.fileTime3;

    hr = ps3Handler.ExtractFileToStream(m_stream, ps3Item, outStream);
    break;
  }

  case PKG_FORMAT_PS4: {
    // Create proper PS4PKGHandler::FileInfo structure
    PS4PKGHandler::FileInfo ps4Item;
    ps4Item.offset = item.offset;
    ps4Item.size = item.size;
    ps4Item.flags = item.flags;
    ps4Item.type = item.type;
    ps4Item.path = item.path;
    ps4Item.isFolder = item.isFolder;
    ps4Item.fileTime1 = item.fileTime1;
    ps4Item.fileTime2 = item.fileTime2;
    ps4Item.fileTime3 = item.fileTime3;
	

    hr = ps4Handler.ExtractFileData(m_stream, ps4Item);
    break;
  }

  case PKG_FORMAT_PS5: {
    PS5PKGHandler::FileInfo ps5Item = {};
    ps5Item.offset = item.offset;
    ps5Item.size = item.size;
    ps5Item.type = item.type;
    ps5Item.flags1 = item.flags1;
    ps5Item.flags2 = item.flags2;
    ps5Item.keyIndex = item.keyIndex;
    ps5Item.isEncrypted = item.isEncrypted;
    ps5Item.path = item.path;

    hr = ps5Handler.ExtractFileToStream(m_stream, ps5Item, outStream, m_ps5RsaDecryptedData);
    break;
  }

  case PKG_FORMAT_PS3_PUP:
  case PKG_FORMAT_PS4_PUP:
  case PKG_FORMAT_PS5_PUP: {
    PUPHandler::FileInfo pupItem = {};
    pupItem.offset = item.offset;
    pupItem.size = item.size;
    pupItem.uncompressed_size = item.uncompressed_size;
    pupItem.entryId = item.entryId;
    pupItem.entryIndex = item.entryIndex;
    pupItem.tableIndex = item.tableIndex;
    pupItem.type = item.type;
    pupItem.flags = item.flags;
    pupItem.isFolder = item.isFolder;
    pupItem.isCompressed = item.isCompressed;
    pupItem.isBlocked = item.isBlocked;
    pupItem.path = item.path;

    hr = pupHandler.ExtractFileToStream(m_stream, pupItem, outStream);
    if (hr == E_NOTIMPL && pupItem.isCompressed) {
      logDebug(L"WARNING: Compressed PUP file extraction not implemented: " +
        std::wstring(item.path.begin(), item.path.end()));
      return E_NOTIMPL;
    }
    break;
  }

  default:
    logDebug(L"ExtractFile: Unsupported format");
    return E_INVALIDARG;
  }

  RINOK(hr);

  logDebug(L"ExtractFile: Successfully extracted " + std::wstring(item.path.begin(), item.path.end()));
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