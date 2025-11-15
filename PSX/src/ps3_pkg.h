#pragma once
#include <windows.h>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <string>
#include "PS3_PKG_Crypto.h"
#include "log.h"
#include "sha.h"
#include "sfo.h"

// ---------------------------------------------------------------------
// PS3 PKG constants
// ---------------------------------------------------------------------
#define PKG_MAGIC_PS3 0x7F504B47
#define PS3_SELF      0x53434500

enum PKG_TYPE {
  PKG_TYPE_PS3 = 0x0001,
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
  uint32_t pkg_info_offset;
  uint32_t pkg_info_count;
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

static inline uint32_t SwapEndian32(uint32_t v) { return _byteswap_ulong(v); }
static inline uint64_t SwapEndian64(uint64_t v) { return _byteswap_uint64(v); }
static inline uint16_t SwapEndian16(uint16_t v) { return _byteswap_ushort(v); }

// ---------------------------------------------------------------------
// PS3 PKG Handler Class - WITH TYPE 0x0001 DETECTION
// ---------------------------------------------------------------------
class PS3PKGHandler {
private:
  PKG_HEADER_PS3 header = {};
  bool isEncrypted = false;
  bool isHomebrew = false;
  bool useRetailKey = false;
  bool useAES_ForType1 = false;

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

  // Pass the flag to crypto module
  void DecryptData(uint8_t* data, size_t size, uint64_t relativeOffset) {
    if (!isEncrypted || size == 0) return;

    PS3Crypto::DecryptPS3PKG(
      data,
      size,
      relativeOffset,
      header.pkg_data_riv,
      header.digest,
      header.pkg_type,
      useAES_ForType1);
  }

public:
  struct FileInfo {
    uint64_t  offset = 0;
    uint64_t  size = 0;
    uint32_t  flags = 0;
    uint32_t  type = 0;
    std::string path;
    bool      isFolder = false;
    int64_t   fileTime1 = 0;
    int64_t   fileTime2 = 0;
    int64_t   fileTime3 = 0;
  };

  HRESULT ParseHeader(IInStream* stream) {
    RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));

    UInt32 read = 0;

    // Read magic
    RINOK(stream->Read(&header.magic, 4, &read));
    if (read != 4) {
      logDebug(L"PS3 PKG: Failed to read magic\n");
      return E_FAIL;
    }

    header.magic = SwapEndian32(header.magic);

    if (header.magic != PKG_MAGIC_PS3) {
      logDebug(L"PS3 PKG: Invalid magic\n");
      return E_FAIL;
    }

    // Read pkg_revision (0x04)
    RINOK(stream->Read(&header.pkg_revision, 2, &read));
    if (read != 2) return E_FAIL;
    header.pkg_revision = SwapEndian16(header.pkg_revision);

    // Read pkg_type (0x06)
    RINOK(stream->Read(&header.pkg_type, 2, &read));
    if (read != 2) return E_FAIL;
    header.pkg_type = SwapEndian16(header.pkg_type);

    // Read pkg_metadata_offset (0x08)
    RINOK(stream->Read(&header.pkg_metadata_offset, 4, &read));
    if (read != 4) return E_FAIL;
    header.pkg_metadata_offset = SwapEndian32(header.pkg_metadata_offset);

    // Read pkg_metadata_count (0x0C)
    RINOK(stream->Read(&header.pkg_metadata_count, 4, &read));
    if (read != 4) return E_FAIL;
    header.pkg_metadata_count = SwapEndian32(header.pkg_metadata_count);

    // Read pkg_metadata_size (0x10)
    RINOK(stream->Read(&header.pkg_metadata_size, 4, &read));
    if (read != 4) return E_FAIL;
    header.pkg_metadata_size = SwapEndian32(header.pkg_metadata_size);

    // Read item_count (0x14)
    RINOK(stream->Read(&header.item_count, 4, &read));
    if (read != 4) return E_FAIL;
    header.item_count = SwapEndian32(header.item_count);

    // Read total_size (0x18)
    RINOK(stream->Read(&header.total_size, 8, &read));
    if (read != 8) return E_FAIL;
    header.total_size = SwapEndian64(header.total_size);

    // Read data_offset (0x20)
    RINOK(stream->Read(&header.data_offset, 8, &read));
    if (read != 8) return E_FAIL;
    header.data_offset = SwapEndian64(header.data_offset);

    // Read data_size (0x28)
    RINOK(stream->Read(&header.data_size, 8, &read));
    if (read != 8) return E_FAIL;
    header.data_size = SwapEndian64(header.data_size);

    // Read pkg_info_offset (0x30)
    RINOK(stream->Read(&header.pkg_info_offset, 4, &read));
    if (read != 4) return E_FAIL;
    header.pkg_info_offset = SwapEndian32(header.pkg_info_offset);

    // Read pkg_info_count (0x34)
    RINOK(stream->Read(&header.pkg_info_count, 4, &read));
    if (read != 4) return E_FAIL;
    header.pkg_info_count = SwapEndian32(header.pkg_info_count);

    // Read content_id (at 0x30 in file)
    RINOK(stream->Seek(0x30, STREAM_SEEK_SET, nullptr));
    RINOK(stream->Read(header.content_id, 0x30, &read));
    if (read != 0x30) return E_FAIL;
    header.content_id[0x2F] = '\0';

    // Read digest (QA digest at 0x60)
    RINOK(stream->Read(header.digest, 0x10, &read));
    if (read != 0x10) return E_FAIL;

    // Read pkg_data_riv (at 0x70)
    RINOK(stream->Read(header.pkg_data_riv, 0x10, &read));
    if (read != 0x10) return E_FAIL;

    // Simple check: if type is 1, 0x8001, 0x8002, or 0x80000001/2, it's encrypted
    isEncrypted = (header.pkg_type == 1 ||
      header.pkg_type == 0x8001 ||
      header.pkg_type == 0x8002 ||
      header.pkg_type == 0x80000001 ||
      header.pkg_type == 0x80000002);

    // CRITICAL: Detect encryption method for type 0x0001
    if (header.pkg_type == 1 && isEncrypted) {
      logDebug(L"PS3 PKG: Type 0x0001 detected - testing encryption method...\n");

      // Read first 32 bytes of encrypted data to test
      std::vector<uint8_t> testBuf(32);
      RINOK(stream->Seek(header.data_offset, STREAM_SEEK_SET, nullptr));
      RINOK(stream->Read(testBuf.data(), 32, &read));
      if (read != 32) {
        logDebug(L"PS3 PKG: Failed to read test data\n");
        return E_FAIL;
      }

      bool aesWorks = PS3Crypto::TestAESDecryption(
        testBuf.data(),
        32,
        header.pkg_data_riv,
        PS3Crypto::PS3_PKG_AES_KEY
      );

      useAES_ForType1 = aesWorks;

      wchar_t debugMsg[256];
      swprintf_s(debugMsg, L"PS3 PKG: Type 0x0001 uses %s encryption\n",
        useAES_ForType1 ? L"AES" : L"SHA1");
      logDebug(debugMsg);
    }

    // Debug output
    wchar_t debugMsg[512];

    swprintf_s(debugMsg, L"PS3 PKG Header: pkg_type=0x%04X, item_count=%u, data_offset=0x%llX, data_size=0x%llX, isEncrypted=%d\n",
      header.pkg_type, header.item_count, header.data_offset, header.data_size, isEncrypted);
    logDebug(debugMsg);

    swprintf_s(debugMsg, L"PS3 PKG Content ID: %hs\n", header.content_id);
    logDebug(debugMsg);

    swprintf_s(debugMsg, L"Digest (0x60): %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
      header.digest[0], header.digest[1], header.digest[2], header.digest[3],
      header.digest[4], header.digest[5], header.digest[6], header.digest[7],
      header.digest[8], header.digest[9], header.digest[10], header.digest[11],
      header.digest[12], header.digest[13], header.digest[14], header.digest[15]);
    logDebug(debugMsg);

    swprintf_s(debugMsg, L"RIV (0x70): %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
      header.pkg_data_riv[0], header.pkg_data_riv[1], header.pkg_data_riv[2], header.pkg_data_riv[3],
      header.pkg_data_riv[4], header.pkg_data_riv[5], header.pkg_data_riv[6], header.pkg_data_riv[7],
      header.pkg_data_riv[8], header.pkg_data_riv[9], header.pkg_data_riv[10], header.pkg_data_riv[11],
      header.pkg_data_riv[12], header.pkg_data_riv[13], header.pkg_data_riv[14], header.pkg_data_riv[15]);
    logDebug(debugMsg);

    // Validate header values
    if (header.item_count == 0 || header.item_count > 100000) {
      swprintf_s(debugMsg, L"PS3 PKG: Invalid item_count: %u\n", header.item_count);
      logDebug(debugMsg);
      return E_FAIL;
    }

    if (header.data_offset == 0 || header.data_size == 0) {
      swprintf_s(debugMsg, L"PS3 PKG: Invalid data_offset (0x%llX) or data_size (0x%llX)\n",
        header.data_offset, header.data_size);
      logDebug(debugMsg);
      return E_FAIL;
    }

    logDebug(L"PS3 PKG: Header parsed successfully\n");
    return S_OK;
  }

  HRESULT ParseFileTable(IInStream* stream, std::vector<FileInfo>& items) {
    char debugMsg[512];

    auto LOGA = [&](const char* m) {
      if (!m) return;
      size_t len = strlen(m);
      logDebug(std::wstring(m, m + len));
      };

    uint64_t tableStart = header.data_offset;
    sprintf_s(debugMsg, "ParseFileTable: Starting at data_offset=0x%llX\n", tableStart);
    LOGA(debugMsg);

    std::vector<uint8_t> sizeBuf;
    HRESULT hr = ReadAndDecryptBlock(stream, tableStart, 32, sizeBuf);
    if (FAILED(hr)) {
      sprintf_s(debugMsg, "ParseFileTable: FAILED to read/decrypt first 32 bytes (HRESULT=0x%X)\n", hr);
      LOGA(debugMsg);
      return hr;
    }

    uint64_t tableSize = SwapEndian64(*(uint64_t*)(sizeBuf.data() + 8));

    sprintf_s(debugMsg, "ParseFileTable: tableSize=0x%llX (from offset +8)\n", tableSize);
    LOGA(debugMsg);

    if (tableSize == 0 || tableSize > header.data_size) {
      sprintf_s(debugMsg, "ParseFileTable: INVALID tableSize (0x%llX), returning E_FAIL\n", tableSize);
      LOGA(debugMsg);
      return E_FAIL;
    }

    // Read full table
    std::vector<uint8_t> tableData;
    hr = ReadAndDecryptBlock(stream, tableStart, tableSize, tableData);
    if (FAILED(hr)) {
      sprintf_s(debugMsg, "ParseFileTable: FAILED to read/decrypt table (size=0x%llX, HRESULT=0x%X)\n",
        tableSize, hr);
      LOGA(debugMsg);
      return hr;
    }

    sprintf_s(debugMsg, "ParseFileTable: Successfully read and decrypted 0x%llX bytes\n", tableSize);
    LOGA(debugMsg);

    const size_t ENTRY_SIZE = 32;
    size_t nameReadOffset = header.item_count * ENTRY_SIZE;

    sprintf_s(debugMsg, "ParseFileTable: item_count=%u, nameReadOffset starts at 0x%zX\n",
      header.item_count, nameReadOffset);
    LOGA(debugMsg);

    for (uint32_t i = 0; i < header.item_count; i++) {
      size_t entryPos = i * ENTRY_SIZE;

      if (entryPos + ENTRY_SIZE > tableData.size()) {
        sprintf_s(debugMsg, "ParseFileTable: Entry %u at 0x%zX exceeds table size, stopping\n",
          i, entryPos);
        LOGA(debugMsg);
        break;
      }

      const uint8_t* p = tableData.data() + entryPos;

      uint32_t nameOff = SwapEndian32(*(uint32_t*)(p + 0x00));
      uint32_t nameLen = SwapEndian32(*(uint32_t*)(p + 0x04));
      uint32_t dataOff = SwapEndian32(*(uint32_t*)(p + 0x0C));  // 4-byte offset
      uint32_t dataSz = SwapEndian32(*(uint32_t*)(p + 0x14));   // 4-byte size
      uint32_t flags = SwapEndian32(*(uint32_t*)(p + 0x18));    // type/flags

      sprintf_s(debugMsg, "Entry %u: nameOff=0x%X, nameLen=%u, dataOff=0x%X, dataSz=%u, flags=0x%X\n",
        i, nameOff, nameLen, dataOff, dataSz, flags);
      LOGA(debugMsg);

      if (nameLen == 0 || nameLen > 4096) {
        sprintf_s(debugMsg, "  Skipping entry %u: invalid nameLen=%u\n", i, nameLen);
        LOGA(debugMsg);
        continue;
      }

      FileInfo fi;
      fi.offset = header.data_offset + dataOff;
      fi.size = dataSz;
      fi.flags = flags;
      fi.type = flags & 0xFF;
      fi.isFolder = (fi.type == 0x04) || (fi.type == 0x05); 

      if (!fi.isFolder && dataSz == 0 && dataOff == 0) {
        fi.isFolder = true; 
      }

      // Read filename from the name table section
      if (nameReadOffset < tableData.size() && nameReadOffset + nameLen <= tableData.size()) {
        const char* namePtr = reinterpret_cast<const char*>(tableData.data() + nameReadOffset);
        fi.path.assign(namePtr, nameLen);

        // Remove null terminator if present
        size_t nul = fi.path.find('\0');
        if (nul != std::string::npos) fi.path.resize(nul);

        // Convert path separators
        std::replace(fi.path.begin(), fi.path.end(), '\\', '/');

        sprintf_s(debugMsg, "  Entry %u: path='%s', size=%u, type=0x%02X, isFolder=%d\n",
          i, fi.path.c_str(), fi.size, fi.type, fi.isFolder);
        LOGA(debugMsg);
      }
      else {
        fi.path = "file_" + std::to_string(i);
        sprintf_s(debugMsg, "  Entry %u: name out of bounds, using fallback '%s'\n",
          i, fi.path.c_str());
        LOGA(debugMsg);
      }

      items.push_back(std::move(fi));

      nameReadOffset += nameLen;
      while (nameReadOffset % 16 != 0) nameReadOffset++;
    }

    sprintf_s(debugMsg, "ParseFileTable: SUCCESS - parsed %zu items\n", items.size());
    LOGA(debugMsg);

    return S_OK;
  }

  HRESULT ExtractFileToStream(IInStream* inStream, const FileInfo& fi, ISequentialOutStream* outStream) {
    if (fi.isFolder || fi.size == 0) return S_OK;

    const size_t CHUNK_SIZE = 2 * 1024 * 1024;
    std::vector<uint8_t> buffer;
    buffer.reserve(CHUNK_SIZE);

    uint64_t remaining = fi.size;
    uint64_t currentOffset = fi.offset;

    while (remaining > 0) {
      size_t toRead = (size_t)std::min((uint64_t)CHUNK_SIZE, remaining);
      buffer.resize(toRead);

      UInt32 read = 0;
      RINOK(inStream->Seek(currentOffset, STREAM_SEEK_SET, nullptr));
      RINOK(inStream->Read(buffer.data(), (UInt32)toRead, &read));
      if (read != toRead) return E_FAIL;

      if (isEncrypted) {
        uint64_t rel = currentOffset - header.data_offset;
        DecryptData(buffer.data(), toRead, rel);
      }

      UInt32 written = 0;
      RINOK(outStream->Write(buffer.data(), (UInt32)toRead, &written));
      if (written != toRead) return E_FAIL;

      remaining -= toRead;
      currentOffset += toRead;
    }

    return S_OK;
  }

  const PKG_HEADER_PS3& GetHeader() const { return header; }
  bool IsEncrypted() const { return isEncrypted; }

  
};

class PS3PKGWriter
{
public:
  PS3PKGWriter() {}

  HRESULT addItem(const std::string& path, UInt64 size, IInStream* stream, bool isFolder, UInt32 flags)
  {
    for (const auto& existing : m_files) {
      if (existing.path == path) {
        logDebug(L"WARNING: Duplicate entry detected for path: " + std::wstring(path.begin(), path.end()));
        logDebug(std::wstring(L"  Existing: ") + (existing.isFolder ? L"DIR" : L"FILE") +
          L" size=" + std::to_wstring(existing.size));

        logDebug(std::wstring(L"  New:      ") + (isFolder ? L"DIR" : L"FILE") +
          L" size=" + std::to_wstring(size));

        logDebug(L"  Skipping duplicate entry!");
        return S_OK;
      }
    }

    FileEntry entry;
    entry.path = path;
    entry.size = size;
    entry.stream = stream;
    entry.isFolder = isFolder;
    entry.flags = flags;

    logDebug(std::wstring(L"Adding: ") + (isFolder ? L"DIR  " : L"FILE ") +
      L"size=" + std::to_wstring(size) + L" " +
      std::wstring(path.begin(), path.end()));


    m_files.push_back(entry);

    if (!isFolder) {
      m_totalDataSize += size;
      if (size % 16) {
        m_totalDataSize += (16 - (size % 16));
      }
    }

    return S_OK;
  }

  HRESULT addItemWithBuffer(const std::string& path, UInt64 size, std::vector<Byte>&& buffer, bool isFolder, UInt32 flags)
  {
    m_ownedBuffers.push_back(std::move(buffer));

    CMyComPtr<CLimitedCachedInStream> limitedStream = new CLimitedCachedInStream;
    CMyComPtr<CEmptyInStream> dummyStream = new CEmptyInStream();
    limitedStream->SetStream(dummyStream, 0);

    auto& preload = limitedStream->Buffer;
    preload.Alloc(m_ownedBuffers.back().size());
    memcpy(preload, m_ownedBuffers.back().data(), m_ownedBuffers.back().size());

    limitedStream->SetCache(m_ownedBuffers.back().size(), 0);
    RINOK(limitedStream->InitAndSeek(0, m_ownedBuffers.back().size()));

    return addItem(path, size, limitedStream, isFolder, flags);
  }

  HRESULT addDirectory(const std::string& path)
  {
    FileEntry entry;
    entry.path = path;
    entry.size = 0;           
    entry.stream = nullptr;    
    entry.isFolder = true;     
    entry.flags = 0;           

    // Check for duplicates
    for (const auto& existing : m_files) {
      if (existing.path == path) {
        logDebug(L"WARNING: Duplicate directory for path: " + std::wstring(path.begin(), path.end()));
        return S_OK;
      }
    }

    logDebug(L"Adding: DIR  size=0 " + std::wstring(path.begin(), path.end()));
    m_files.push_back(entry);

    return S_OK;
  }

  HRESULT addFile(const std::string& path, UInt64 size, IInStream* stream)
  {
    return addItem(path, size, stream, false, 0); 
  }

  HRESULT writePKG(ISequentialOutStream* outStream, IArchiveUpdateCallback* callback, const std::string& contentID, const std::string& sfoPath = "", bool isRetail = false)
  {
    // DIAGNOSTIC: Print file structure BEFORE writing
    logDebug(L"\n========================================");
    logDebug(L"PKG FILE STRUCTURE BEFORE WRITING:");
    logDebug(L"========================================");
    logDebug(L"Total entries: " + std::to_wstring(m_files.size()));
    logDebug(L"Total data size: " + std::to_wstring(m_totalDataSize));

    for (size_t i = 0; i < m_files.size(); i++) {
      const auto& f = m_files[i];
      std::wstring type = f.isFolder ? L"DIR " : L"FILE";
      std::wstring stream_info = (f.stream != nullptr) ? L"stream=YES" : L"stream=NO ";
      std::wstring flags_str = L"0x" + std::to_wstring(f.flags);

      logDebug(L"[" + std::to_wstring(i) + L"] " + type +
        L" size=" + std::to_wstring(f.size) +
        L" flags=" + flags_str +
        L" " + stream_info +
        L" path=" + std::wstring(f.path.begin(), f.path.end()));
    }
    logDebug(L"========================================\n");

    try {
      logDebug(L"PKGWriter: Building PS3 PKG...");

      if (!outStream) {
        logDebug(L"PKGWriter: ERROR - outStream is NULL");
        return E_POINTER;
      }

      if (!callback) {
        logDebug(L"PKGWriter: ERROR - callback is NULL");
        return E_POINTER;
      }

      uint64_t fileEntryTableSize = 0;
      uint64_t filenameTableSize = 0;
      uint64_t fileDataSize = 0;

      std::vector<uint32_t> filenameOffsets;
      filenameOffsets.reserve(m_files.size());

      for (const auto& f : m_files) {
        fileEntryTableSize += 0x20;

        uint32_t filenameOffset = (uint32_t)filenameTableSize;
        filenameOffsets.push_back(filenameOffset);

        size_t filenameBytesLength = f.path.length();
        filenameTableSize += filenameBytesLength;

        if (filenameBytesLength % 0x10 > 0) {
          filenameTableSize += 0x10 - (filenameBytesLength % 0x10);
        }

        if (!f.isFolder) {
          fileDataSize += f.size;
          if (f.size % 0x10 > 0) {
            fileDataSize += 0x10 - (f.size % 0x10);
          }
        }
      }

      uint64_t encryptedBodySize = fileEntryTableSize + filenameTableSize + fileDataSize;

      logDebug(L"PKGWriter: File table size: " + std::to_wstring(fileEntryTableSize));
      logDebug(L"PKGWriter: Filename table size: " + std::to_wstring(filenameTableSize));
      logDebug(L"PKGWriter: File data size: " + std::to_wstring(fileDataSize));
      logDebug(L"PKGWriter: Total encrypted body: " + std::to_wstring(encryptedBodySize));

      std::vector<uint8_t> metadataEntries;

      // 1. DRM Type = 3 (Free)
      {
        uint32_t type = SwapEndian32(0x0001);
        uint32_t size = SwapEndian32(4);
        uint32_t value = SwapEndian32(0x00000003);
        metadataEntries.insert(metadataEntries.end(), (uint8_t*)&type, (uint8_t*)&type + 4);
        metadataEntries.insert(metadataEntries.end(), (uint8_t*)&size, (uint8_t*)&size + 4);
        metadataEntries.insert(metadataEntries.end(), (uint8_t*)&value, (uint8_t*)&value + 4);
      }

      // 2. Content Type = 4 (GameData)
      {
        uint32_t type = SwapEndian32(0x0002);
        uint32_t size = SwapEndian32(4);
        uint32_t value = SwapEndian32(0x00000004);
        metadataEntries.insert(metadataEntries.end(), (uint8_t*)&type, (uint8_t*)&type + 4);
        metadataEntries.insert(metadataEntries.end(), (uint8_t*)&size, (uint8_t*)&size + 4);
        metadataEntries.insert(metadataEntries.end(), (uint8_t*)&value, (uint8_t*)&value + 4);
      }

      // 3. Package Flags = 0 (None)
      {
        uint32_t type = SwapEndian32(0x0003);
        uint32_t size = SwapEndian32(4);
        uint32_t value = SwapEndian32(0x00000000);
        metadataEntries.insert(metadataEntries.end(), (uint8_t*)&type, (uint8_t*)&type + 4);
        metadataEntries.insert(metadataEntries.end(), (uint8_t*)&size, (uint8_t*)&size + 4);
        metadataEntries.insert(metadataEntries.end(), (uint8_t*)&value, (uint8_t*)&value + 4);
      }

      // 4. Package Size = encryptedBodySize
      {
        uint32_t type = SwapEndian32(0x0004);
        uint32_t size = SwapEndian32(8);
        uint64_t value = SwapEndian64(encryptedBodySize);
        metadataEntries.insert(metadataEntries.end(), (uint8_t*)&type, (uint8_t*)&type + 4);
        metadataEntries.insert(metadataEntries.end(), (uint8_t*)&size, (uint8_t*)&size + 4);
        metadataEntries.insert(metadataEntries.end(), (uint8_t*)&value, (uint8_t*)&value + 8);
      }

      const uint64_t SIGNED_FOOTER_SIZE = 0x40;
      uint32_t totalMetadataSize = (uint32_t)metadataEntries.size() + SIGNED_FOOTER_SIZE;
      uint32_t metadataCount = 4;
      uint64_t metadataOffset = 0xC0;
      uint64_t dataOffset = metadataOffset + totalMetadataSize;
      uint64_t totalPkgSize = 0xC0 + totalMetadataSize + encryptedBodySize + 0x40 + 0x20;

      logDebug(L"PKGWriter: Total PKG size: " + std::to_wstring(totalPkgSize));

      std::vector<uint8_t> headerBuf(0x80, 0);

      // Magic
      *(uint32_t*)(headerBuf.data() + 0x00) = SwapEndian32(0x7F504B47);

      // Revision
      if (isRetail) {
        *(uint16_t*)(headerBuf.data() + 0x04) = SwapEndian16(0x8000);
      }
      else {
        *(uint16_t*)(headerBuf.data() + 0x04) = SwapEndian16(0x0000);
      }

      // Type
      *(uint16_t*)(headerBuf.data() + 0x06) = SwapEndian16(0x0001);

      // Metadata fields
      *(uint32_t*)(headerBuf.data() + 0x08) = SwapEndian32((uint32_t)metadataOffset);
      *(uint32_t*)(headerBuf.data() + 0x0C) = SwapEndian32(metadataCount);
      *(uint32_t*)(headerBuf.data() + 0x10) = SwapEndian32(totalMetadataSize);
      *(uint32_t*)(headerBuf.data() + 0x14) = SwapEndian32((uint32_t)m_files.size());
      *(uint64_t*)(headerBuf.data() + 0x18) = SwapEndian64(totalPkgSize);
      *(uint64_t*)(headerBuf.data() + 0x20) = SwapEndian64(dataOffset);
      *(uint64_t*)(headerBuf.data() + 0x28) = SwapEndian64(encryptedBodySize);

      // ===================================================================
      // UPDATED: Content ID with SFO Reader Integration
      // ===================================================================
      std::string finalContentID = contentID;

      // If no Content ID provided, try to read from PARAM.SFO
      if (finalContentID.empty() && !sfoPath.empty()) {
        finalContentID = SFOReader::getContentID(sfoPath);
        if (!finalContentID.empty()) {
          logDebug(L"PKGWriter: Using Content ID from PARAM.SFO: " +
            std::wstring(finalContentID.begin(), finalContentID.end()));
        }
        else {
          logDebug(L"PKGWriter: Could not read Content ID from PARAM.SFO: " +
            std::wstring(sfoPath.begin(), sfoPath.end()));
        }
      }

      // Content ID (0x30 bytes, null-padded)
      const char* cid = finalContentID.empty() ? "UP9000-NPUB12345_00-0000000000000000" : finalContentID.c_str();
      memset(headerBuf.data() + 0x30, 0, 0x30);
      size_t cidLen = strlen(cid);
      if (cidLen > 0x2F) cidLen = 0x2F;
      memcpy(headerBuf.data() + 0x30, cid, cidLen);

      logDebug(L"PKGWriter: Content ID: " + std::wstring(cid, cid + cidLen));
      // ===================================================================

      // Debug digest (zeros)
      memset(headerBuf.data() + 0x60, 0, 0x10);

      // Package IV
      memcpy(headerBuf.data() + 0x70, PS3Crypto::pkg_iv, 0x10);

      // Generate header digest
      std::vector<uint8_t> headerDigest(0x40);
      PS3Crypto::GeneratePKGDigest(headerBuf.data(), 0x80, headerDigest.data());

      SHA1 sha1;

      // Write header + digest (0xC0 total)
      UInt32 written = 0;
      RINOK(outStream->Write(headerBuf.data(), 0x80, &written));
      if (written != 0x80) return E_FAIL;
      sha1.update(headerBuf.data(), 0x80);

      RINOK(outStream->Write(headerDigest.data(), 0x40, &written));
      if (written != 0x40) return E_FAIL;
      sha1.update(headerDigest.data(), 0x40);

      // Write metadata entries
      RINOK(outStream->Write(metadataEntries.data(), (UInt32)metadataEntries.size(), &written));
      if (written != metadataEntries.size()) return E_FAIL;
      sha1.update(metadataEntries.data(), metadataEntries.size());

      // Generate and write metadata digest
      std::vector<uint8_t> metaDigest(0x40);
      PS3Crypto::GeneratePKGDigest(metadataEntries.data(), (uint32_t)metadataEntries.size(), metaDigest.data());
      RINOK(outStream->Write(metaDigest.data(), 0x40, &written));
      if (written != 0x40) return E_FAIL;
      sha1.update(metaDigest.data(), 0x40);

      std::vector<uint8_t> fileTable(fileEntryTableSize, 0);
      uint64_t totalFileOffsetUsed = 0;

      for (size_t i = 0; i < m_files.size(); ++i) {
        const auto& f = m_files[i];
        uint8_t* entry = fileTable.data() + i * 0x20;

        // FilenameOffset (relative to start of encrypted body)
        uint32_t fnOffset = (uint32_t)(fileEntryTableSize + filenameOffsets[i]);
        *(uint32_t*)(entry + 0x00) = SwapEndian32(fnOffset);

        // FilenameSize
        *(uint32_t*)(entry + 0x04) = SwapEndian32((uint32_t)f.path.length());

        // DataOffset - Match C# behavior exactly
        uint64_t dataOffsetValue = fileEntryTableSize + filenameTableSize + totalFileOffsetUsed;
        *(uint64_t*)(entry + 0x08) = SwapEndian64(dataOffsetValue);

        // DataSize
        *(uint64_t*)(entry + 0x10) = SwapEndian64(f.size);

        uint32_t flags = f.flags;
        if (flags == 0) {
          if (f.isFolder) {
            flags = 0x80000004; // Directory | Overwrites
          }
          else {
            flags = 0x80000000; // Overwrites only
          }
        }
        *(uint32_t*)(entry + 0x18) = SwapEndian32(flags);

        // Padding
        *(uint32_t*)(entry + 0x1C) = SwapEndian32(0);

        // Increment offset tracker (only for files, not directories)
        if (!f.isFolder) {
          totalFileOffsetUsed += f.size;
          if (f.size % 0x10 > 0) {
            totalFileOffsetUsed += 0x10 - (f.size % 0x10);
          }
        }
      }

      // Build filename table
      std::vector<uint8_t> filenameTable(filenameTableSize, 0);
      size_t namePos = 0;
      for (const auto& f : m_files) {
        size_t len = f.path.length();
        memcpy(filenameTable.data() + namePos, f.path.c_str(), len);
        namePos += len;
        // Align to 16 bytes
        if (namePos % 0x10 > 0) {
          namePos += 0x10 - (namePos % 0x10);
        }
      }

      // Encrypt and write file table
      PS3Crypto::EncryptPS3PKG(fileTable.data(), fileTable.size(), 0, PS3Crypto::pkg_iv, nullptr, 0x0001, true);
      RINOK(outStream->Write(fileTable.data(), (UInt32)fileTable.size(), &written));
      if (written != fileTable.size()) return E_FAIL;
      sha1.update(fileTable.data(), fileTable.size());

      // Encrypt and write filename table
      PS3Crypto::EncryptPS3PKG(filenameTable.data(), filenameTable.size(), fileEntryTableSize, PS3Crypto::pkg_iv, nullptr, 0x0001, true);
      RINOK(outStream->Write(filenameTable.data(), (UInt32)filenameTable.size(), &written));
      if (written != filenameTable.size()) return E_FAIL;
      sha1.update(filenameTable.data(), filenameTable.size());

      // Write file data
      const size_t BUFFER_SIZE = 4 * 1024 * 1024;
      std::vector<uint8_t> buffer(BUFFER_SIZE);
      UInt64 completed = 0;
      callback->SetTotal(fileDataSize);

      uint64_t currentDataOffset = fileEntryTableSize + filenameTableSize;

      for (const auto& f : m_files) {
        if (f.isFolder) continue;
        if (f.size == 0) continue;

        RINOK(f.stream->Seek(0, STREAM_SEEK_SET, nullptr));

        UInt64 remaining = f.size;
        while (remaining > 0) {
          UInt32 toRead = (UInt32)std::min((UInt64)BUFFER_SIZE, remaining);
          UInt32 read = 0;
          RINOK(f.stream->Read(buffer.data(), toRead, &read));
          if (read == 0) return E_FAIL;

          // Encrypt
          PS3Crypto::EncryptPS3PKG(buffer.data(), read, currentDataOffset, PS3Crypto::pkg_iv, nullptr, 0x0001, true);

          RINOK(outStream->Write(buffer.data(), read, &written));
          if (written != read) return E_FAIL;
          sha1.update(buffer.data(), read);

          remaining -= read;
          completed += read;
          currentDataOffset += read;
          callback->SetCompleted(&completed);
        }

        // Write padding for 16-byte alignment
        if (f.size % 0x10 > 0) {
          uint32_t padSize = 0x10 - (f.size % 0x10);
          std::vector<uint8_t> padding(padSize, 0);
          PS3Crypto::EncryptPS3PKG(padding.data(), padSize, currentDataOffset, PS3Crypto::pkg_iv, nullptr, 0x0001, true);
          RINOK(outStream->Write(padding.data(), padSize, &written));
          if (written != padSize) return E_FAIL;
          sha1.update(padding.data(), padSize);
          currentDataOffset += padSize;
        }
      }

      // Write signature (hash of 0x10 zero bytes)
      std::vector<uint8_t> emptyBuf(0x10, 0);
      std::vector<uint8_t> signature(0x40);
      PS3Crypto::GeneratePKGDigest(emptyBuf.data(), 0x10, signature.data());
      RINOK(outStream->Write(signature.data(), 0x40, &written));
      if (written != 0x40) return E_FAIL;
      sha1.update(signature.data(), 0x40);

      // Write final SHA-1 footer (0x20 bytes: 20 SHA-1 + 12 padding)
      std::vector<uint8_t> finalFooter(0x20, 0);
      sha1.finalize(finalFooter.data());

      RINOK(outStream->Write(finalFooter.data(), 0x20, &written));
      if (written != 0x20) return E_FAIL;

      callback->SetCompleted(&fileDataSize);
      logDebug(L"PKGWriter: PS3 PKG created successfully!");
      return S_OK;

    }
    catch (const std::exception& e) {
      logDebug(L"PKGWriter: EXCEPTION - " + std::wstring(e.what(), e.what() + strlen(e.what())));
      return E_FAIL;
    }
    catch (...) {
      logDebug(L"PKGWriter: UNKNOWN EXCEPTION");
      return E_FAIL;
    }
  }
  // Helper function: SwapEndian16
  inline uint16_t SwapEndian16(uint16_t val) {
    return (val << 8) | (val >> 8);
  }

private:
  struct FileEntry {
    std::string path;
    UInt64 size = 0;
    CMyComPtr<IInStream> stream;
    bool isFolder = false;
    UInt32 flags = 0;
  };

  std::vector<FileEntry> m_files;
  std::vector<std::vector<Byte>> m_ownedBuffers;
  UInt64 m_totalDataSize = 0;
};