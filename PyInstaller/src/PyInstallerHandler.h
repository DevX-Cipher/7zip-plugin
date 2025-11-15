#define NOMINMAX
#undef min
#undef max
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#include <vector>
#include <string>
#include <sstream>
#include <cstdint>
#include <locale>
#include <map>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <shlobj.h>
#include <algorithm>


#ifdef _DEBUG
static void logDebug(const std::string& message);
static void logDebug(const std::wstring& message);
static void logDebug(const std::wstringstream& wss);
#else
// No-op in release builds
#define logDebug(...) ((void)0)
#endif

#include "zlib_decoder.h"
#include <chrono>
#include <codecvt>

class PyInstallerHandler {
  UInt64 archiveSize;
  uint64_t overlayPos;
public:
  HRESULT Open(IInStream* stream, const UInt64*, IArchiveOpenCallback* callback);
  CMyComPtr<IArchiveOpenVolumeCallback> volCallback;
  HRESULT ParseArchive(IInStream* stream, UInt64 fileSize);
  HRESULT ReadData(IInStream* stream);
  uint32_t ByteSwap(uint32_t x) {
    return ((x >> 24) & 0x000000FF) |
      ((x >> 8) & 0x0000FF00) |
      ((x << 8) & 0x00FF0000) |
      ((x << 24) & 0xFF000000);
  }

  struct ArchiveEntry {
    uint32_t entryPos;
    uint32_t compressedSize;
    uint32_t uncompressedSize;
    uint8_t compressionFlag;
    std::string compressionType;
    std::string name;
    std::vector<uint8_t> data;
    std::vector<uint8_t> decompressedData;

    ArchiveEntry(uint32_t entryPos, uint32_t compressedSize, uint32_t uncompressedSize,
      uint8_t compressionFlag, const std::string& compressionType,
      const std::string& name)
      : entryPos(entryPos), compressedSize(compressedSize), uncompressedSize(uncompressedSize),
      compressionFlag(compressionFlag), compressionType(compressionType), name(name) {
    }


  };

  // Additional members for handling the PyInstaller archive
  UInt32 lengthofPackage = 0;            // Length of the package
  UInt32 toc = 0;                        // Table of contents
  UInt32 tocLen = 0;                     // Length of TOC
  UInt32 pyver = 0;                      // Python version
  uint64_t cookiePos = -1;               // Position of the cookie
  uint64_t tableOfContentsPos = 0;       // Position of the TOC
  uint64_t tableOfContentsSize = 0;      // Size of the TOC

  const std::string MAGIC = "MEI\014\013\012\013\016"; // Magic bytes for PyInstaller
  std::vector<ArchiveEntry> items;

};
void HandleError(const std::wstring& errorMessage);
void HandleError(const std::wstring& errorMessage) {
  MessageBox(NULL, errorMessage.c_str(), L"Error", MB_ICONERROR);
}
HRESULT SafeRead(IInStream* stream, void* buffer, size_t size, UInt32* bytesRead) {
  HRESULT result = stream->Read(buffer, static_cast<UInt32>(size), bytesRead);
  if (result != S_OK || *bytesRead != size) {
    HandleError(L"Failed to read from stream");
    return S_FALSE;
  }
  return S_OK;
}

static std::wstring getDesktopPath() {
  wchar_t path[MAX_PATH];
  if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_DESKTOP, nullptr, SHGFP_TYPE_CURRENT, path))) {
    return std::wstring(path);
  }
  return L".";
}

#ifdef _DEBUG
static void logDebug(const std::string& message) {
  static std::string logFilePath;
  if (logFilePath.empty()) {
    std::wstring desktopPath = getDesktopPath();
    std::wstring logPathW = desktopPath + L"\\decompression_debug.log";

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, logPathW.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size_needed <= 0) return;

    std::string utf8Path(size_needed - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, logPathW.c_str(), -1, &utf8Path[0], size_needed - 1, nullptr, nullptr);
    logFilePath = utf8Path;
  }

  std::ofstream logFile(logFilePath, std::ios::app);
  if (!logFile.is_open()) return;

  auto now = std::chrono::system_clock::now();
  std::time_t now_c = std::chrono::system_clock::to_time_t(now);
  char timeStr[64] = {};
  ctime_s(timeStr, sizeof(timeStr), &now_c);
  timeStr[strcspn(timeStr, "\n")] = 0;

  logFile << "[" << timeStr << "] " << message << "\n";
}

static void logDebug(const std::wstring& message) {
  int size_needed = WideCharToMultiByte(CP_UTF8, 0, message.c_str(), -1, nullptr, 0, nullptr, nullptr);
  if (size_needed <= 0) return;

  std::string utf8Message(size_needed - 1, 0);
  WideCharToMultiByte(CP_UTF8, 0, message.c_str(), -1, &utf8Message[0], size_needed - 1, nullptr, nullptr);
  logDebug(utf8Message);
}

static void logDebug(const std::wstringstream& wss) {
  logDebug(wss.str());
}
#endif // _DEBUG

static std::string wideToUtf8(const std::wstring& wstr) {
  if (wstr.empty()) return {};
  int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
  if (size_needed <= 1) return {};
  std::string strTo(size_needed - 1, 0);
  WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &strTo[0], size_needed - 1, nullptr, nullptr);
  return strTo;
}


HRESULT PyInstallerHandler::Open(IInStream* stream, const UInt64*, IArchiveOpenCallback* callback) {
  if (!callback || !stream) {
    logDebug(L"[!] Error: Invalid input parameters to Open()");
    return S_FALSE; // Early return if inputs are invalid
  }

  // Query interface for volume callback
  HRESULT result = callback->QueryInterface(IID_IArchiveOpenVolumeCallback, (void**)&volCallback);
  RINOK(result);

  if (volCallback == nullptr) {
    logDebug(L"[!] Error: Failed to get volume callback interface.");
    return E_FAIL;
  }

  // Initialize and validate the file size
  UInt64 fileSize;
  RINOK(stream->Seek(0, STREAM_SEEK_END, &fileSize));

  const size_t searchChunkSize = 8192;
  uint64_t endPos = fileSize;
  cookiePos = -1;

  // Search for the magic number in reverse
  while (true) {
    uint64_t startPos = endPos >= searchChunkSize ? endPos - searchChunkSize : 0;
    size_t chunkSize = endPos - startPos;
    if (chunkSize < MAGIC.size()) break;

    RINOK(stream->Seek(startPos, STREAM_SEEK_SET, nullptr));
    std::vector<char> data(chunkSize);
    UInt32 bytesRead = 0;
    RINOK(stream->Read(data.data(), static_cast<UInt32>(chunkSize), &bytesRead));

    if (bytesRead != chunkSize) {
      logDebug(L"[!] Warning: Failed to read the stream correctly at offset " + std::to_wstring(startPos));
      return S_FALSE;
    }

    auto offs = std::string(data.data(), chunkSize).rfind(MAGIC);
    if (offs != std::string::npos) {
      cookiePos = startPos + offs;
      break;
    }

    endPos = startPos + MAGIC.size() - 1;
    if (startPos == 0) break;
  }

  if (cookiePos == -1) {
    logDebug(L"[!] Warning: Missing cookie, unsupported PyInstaller version or not a PyInstaller archive");
    return S_FALSE;
  }

  // Read version info
  RINOK(stream->Seek(cookiePos + 8, STREAM_SEEK_SET, nullptr));
  char versionBuffer[64];
  UInt32 bytesRead = 0;
  RINOK(stream->Read(versionBuffer, sizeof(versionBuffer), &bytesRead));

  if (bytesRead < sizeof(uint32_t)) {
    logDebug(L"[!] Warning: Insufficient data read for the PyInstaller version");
    return S_FALSE;
  }

  uint32_t pyinstVer = (std::string(versionBuffer, 64).find("python") != std::string::npos) ? 21 : 20;

  // Read main buffer
  RINOK(stream->Seek(cookiePos, STREAM_SEEK_SET, nullptr));
  const size_t bufferSize = (pyinstVer == 20) ? 32 : 88;
  std::vector<char> buffer(bufferSize);
  RINOK(stream->Read(buffer.data(), bufferSize, &bytesRead));

  if (bytesRead != bufferSize) {
    logDebug((pyinstVer == 20) ? L"[!] Warning: Failed to read the PyInstaller 2.0 buffer"
      : L"[!] Warning: Failed to read the PyInstaller 2.1 buffer");
    return S_FALSE;
  }

  // Extract fields
  memcpy(&lengthofPackage, buffer.data() + 8, 4);
  memcpy(&toc, buffer.data() + 12, 4);
  memcpy(&tocLen, buffer.data() + 16, 4);
  memcpy(&pyver, buffer.data() + 20, 4);
  lengthofPackage = ByteSwap(lengthofPackage);
  toc = ByteSwap(toc);
  tocLen = ByteSwap(tocLen);
  pyver = ByteSwap(pyver);

  if (tocLen > fileSize || toc < 0 || lengthofPackage < 0) {
    logDebug(L"[!] Warning: Invalid TOC or length values detected.");
    return S_FALSE;
  }

  // Calculate overlay and TOC positions
  uint64_t tailBytes = fileSize - cookiePos - bufferSize;
  uint64_t overlaySize = static_cast<uint64_t>(lengthofPackage) + tailBytes;
  overlayPos = fileSize - overlaySize;
  tableOfContentsPos = overlayPos + toc;
  tableOfContentsSize = tocLen;

  RINOK(callback->SetTotal(nullptr, &tableOfContentsSize));

  // Parse archive and read data
  HRESULT parseResult = ParseArchive(stream, fileSize);
  RINOK(parseResult);

  HRESULT readDataResult = ReadData(stream);
  RINOK(readDataResult);

  archiveSize = tableOfContentsSize + lengthofPackage;

  logDebug(L"[+] Successfully opened PyInstaller archive, TOC size: " + std::to_wstring(tableOfContentsSize));

  return S_OK;
}


HRESULT PyInstallerHandler::ParseArchive(IInStream* stream, UInt64 fileSize) {
  HRESULT result = stream->Seek(tableOfContentsPos, STREAM_SEEK_SET, nullptr);
  RINOK(result);

  uint32_t parsedLen = 0;
  while (parsedLen < tableOfContentsSize) {
    uint32_t entrySize;
    UInt32 bytesRead = 0;
    result = SafeRead(stream, &entrySize, sizeof(entrySize), &bytesRead);
    if (result != S_OK || bytesRead != sizeof(entrySize)) {
      logDebug(L"[!] Error: Failed to read entry size at offset " + std::to_wstring(tableOfContentsPos + parsedLen));
      return S_FALSE;
    }
    entrySize = ByteSwap(entrySize);

    if (entrySize > (tableOfContentsSize - parsedLen)) {
      logDebug(L"[!] Error: Entry size exceeds remaining TOC size");
      return S_FALSE;
    }

    uint32_t nameLen = sizeof(uint32_t) + sizeof(uint32_t) * 3 + sizeof(uint8_t) + sizeof(char);
    std::vector<char> nameBuffer(entrySize - nameLen);
    uint32_t entryPos, compressedSize, uncompressedSize;
    uint8_t compressionFlag;
    char compressionType;

    auto safeReadField = [&](auto& field, const char* fieldName) -> bool {
      result = SafeRead(stream, &field, sizeof(field), &bytesRead);
      if (result != S_OK || bytesRead != sizeof(field)) {
        // Convert fieldName (const char*) to wstring
        std::wstring wFieldName(fieldName, fieldName + strlen(fieldName));
        logDebug(L"[!] Error: Failed to read " + wFieldName);
        return false;
      }
      field = ByteSwap(field);
      return true;
      };

    if (!safeReadField(entryPos, "entry position") ||
      !safeReadField(compressedSize, "compressed size") ||
      !safeReadField(uncompressedSize, "uncompressed size")) {
      return S_FALSE;
    }

    // Compression flag
    result = SafeRead(stream, &compressionFlag, sizeof(compressionFlag), &bytesRead);
    if (result != S_OK || bytesRead != sizeof(compressionFlag)) {
      logDebug(L"[!] Error: Failed to read compression flag");
      return S_FALSE;
    }

    // Compression type
    result = SafeRead(stream, &compressionType, sizeof(compressionType), &bytesRead);
    if (result != S_OK || bytesRead != sizeof(compressionType)) {
      logDebug(L"[!] Error: Failed to read compression type");
      return S_FALSE;
    }

    // Name buffer
    result = SafeRead(stream, nameBuffer.data(), nameBuffer.size(), &bytesRead);
    if (result != S_OK || bytesRead != nameBuffer.size()) {
      logDebug(L"[!] Error: Failed to read name buffer");
      return S_FALSE;
    }

    std::string utf8Name(nameBuffer.begin(), nameBuffer.end());
    std::wstring name;
    try {
      name = std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().from_bytes(utf8Name);
      name.erase(std::remove(name.begin(), name.end(), L'\0'), name.end());


    }
    catch (const std::exception&) {
      std::wstring newName = L"random_" + std::to_wstring(rand());
      logDebug(L"[!] Warning: Invalid file name bytes, using random name: " + newName);
      name = newName;
    }

    // Clean file name
    if (!name.empty() && name.front() == L'/') name.erase(0, 1);
    if (name.empty()) name = L"random_" + std::to_wstring(rand());
    if (compressionType == 's' || compressionType == 'M' || compressionType == 'm') name += L".pyc";

    UInt64 actualOffset = overlayPos + entryPos;

    // Debugging: log entry metadata
    std::wstringstream entryMsg;
    entryMsg << L"[Debug] Parsed entry metadata:"
      << L"\nEntry Position (relative): " << entryPos
      << L"\nActual Offset (in archive): " << actualOffset
      << L"\nCompressed Size: " << compressedSize
      << L"\nUncompressed Size: " << uncompressedSize
      << L"\nCompression Flag: " << (int)compressionFlag
      << L"\nCompression Type: " << compressionType
      << L"\nFile Name: " << name;
    logDebug(entryMsg);

    // Store the entry
    ArchiveEntry item(entryPos, compressedSize, uncompressedSize, compressionFlag,
      std::string(1, compressionType), std::string(name.begin(), name.end()));
    items.emplace_back(item);
    parsedLen += entrySize;
  }

  if (parsedLen != tableOfContentsSize) {
    logDebug(L"[!] Warning: Parsed length does not match TOC size");
    return S_FALSE;
  }

  logDebug(L"[+] Found " + std::to_wstring(items.size()) + L" files in archive");

  return S_OK;
}

HRESULT PyInstallerHandler::ReadData(IInStream* stream) {
  if (items.empty()) {
    HandleError(L"[!] Error: No metadata available. ParseArchive must be called first.");
    return S_FALSE;
  }

  logDebug("Starting ReadData for " + std::to_string(items.size()) + " items");

  for (auto& item : items) {
    if (item.compressedSize == 0) {
      logDebug("Skipping item with zero compressed size");
      continue;  // Skip if there's no compressed data
    }

    // Handle PYZ files - they're special uncompressed archive files
    if (item.compressionType == "z") {
      logDebug("Processing PYZ archive file (uncompressed): " + item.name);

      // PYZ files are stored uncompressed, just read the raw data
      uint64_t actualOffset = overlayPos + item.entryPos;
      HRESULT result = stream->Seek(actualOffset, STREAM_SEEK_SET, nullptr);
      if (result != S_OK) {
        logDebug("Failed to seek to PYZ offset: " + std::to_string(actualOffset));
        HandleError(L"[!] Error: Failed to seek to actual offset");
        return S_FALSE;
      }

      item.data.resize(item.compressedSize);
      UInt32 bytesRead = 0;
      result = SafeRead(stream, item.data.data(), item.compressedSize, &bytesRead);
      if (result != S_OK || bytesRead != item.compressedSize) {
        logDebug("Failed to read PYZ data - Expected: " + std::to_string(item.compressedSize) +
          ", Got: " + std::to_string(bytesRead));
        HandleError(L"[!] Error: Failed to read PYZ file data");
        return S_FALSE;
      }

      logDebug("Successfully read PYZ file: " + std::to_string(bytesRead) + " bytes");

      // For PYZ files, the data IS the decompressed data (it's stored uncompressed)
      item.decompressedData = item.data;

      logDebug("PYZ file processed successfully");

      continue;
    }

    // Skip uncompressed files (type 'o' for directory markers)
    if (item.compressionFlag == 0 || item.compressionType == "o") {
      logDebug("Skipping uncompressed/directory entry: " + item.name);
      continue;
    }

    logDebug("Processing item - Compressed size: " + std::to_string(item.compressedSize) +
      ", Uncompressed size: " + std::to_string(item.uncompressedSize));

    uint64_t actualOffset = overlayPos + item.entryPos;
    HRESULT result = stream->Seek(actualOffset, STREAM_SEEK_SET, nullptr);
    if (result != S_OK) {
      logDebug("Failed to seek to offset: " + std::to_string(actualOffset));
      HandleError(L"[!] Error: Failed to seek to actual offset");
      return S_FALSE;
    }

    item.data.resize(item.compressedSize);
    UInt32 bytesRead = 0;
    result = SafeRead(stream, item.data.data(), item.compressedSize, &bytesRead);
    if (result != S_OK || bytesRead != item.compressedSize) {
      logDebug("Failed to read data - Expected: " + std::to_string(item.compressedSize) +
        ", Got: " + std::to_string(bytesRead));
      HandleError(L"[!] Error: Failed to read file data");
      return S_FALSE;
    }

    logDebug("Successfully read " + std::to_string(bytesRead) + " bytes");

    bool zlibFound = false;
    size_t zlibHeaderIndex = 0;
    for (; zlibHeaderIndex < item.data.size() - 1; ++zlibHeaderIndex) {
      if (item.data[zlibHeaderIndex] == 0x78) {  // 0x78 is typical for zlib headers
        zlibFound = true;
        break;
      }
    }

    if (zlibFound) {
      logDebug("Found zlib header at index: " + std::to_string(zlibHeaderIndex));

      std::vector<uint8_t> actualCompressedData(item.data.begin() + zlibHeaderIndex, item.data.end());

      logDebug("Actual compressed data size: " + std::to_string(actualCompressedData.size()));
      // Log first few bytes for debugging
      std::stringstream ss;
      ss << "First bytes: ";
      for (size_t i = 0; i < std::min(size_t(16), actualCompressedData.size()); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)actualCompressedData[i] << " ";
      }
      logDebug(ss.str());

      // Create output ByteVector for decompression
      ByteVector* output = bytevector_create(item.uncompressedSize);
      if (!output) {
        logDebug("Failed to allocate ByteVector");
        HandleError(L"[!] Error: Failed to allocate memory for decompression");
        return S_FALSE;
      }

      logDebug("Starting decompression with custom zlib decoder");

      int decompressResult = zlib_decompress(
        actualCompressedData.data(),
        actualCompressedData.size(),
        output
      );

      if (decompressResult < 0) {
        logDebug("Decompression failed with error code: " + std::to_string(decompressResult));
        bytevector_free(output);
        HandleError(L"[!] Error: Failed to decompress data");
        return S_FALSE;
      }

      logDebug("Decompression successful - Output size: " + std::to_string(output->length));

      // Copy decompressed data to item
      item.decompressedData.resize(output->length);
      memcpy(item.decompressedData.data(), output->data, output->length);

      // Clean up
      bytevector_free(output);

      // Verify size matches expected
      if (item.decompressedData.size() != item.uncompressedSize) {
        logDebug("Size mismatch - Expected: " + std::to_string(item.uncompressedSize) +
          ", Got: " + std::to_string(item.decompressedData.size()));
        HandleError(L"[!] Warning: Decompressed size does not match expected uncompressed size");
        return S_FALSE;
      }

      logDebug("Item processed successfully");
    }
    else {
      logDebug("No zlib header (0x78) found in data");
      // Log first few bytes to help debug
      std::stringstream ss;
      ss << "First bytes of data: ";
      for (size_t i = 0; i < std::min(size_t(16), item.data.size()); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)item.data[i] << " ";
      }
      logDebug(ss.str());
      HandleError(L"[!] Error: No zlib header found in data");
      return S_FALSE;
    }
  }

  logDebug("ReadData completed successfully for all items");

  return S_OK;
}