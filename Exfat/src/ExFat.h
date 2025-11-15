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

#ifdef _DEBUG
static void logDebug(const std::string& message);
static void logDebug(const std::wstring& message);
#else
#define logDebug(...) ((void)0)
#endif

static std::string wideToUtf8(const std::wstring& wstr);

// ExFAT structures
#pragma pack(push, 1)

struct ExFATBootSector {
  uint8_t jumpBoot[3];
  char fileSystemName[8];
  uint8_t mustBeZero[53];
  uint64_t partitionOffset;
  uint64_t volumeLength;
  uint32_t fatOffset;
  uint32_t fatLength;
  uint32_t clusterHeapOffset;
  uint32_t clusterCount;
  uint32_t rootDirCluster;
  uint32_t volumeSerialNumber;
  uint16_t fileSystemRevision;
  uint16_t volumeFlags;
  uint8_t bytesPerSectorShift;
  uint8_t sectorsPerClusterShift;
  uint8_t numberOfFats;
  uint8_t driveSelect;
  uint8_t percentInUse;
  uint8_t reserved[7];
  uint8_t bootCode[390];
  uint16_t bootSignature; 
};

struct ExFATDirEntry {
  uint8_t entryType;
  union {
    struct {
      uint8_t secondaryCount;
      uint16_t setChecksum;
      uint16_t fileAttributes;
      uint16_t reserved1;
      uint32_t createTimestamp;
      uint32_t modifyTimestamp;
      uint32_t accessTimestamp;
      uint8_t create10msIncrement;
      uint8_t modify10msIncrement;
      uint8_t createUtcOffset;
      uint8_t modifyUtcOffset;
      uint8_t accessUtcOffset;
      uint8_t reserved2[7];
    } file;
    struct {
      uint8_t generalSecondaryFlags;
      uint8_t reserved1;
      uint8_t nameLength;
      uint16_t nameHash;
      uint16_t reserved2;
      uint64_t validDataLength;
      uint32_t reserved3;
      uint32_t firstCluster;
      uint64_t dataLength;
    } stream;
    struct {  
      uint8_t generalSecondaryFlags;
      uint16_t fileName[15];
    } name;
    uint8_t raw[31];
  };
};

#pragma pack(pop)

class ExFATHandler {
private:
  ExFATBootSector bootSector;
  std::vector<uint32_t> fat;
  uint32_t bytesPerSector;
  uint32_t bytesPerCluster;
  uint64_t clusterHeapStart;
  std::vector<char> fatData;

public:
  struct FileInfo {
    std::string path;
    std::string name;
    uint64_t size;
    uint64_t validDataLength;
    uint32_t firstCluster;
    uint32_t attributes;
    uint32_t createTime;
    uint32_t modifyTime;
    uint32_t accessTime;
    bool isDirectory;
    std::streampos position;

    FileInfo()
      : size(0), validDataLength(0), firstCluster(0), attributes(0),
      createTime(0), modifyTime(0), accessTime(0), isDirectory(false), position(0) {
    }
  };

  std::vector<FileInfo> items;

  HRESULT Open(IInStream* stream, const UInt64* fileSize, IArchiveOpenCallback* callback);
  HRESULT ReadBootSector(IInStream* stream);
  HRESULT ReadFAT(IInStream* stream);
  HRESULT ParseDirectory(IInStream* stream, uint32_t clusterNum, const std::string& parentPath);
  uint32_t GetNextCluster(uint32_t currentCluster);
  HRESULT ReadCluster(IInStream* stream, uint32_t clusterNum, std::vector<uint8_t>& buffer);
  HRESULT ExtractFile(IInStream* stream, FileInfo& fileInfo, std::vector<uint8_t>& output);

private:
  bool ValidateBootSector();
  std::wstring DecodeFileName(const std::vector<uint16_t>& utf16Name);
};

// Utility functions
static std::wstring getDesktopPath() {
  wchar_t path[MAX_PATH];
  if (GetEnvironmentVariableW(L"USERPROFILE", path, MAX_PATH)) {
    std::wstring desktop = path;
    desktop += L"\\Desktop";
    return desktop;
  }
  return L".";
}

#ifdef _DEBUG
static void logDebug(const std::string& message) {
  static std::string logFilePath;
  if (logFilePath.empty()) {
    std::wstring desktopPath = getDesktopPath();
    std::wstring logPathW = desktopPath + L"\\exfat_debug.log";

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
#endif

static std::string wideToUtf8(const std::wstring& wstr) {
  if (wstr.empty()) return {};
  int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
  if (size_needed <= 1) return {};
  std::string strTo(size_needed - 1, 0);
  WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &strTo[0], size_needed - 1, nullptr, nullptr);
  return strTo;
}

bool ExFATHandler::ValidateBootSector() {
  // Check signature
  if (bootSector.bootSignature != 0xAA55) {
    logDebug("Invalid boot signature");
    return false;
  }

  // Check filesystem name
  if (memcmp(bootSector.fileSystemName, "EXFAT   ", 8) != 0) {
    logDebug("Invalid filesystem name");
    return false;
  }

  // Check that mustBeZero is actually zero
  for (int i = 0; i < 53; i++) {
    if (bootSector.mustBeZero[i] != 0) {
      logDebug("mustBeZero field contains non-zero values");
      return false;
    }
  }

  return true;
}

HRESULT ExFATHandler::ReadBootSector(IInStream* stream) {
  RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));

  UInt32 bytesRead = 0;
  RINOK(stream->Read(reinterpret_cast<BYTE*>(&bootSector), sizeof(ExFATBootSector), &bytesRead));

  if (bytesRead != sizeof(ExFATBootSector)) {
    logDebug("Failed to read boot sector");
    return E_FAIL;
  }

  if (!ValidateBootSector()) {
    logDebug("Boot sector validation failed");
    return E_FAIL;
  }

  // Calculate sizes
  bytesPerSector = 1 << bootSector.bytesPerSectorShift;
  bytesPerCluster = bytesPerSector << bootSector.sectorsPerClusterShift;
  clusterHeapStart = bootSector.clusterHeapOffset * bytesPerSector;

  logDebug("ExFAT Boot Sector Info:");
  logDebug("  Bytes per sector: " + std::to_string(bytesPerSector));
  logDebug("  Bytes per cluster: " + std::to_string(bytesPerCluster));
  logDebug("  FAT offset: " + std::to_string(bootSector.fatOffset));
  logDebug("  FAT length: " + std::to_string(bootSector.fatLength));
  logDebug("  Cluster heap offset: " + std::to_string(bootSector.clusterHeapOffset));
  logDebug("  Root directory cluster: " + std::to_string(bootSector.rootDirCluster));

  return S_OK;
}

HRESULT ExFATHandler::ReadFAT(IInStream* stream) {
  uint64_t fatOffset = bootSector.fatOffset * bytesPerSector;
  uint32_t fatSize = bootSector.fatLength * bytesPerSector;

  logDebug("Reading FAT at offset " + std::to_string(fatOffset) + ", size " + std::to_string(fatSize));

  RINOK(stream->Seek(fatOffset, STREAM_SEEK_SET, nullptr));

  fatData.resize(fatSize);
  UInt32 bytesRead = 0;
  RINOK(stream->Read(reinterpret_cast<BYTE*>(fatData.data()), fatSize, &bytesRead));

  if (bytesRead != fatSize) {
    logDebug("Failed to read complete FAT");
    return E_FAIL;
  }

  logDebug("FAT read successfully");
  return S_OK;
}

uint32_t ExFATHandler::GetNextCluster(uint32_t currentCluster) {
  if (currentCluster < 2 || currentCluster >= bootSector.clusterCount + 2) {
    return 0xFFFFFFFF;  // End of chain
  }

  uint32_t offset = currentCluster * 4;
  if (offset + 4 > fatData.size()) {
    return 0xFFFFFFFF;
  }

  uint32_t nextCluster = *reinterpret_cast<uint32_t*>(&fatData[offset]);

  // Check for end of chain or bad cluster
  if (nextCluster >= 0xFFFFFFF8) {
    return 0xFFFFFFFF;
  }

  return nextCluster;
}

HRESULT ExFATHandler::ReadCluster(IInStream* stream, uint32_t clusterNum, std::vector<uint8_t>& buffer) {
  if (clusterNum < 2 || clusterNum >= bootSector.clusterCount + 2) {
    logDebug("Invalid cluster number: " + std::to_string(clusterNum));
    return E_FAIL;
  }

  uint64_t clusterOffset = clusterHeapStart + ((clusterNum - 2) * bytesPerCluster);
  RINOK(stream->Seek(clusterOffset, STREAM_SEEK_SET, nullptr));

  buffer.resize(bytesPerCluster);
  UInt32 bytesRead = 0;
  RINOK(stream->Read(buffer.data(), bytesPerCluster, &bytesRead));

  if (bytesRead != bytesPerCluster) {
    logDebug("Failed to read complete cluster");
    return E_FAIL;
  }

  return S_OK;
}

std::wstring ExFATHandler::DecodeFileName(const std::vector<uint16_t>& utf16Name) {
  if (utf16Name.empty()) return L"";

  std::wstring result;
  for (uint16_t ch : utf16Name) {
    if (ch == 0) break;
    result += static_cast<wchar_t>(ch);
  }
  return result;
}

HRESULT ExFATHandler::ParseDirectory(IInStream* stream, uint32_t clusterNum, const std::string& parentPath) {
  logDebug("Parsing directory at cluster " + std::to_string(clusterNum) + ", path: " + parentPath);

  uint32_t currentCluster = clusterNum;
  FileInfo* currentFile = nullptr;
  std::vector<uint16_t> fileNameChars;
  int secondaryRemaining = 0;

  while (currentCluster != 0xFFFFFFFF && currentCluster >= 2) {
    std::vector<uint8_t> clusterData;
    RINOK(ReadCluster(stream, currentCluster, clusterData));

    size_t entryCount = bytesPerCluster / sizeof(ExFATDirEntry);
    ExFATDirEntry* entries = reinterpret_cast<ExFATDirEntry*>(clusterData.data());

    for (size_t i = 0; i < entryCount; i++) {
      ExFATDirEntry& entry = entries[i];

      // End of directory
      if (entry.entryType == 0x00) {
        return S_OK;
      }

      // Skip unused entries
      if (entry.entryType == 0x83 || (entry.entryType & 0x80) == 0) {
        continue;
      }

      // File directory entry
      if (entry.entryType == 0x85) {
        if (currentFile) {
          items.push_back(*currentFile);
          delete currentFile;
        }

        currentFile = new FileInfo();
        currentFile->attributes = entry.file.fileAttributes;
        currentFile->createTime = entry.file.createTimestamp;
        currentFile->modifyTime = entry.file.modifyTimestamp;
        currentFile->accessTime = entry.file.accessTimestamp;
        currentFile->isDirectory = (entry.file.fileAttributes & 0x10) != 0;
        secondaryRemaining = entry.file.secondaryCount;
        fileNameChars.clear();
      }
      // Stream extension
      else if (entry.entryType == 0xC0 && currentFile && secondaryRemaining > 0) {
        currentFile->firstCluster = entry.stream.firstCluster;
        currentFile->size = entry.stream.dataLength;
        currentFile->validDataLength = entry.stream.validDataLength;
        secondaryRemaining--;
      }
      // File name extension
      else if (entry.entryType == 0xC1 && currentFile && secondaryRemaining > 0) {
        for (int j = 0; j < 15; j++) {
          fileNameChars.push_back(entry.name.fileName[j]);
        }
        secondaryRemaining--;

        // If this is the last secondary entry, finalize the file
        if (secondaryRemaining == 0) {
          std::wstring wFileName = DecodeFileName(fileNameChars);
          currentFile->name = wideToUtf8(wFileName);
          currentFile->path = parentPath.empty() ? currentFile->name : parentPath + "/" + currentFile->name;

          logDebug("Found: " + currentFile->path +
            " (size: " + std::to_string(currentFile->size) +
            ", cluster: " + std::to_string(currentFile->firstCluster) + ")");

          items.push_back(*currentFile);

          // Recursively parse subdirectories
          if (currentFile->isDirectory && currentFile->firstCluster >= 2) {
            ParseDirectory(stream, currentFile->firstCluster, currentFile->path);
          }

          delete currentFile;
          currentFile = nullptr;
          fileNameChars.clear();
        }
      }
    }

    currentCluster = GetNextCluster(currentCluster);
  }

  if (currentFile) {
    delete currentFile;
  }

  return S_OK;
}

HRESULT ExFATHandler::ExtractFile(IInStream* stream, FileInfo& fileInfo, std::vector<uint8_t>& output) {
  if (fileInfo.isDirectory) {
    return S_OK;
  }

  output.clear();
  output.reserve(fileInfo.size);

  uint32_t currentCluster = fileInfo.firstCluster;
  uint64_t remainingBytes = fileInfo.size;

  while (currentCluster != 0xFFFFFFFF && currentCluster >= 2 && remainingBytes > 0) {
    std::vector<uint8_t> clusterData;
    RINOK(ReadCluster(stream, currentCluster, clusterData));

    uint32_t bytesToCopy = (remainingBytes < bytesPerCluster) ? remainingBytes : bytesPerCluster;
    output.insert(output.end(), clusterData.begin(), clusterData.begin() + bytesToCopy);

    remainingBytes -= bytesToCopy;
    currentCluster = GetNextCluster(currentCluster);
  }

  logDebug("Extracted " + std::to_string(output.size()) + " bytes from " + fileInfo.path);
  return S_OK;
}

HRESULT ExFATHandler::Open(IInStream* stream, const UInt64* fileSize, IArchiveOpenCallback* callback) {
  if (!stream) {
    logDebug("Error: Invalid stream in Open()");
    return S_FALSE;
  }

  logDebug("Opening ExFAT image...");

  // Read and validate boot sector
  RINOK(ReadBootSector(stream));

  // Read File Allocation Table
  RINOK(ReadFAT(stream));

  // Set total for progress
  if (callback) {
    UInt64 totalSize = *fileSize;
    callback->SetTotal(nullptr, &totalSize);
  }

  // Parse root directory
  RINOK(ParseDirectory(stream, bootSector.rootDirCluster, ""));

  logDebug("ExFAT archive parsed successfully. Total items: " + std::to_string(items.size()));

  return S_OK;
}