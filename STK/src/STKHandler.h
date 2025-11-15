#define NOMINMAX
#include <windows.h>
#undef min
#undef max
#include <algorithm>
#include <vector>
#include <string>
#include <cstdint>
#include <iostream>

class STKArchiveHandler {
public:
  struct FileInfo {
    std::streampos position;
    uint32_t offset;
    uint32_t size;
    uint32_t uncompressed_size;
    uint8_t compression;
    std::string path;
    std::vector<uint8_t> decompressedData;

    // STK 2.1 fields
    std::string modified;
    std::string created;
    std::string creator;
    std::vector<uint8_t> unk;

    FileInfo()
      : position(0), offset(0), size(0), uncompressed_size(0),
      compression(0), path("") {
    }

    void SetFileInfo(uint32_t off, uint32_t sz, uint8_t comp) {
      offset = off;
      size = sz;
      compression = comp;
    }

    void SetFileInfoSTK21(uint32_t off, uint32_t sz, uint8_t comp,
      uint32_t uncompressed, const std::string& mod,
      const std::string& cre, const std::string& crea) {
      offset = off;
      size = sz;
      compression = comp;
      uncompressed_size = uncompressed;
      modified = mod;
      created = cre;
      creator = crea;
    }
  };

  std::vector<FileInfo> items;
  float version;

  HRESULT Open(IInStream* stream, const UInt64* fileSize, IArchiveOpenCallback* callback);
  HRESULT ParseSTK10(IInStream* stream);
  HRESULT ParseSTK20(IInStream* stream);
  HRESULT ParseSTK21(IInStream* stream);
  HRESULT ExtractFile(IInStream* stream, FileInfo& fileInfo);
  HRESULT UnpackChunk(IInStream* stream, uint32_t size, std::vector<uint8_t>& output);
  HRESULT UnpackChunks(IInStream* stream, FileInfo& fileInfo);
  HRESULT ExtractAll(IInStream* stream);
};

// Utility functions
static HRESULT readUint32(IInStream* stream, uint32_t* value) {
  UInt32 bytesRead = 0;
  return stream->Read(reinterpret_cast<BYTE*>(value), sizeof(uint32_t), &bytesRead);
}

static HRESULT readUint16(IInStream* stream, uint16_t* value) {
  UInt32 bytesRead = 0;
  return stream->Read(reinterpret_cast<BYTE*>(value), sizeof(uint16_t), &bytesRead);
}

static HRESULT readUint8(IInStream* stream, uint8_t* value) {
  UInt32 bytesRead = 0;
  return stream->Read(reinterpret_cast<BYTE*>(value), sizeof(uint8_t), &bytesRead);
}

static std::string readCString(IInStream* stream, size_t maxLen) {
  std::string result;
  char ch;
  UInt32 bytesRead;

  for (size_t i = 0; i < maxLen; i++) {
    if (FAILED(stream->Read(reinterpret_cast<BYTE*>(&ch), 1, &bytesRead)) || bytesRead == 0) {
      break;
    }
    if (ch == '\0') {
      break;
    }
    result += ch;
  }
  return result;
}

static std::string replaceCyrillic(const std::string& input) {
  std::string result = input;
  const std::pair<char, char> replacements[] = {
      {'\x85', 'E'}, {'\x8A', 'K'}, {'\x8E', 'O'},
      {'\x91', 'C'}, {'\x92', 'T'}
  };

  for (const auto& rep : replacements) {
    size_t pos = 0;
    while ((pos = result.find(rep.first, pos)) != std::string::npos) {
      result[pos] = rep.second;
      pos++;
    }
  }
  return result;
}

HRESULT STKArchiveHandler::UnpackChunk(IInStream* stream, uint32_t size, std::vector<uint8_t>& output) {
  uint16_t bufferIndex = 4078;
  std::vector<uint8_t> buffer(4096);

  // Initialize buffer with spaces
  std::fill(buffer.begin(), buffer.begin() + 4078, 0x20);
  std::fill(buffer.begin() + 4078, buffer.end(), 0x00);

  uint16_t command = 0;

  while (size > 0) {
    command >>= 1;
    if ((command & 0x0100) == 0) {
      uint8_t cmdByte;
      RINOK(readUint8(stream, &cmdByte));
      command = cmdByte | 0xFF00;
    }

    if (command & 1) {
      // Direct byte copy
      uint8_t temp;
      RINOK(readUint8(stream, &temp));
      output.push_back(temp);
      buffer[bufferIndex] = temp;
      bufferIndex = (bufferIndex + 1) % 4096;
      size--;
    }
    else {
      // Copy from buffer
      uint8_t hi, low;
      RINOK(readUint8(stream, &hi));
      RINOK(readUint8(stream, &low));

      uint16_t offset = hi | ((low & 0xF0) << 4);
      uint16_t length = (low & 0x0F) + 3;

      for (uint16_t i = 0; i < length; i++) {
        uint8_t byte = buffer[(offset + i) % 4096];
        output.push_back(byte);
        size--;

        if (size == 0) {
          return S_OK;
        }

        buffer[bufferIndex] = byte;
        bufferIndex = (bufferIndex + 1) % 4096;
      }
    }
  }

  return S_OK;
}

HRESULT STKArchiveHandler::UnpackChunks(IInStream* stream, FileInfo& fileInfo) {
  uint16_t chunkSize = 0;
  uint32_t totalUncompressed = 0;
  std::vector<uint8_t> data;

  while (chunkSize != 0xFFFF) {
    UInt64 chunkStart;
    RINOK(stream->Seek(0, STREAM_SEEK_CUR, &chunkStart));

    RINOK(readUint16(stream, &chunkSize));

    if (chunkSize == 0xFFFF) {
      break;
    }

    uint16_t realSize;
    RINOK(readUint16(stream, &realSize));
    totalUncompressed += realSize;

    // Skip 2 bytes
    stream->Seek(2, STREAM_SEEK_CUR, nullptr);

    // Unpack this chunk
    std::vector<uint8_t> chunkData;
    RINOK(UnpackChunk(stream, realSize, chunkData));

    data.insert(data.end(), chunkData.begin(), chunkData.end());

    // Verify position
    UInt64 currentPos;
    stream->Seek(0, STREAM_SEEK_CUR, &currentPos);
    if (currentPos != chunkStart + chunkSize + 2) {
      return E_FAIL;
    }
  }

  if (data.size() != totalUncompressed) {
    return E_FAIL;
  }

  fileInfo.decompressedData = data;
  fileInfo.uncompressed_size = totalUncompressed;

  return S_OK;
}

HRESULT STKArchiveHandler::ParseSTK10(IInStream* stream) {
  // STK version 1.0 format
  uint16_t fileCount;
  RINOK(readUint16(stream, &fileCount));

  for (uint16_t i = 0; i < fileCount; i++) {
    FileInfo fileInfo;

    // Read filename (13 bytes)
    char rawFilename[13];
    UInt32 bytesRead;
    RINOK(stream->Read(reinterpret_cast<BYTE*>(rawFilename), 13, &bytesRead));

    // Extract null-terminated string
    std::string filename;
    for (int j = 0; j < 13 && rawFilename[j] != '\0'; j++) {
      filename += rawFilename[j];
    }

    // Read file info
    uint32_t size, offset;
    RINOK(readUint32(stream, &size));
    RINOK(readUint32(stream, &offset));

    // Read compression flag
    uint8_t compressionByte;
    RINOK(readUint8(stream, &compressionByte));
    uint8_t compression = (compressionByte != 0x00) ? 1 : 0;

    // Handle special .0OT files
    if (filename.length() >= 4) {
      std::string upper = filename;
      std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
      if (upper.substr(upper.length() - 4) == ".0OT") {
        compression = 2;
        filename = filename.substr(0, filename.length() - 4) + ".TOT";
      }
    }

    // Replace cyrillic characters
    filename = replaceCyrillic(filename);

    fileInfo.SetFileInfo(offset, size, compression);
    fileInfo.path = filename;

    items.push_back(fileInfo);
  }

  return S_OK;
}

HRESULT STKArchiveHandler::ParseSTK20(IInStream* stream) {
  // STK 2.0 format
  return ParseSTK21(stream); // Same structure
}

HRESULT STKArchiveHandler::ParseSTK21(IInStream* stream) {
  // Read header
  char dateStr[14];
  char creatorStr[8];
  UInt32 bytesRead;

  RINOK(stream->Read(reinterpret_cast<BYTE*>(dateStr), 14, &bytesRead));
  RINOK(stream->Read(reinterpret_cast<BYTE*>(creatorStr), 8, &bytesRead));

  uint32_t fileNamesOffset;
  RINOK(readUint32(stream, &fileNamesOffset));

  // Seek to file names section
  RINOK(stream->Seek(fileNamesOffset, STREAM_SEEK_SET, nullptr));

  uint32_t fileCount;
  RINOK(readUint32(stream, &fileCount));

  uint32_t miscOffset;
  RINOK(readUint32(stream, &miscOffset));

  for (uint32_t i = 0; i < fileCount; i++) {
    FileInfo fileInfo;

    // Seek to file info
    RINOK(stream->Seek(miscOffset + i * 61, STREAM_SEEK_SET, nullptr));

    uint32_t filenameOffset;
    RINOK(readUint32(stream, &filenameOffset));

    // Read timestamps
    char modifiedStr[14], createdStr[14];
    RINOK(stream->Read(reinterpret_cast<BYTE*>(modifiedStr), 14, &bytesRead));
    RINOK(stream->Read(reinterpret_cast<BYTE*>(createdStr), 14, &bytesRead));

    // Read creator
    char creator[8];
    RINOK(stream->Read(reinterpret_cast<BYTE*>(creator), 8, &bytesRead));

    uint32_t size, uncompressedSize;
    RINOK(readUint32(stream, &size));
    RINOK(readUint32(stream, &uncompressedSize));

    // Skip 5 unknown bytes
    stream->Seek(5, STREAM_SEEK_CUR, nullptr);

    uint32_t offset, compression;
    RINOK(readUint32(stream, &offset));
    RINOK(readUint32(stream, &compression));

    // Read filename
    RINOK(stream->Seek(filenameOffset, STREAM_SEEK_SET, nullptr));
    std::string filename = readCString(stream, 256);

    fileInfo.SetFileInfoSTK21(
      offset, size, static_cast<uint8_t>(compression), uncompressedSize,
      std::string(modifiedStr, 14), std::string(createdStr, 14),
      std::string(creator, 8)
    );
    fileInfo.path = filename;

    items.push_back(fileInfo);
  }

  return S_OK;
}

HRESULT STKArchiveHandler::ExtractFile(IInStream* stream, FileInfo& fileInfo) {
  // Seek to file data
  RINOK(stream->Seek(fileInfo.offset, STREAM_SEEK_SET, nullptr));

  if (fileInfo.compression == 0) {
    // No compression - direct read
    fileInfo.decompressedData.resize(fileInfo.size);
    UInt32 bytesRead;
    RINOK(stream->Read(fileInfo.decompressedData.data(), fileInfo.size, &bytesRead));
    fileInfo.uncompressed_size = fileInfo.size;

  }
  else if (fileInfo.compression == 2) {
    // Multiple chunks compression
    RINOK(UnpackChunks(stream, fileInfo));

  }
  else if (fileInfo.compression == 1) {
    // Single chunk compression
    uint32_t uncompressedSize;
    RINOK(readUint32(stream, &uncompressedSize));

    RINOK(UnpackChunk(stream, uncompressedSize, fileInfo.decompressedData));
    fileInfo.uncompressed_size = uncompressedSize;
  }

  return S_OK;
}

HRESULT STKArchiveHandler::Open(IInStream* stream, const UInt64* fileSize, IArchiveOpenCallback* callback) {
  if (!stream) {
    return E_FAIL;
  }

  // Read header to determine version
  char header[6];
  UInt32 bytesRead;
  RINOK(stream->Read(reinterpret_cast<BYTE*>(header), 6, &bytesRead));

  if (bytesRead == 6 && memcmp(header, "STK2.0", 6) == 0) {
    version = 2.0f;
    return ParseSTK20(stream);
  }
  else if (bytesRead == 6 && memcmp(header, "STK2.1", 6) == 0) {
    version = 2.1f;
    return ParseSTK21(stream);
  }
  else {
    // Version 1.0 - no header
    version = 1.0f;
    RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));
    return ParseSTK10(stream);
  }

  return S_OK;
}

// Extract all files
HRESULT STKArchiveHandler::ExtractAll(IInStream* stream) {
  for (auto& item : items) {
    HRESULT hr = ExtractFile(stream, item);
    if (FAILED(hr)) {
      std::cerr << "Failed to extract: " << item.path << std::endl;
      return hr;
    }
  }
  return S_OK;
}