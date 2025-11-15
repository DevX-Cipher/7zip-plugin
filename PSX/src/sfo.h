#pragma once
#include <string>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cstring>

// SFO file header structure (20 bytes)
struct SFOHeader {
  uint32_t magic;              // 0x46535000 (little-endian)
  uint32_t version;            // Usually 0x00000101
  uint32_t keyTableStart;
  uint32_t dataTableStart;
  uint32_t numEntries;
};

// Index table entry structure (16 bytes per entry)
struct SFOIndexEntry {
  uint16_t keyOffset;          // Offset into key table
  uint16_t dataFormat;         // 0x0204 (UTF-8), 0x0404 (UINT32)
  uint32_t dataLen;            // Actual length of data
  uint32_t dataMaxLen;         // Reserved space for data
  uint32_t dataOffset;         // Offset into data table
};

class SFOReader {
private:
  // Read a null-terminated string from a specific position
  static std::string readStringAt(std::ifstream& file, size_t position) {
    file.seekg(position);
    std::string result;
    char ch;
    while (file.get(ch) && ch != '\0') {
      result += ch;
    }
    return result;
  }

  // Read value based on format type
  static std::string readValue(std::ifstream& file, const SFOIndexEntry& entry, uint32_t dataTableStart) {
    file.seekg(dataTableStart + entry.dataOffset);

    // Format types: 0x0204 = UTF-8, 0x0400 = UTF-8 special, 0x0404 = UINT32
    if (entry.dataFormat == 0x0204 || entry.dataFormat == 0x0400) {
      std::vector<char> buffer(entry.dataMaxLen);
      file.read(buffer.data(), entry.dataMaxLen);
      return std::string(buffer.data());
    }
    else if (entry.dataFormat == 0x0404) {
      uint32_t value;
      file.read(reinterpret_cast<char*>(&value), sizeof(value));
      return std::to_string(value);
    }

    return "";
  }

public:
  // Read a specific parameter from SFO file
  static std::string readParameter(const std::string& filepath, const std::string& paramName) {
    std::ifstream file(filepath, std::ios::binary);

    if (!file.is_open()) {
      return "";
    }

    // Read header
    SFOHeader header;
    file.read(reinterpret_cast<char*>(&header), sizeof(SFOHeader));

    // Validate magic bytes (should be 0x46535000 in little-endian)
    if (header.magic != 0x46535000) {
      return "";
    }

    // Read all index entries
    std::vector<SFOIndexEntry> entries(header.numEntries);
    for (uint32_t i = 0; i < header.numEntries; i++) {
      file.read(reinterpret_cast<char*>(&entries[i]), sizeof(SFOIndexEntry));
    }

    // Search for the requested parameter
    for (const auto& entry : entries) {
      std::string keyName = readStringAt(file, header.keyTableStart + entry.keyOffset);

      if (keyName == paramName) {
        std::string value = readValue(file, entry, header.dataTableStart);
        file.close();
        return value;
      }
    }

    file.close();
    return "";
  }


  // Read CONTENT_ID from memory buffer
  static std::string getContentIDFromMemory(const uint8_t* data, size_t dataSize)
  {
    if (!data || dataSize < 20) {
      return "";
    }

    try {
      // Check magic (0x46535000 = "\0PSF" in little-endian)
      uint32_t magic = *(uint32_t*)(data);
      if (magic != 0x46535000) {
        return "";
      }

      uint32_t keyTableStart = *(uint32_t*)(data + 0x08);
      uint32_t dataTableStart = *(uint32_t*)(data + 0x0C);
      uint32_t numEntries = *(uint32_t*)(data + 0x10);

      if (keyTableStart >= dataSize || dataTableStart >= dataSize) {
        return "";
      }

      // Parse entries
      for (uint32_t i = 0; i < numEntries; i++) {
        uint32_t entryOffset = 0x14 + (i * 0x10);
        if (entryOffset + 0x10 > dataSize) break;

        uint16_t keyOffset = *(uint16_t*)(data + entryOffset + 0x00);
        uint16_t dataFormat = *(uint16_t*)(data + entryOffset + 0x02);
        uint32_t dataLen = *(uint32_t*)(data + entryOffset + 0x04);
        uint32_t dataMaxLen = *(uint32_t*)(data + entryOffset + 0x08);
        uint32_t dataOffset = *(uint32_t*)(data + entryOffset + 0x0C);

        uint32_t keyPos = keyTableStart + keyOffset;
        uint32_t dataPos = dataTableStart + dataOffset;

        if (keyPos >= dataSize || dataPos >= dataSize) continue;

        // Read key name
        std::string keyName;
        for (size_t j = keyPos; j < dataSize && data[j] != 0; j++) {
          keyName += (char)data[j];
        }

        logDebug(("SFO Key: " + keyName + "\n").c_str());

        // Check if this is CONTENT_ID
        if (keyName == "CONTENT_ID") {
          char debugMsg[256];
          sprintf_s(debugMsg, "Found CONTENT_ID: dataFormat=0x%04X, dataLen=%u, dataMaxLen=%u, dataPos=%u\n",
            dataFormat, dataLen, dataMaxLen, dataPos);
          logDebug(debugMsg);

          if (dataFormat == 0x0204 || dataFormat == 0x0400 || dataFormat == 0x0402) {
            uint32_t maxRead = (dataPos + dataMaxLen <= dataSize) ? dataMaxLen : (dataSize - dataPos);

            std::string contentID;
            for (size_t j = 0; j < maxRead && data[dataPos + j] != 0; j++) {
              contentID += (char)data[dataPos + j];
            }
            logDebug(("Content ID read: " + contentID + "\n").c_str());
            return contentID;
          }

          else {
            char debugMsg[128];
            sprintf_s(debugMsg, "Unexpected data format for CONTENT_ID: 0x%04X\n", dataFormat);
            logDebug(debugMsg);
          }

        }
      }

      return "";
    }
    catch (...) {
      return "";
    }
  }

  // Convenience method to read CONTENT_ID
  static std::string getContentID(const std::string& filepath) {
    return readParameter(filepath, "CONTENT_ID");
  }
};