#pragma once
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <optional>

namespace UpxPE {
  inline uint16_t readU16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
  }
  inline uint32_t readU32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
      (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
  }
  inline uint64_t readU64(const uint8_t* p) {
    return static_cast<uint64_t>(readU32(p)) | (static_cast<uint64_t>(readU32(p + 4)) << 32);
  }
  inline void writeU16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
  }
  inline void writeU32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
  }
  inline void writeU64(uint8_t* p, uint64_t v) {
    writeU32(p, static_cast<uint32_t>(v & 0xFFFFFFFFu));
    writeU32(p + 4, static_cast<uint32_t>((v >> 32) & 0xFFFFFFFFu));
  }

  inline uint64_t alignUp(uint64_t value, uint64_t alignment) {
    if (alignment <= 1) return value;
    return (value + alignment - 1) & ~(alignment - 1);
  }


  struct PEView {
    const uint8_t* data = nullptr;
    size_t size = 0;

    bool is64 = false;
    uint32_t ntHeaderOffset = 0;   
    uint32_t sizeOfHeaders = 0;
    uint32_t sectionAlignment = 0;
    uint32_t fileAlignment = 0;
    uint32_t numberOfSections = 0;
    uint32_t sectionHeaderOffset = 0; // offset of first IMAGE_SECTION_HEADER
    uint64_t imageBase = 0;

    IMAGE_NT_HEADERS32 nt32{};
    IMAGE_NT_HEADERS64 nt64{};

    IMAGE_DATA_DIRECTORY dataDirectory(size_t index) const {
      if (is64) {
        if (index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return {};
        return nt64.OptionalHeader.DataDirectory[index];
      }
      if (index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return {};
      return nt32.OptionalHeader.DataDirectory[index];
    }
  };

  inline std::optional<PEView> parsePEHeaders(const uint8_t* data, size_t size) {
    if (!data || size < sizeof(IMAGE_DOS_HEADER)) return std::nullopt;

    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return std::nullopt; // "MZ"

    if (dos->e_lfanew < 0 ||
      static_cast<uint64_t>(dos->e_lfanew) + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) > size) {
      return std::nullopt;
    }

    const uint8_t* ntBase = data + dos->e_lfanew;
    uint32_t signature = readU32(ntBase);
    if (signature != IMAGE_NT_SIGNATURE) return std::nullopt; // "PE\0\0"

    const IMAGE_FILE_HEADER* fh =
      reinterpret_cast<const IMAGE_FILE_HEADER*>(ntBase + sizeof(uint32_t));

    const uint8_t* optHeaderBase = ntBase + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);
    if (static_cast<size_t>(optHeaderBase - data) + sizeof(uint16_t) > size) return std::nullopt;
    uint16_t magic = readU16(optHeaderBase);

    PEView view;
    view.data = data;
    view.size = size;
    view.ntHeaderOffset = static_cast<uint32_t>(dos->e_lfanew);

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      view.is64 = false;
      if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS32) > size) return std::nullopt;
      std::memcpy(&view.nt32, ntBase, sizeof(IMAGE_NT_HEADERS32));
      view.sizeOfHeaders = view.nt32.OptionalHeader.SizeOfHeaders;
      view.sectionAlignment = view.nt32.OptionalHeader.SectionAlignment;
      view.fileAlignment = view.nt32.OptionalHeader.FileAlignment;
      view.numberOfSections = fh->NumberOfSections;
      view.imageBase = view.nt32.OptionalHeader.ImageBase;
      view.sectionHeaderOffset = dos->e_lfanew + sizeof(IMAGE_NT_HEADERS32);
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
      view.is64 = true;
      if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > size) return std::nullopt;
      std::memcpy(&view.nt64, ntBase, sizeof(IMAGE_NT_HEADERS64));
      view.sizeOfHeaders = view.nt64.OptionalHeader.SizeOfHeaders;
      view.sectionAlignment = view.nt64.OptionalHeader.SectionAlignment;
      view.fileAlignment = view.nt64.OptionalHeader.FileAlignment;
      view.numberOfSections = fh->NumberOfSections;
      view.imageBase = view.nt64.OptionalHeader.ImageBase;
      view.sectionHeaderOffset = dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    }
    else {
      return std::nullopt; 
    }

    if (static_cast<uint64_t>(view.sectionHeaderOffset) +
      static_cast<uint64_t>(view.numberOfSections) * sizeof(IMAGE_SECTION_HEADER) > size) {
      return std::nullopt;
    }

    return view;
  }

  inline std::vector<IMAGE_SECTION_HEADER> readSectionHeaders(const PEView& view) {
    std::vector<IMAGE_SECTION_HEADER> result;
    result.resize(view.numberOfSections);
    std::memcpy(result.data(), view.data + view.sectionHeaderOffset,
      view.numberOfSections * sizeof(IMAGE_SECTION_HEADER));
    return result;
  }

  inline std::vector<uint8_t> readDosStub(const uint8_t* data, size_t size) {
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
    size_t stubStart = sizeof(IMAGE_DOS_HEADER);
    size_t stubEnd = static_cast<size_t>(dos->e_lfanew);
    if (stubEnd < stubStart || stubEnd > size) return {};
    return std::vector<uint8_t>(data + stubStart, data + stubEnd);
  }

} // namespace UpxPE
