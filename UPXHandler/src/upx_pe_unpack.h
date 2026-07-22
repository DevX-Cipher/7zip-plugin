#pragma once

#include "upx_pe_helpers.h"
#include <vector>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <functional>

namespace UpxPE {
  using ApplyFilterFn = std::function<bool(uint8_t* pData, int64_t nDataSize,
    uint8_t nFilter, uint8_t nFilterCTO, uint32_t nAddValue)>;

  struct UnpackPEParams {
    const std::vector<uint8_t>* packedFile = nullptr;
    std::vector<uint8_t>* payload = nullptr;

    uint8_t filter = 0;
    uint8_t filterCTO = 0;

    ApplyFilterFn applyFilter = nullptr;
  };

  namespace detail {
    inline uint32_t rd32(const uint8_t* p) { return readU32(p); }
    inline uint16_t rd16(const uint8_t* p) { return readU16(p); }

  } // namespace detail

  inline bool unpackPE(const UnpackPEParams& params, std::vector<uint8_t>* out) {
    if (!params.packedFile || !params.payload || !out) return false;
    if (params.payload->size() < 4) return false;

    std::vector<uint8_t>& payload = *params.payload;

    const std::vector<uint8_t>& packed = *params.packedFile;
    if (packed.size() < sizeof(IMAGE_DOS_HEADER)) return false;

    IMAGE_DOS_HEADER dosHeader{};
    std::memcpy(&dosHeader, packed.data(), sizeof(IMAGE_DOS_HEADER));
    std::vector<uint8_t> dosStub = readDosStub(packed.data(), packed.size());

    uint32_t extraInfoOffset = detail::rd32(payload.data() + payload.size() - 4);

    if (static_cast<uint64_t>(extraInfoOffset) + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) + sizeof(uint16_t)
    > payload.size()) {
      return false;
    }

    const uint8_t* ntBase = payload.data() + extraInfoOffset;
    uint16_t magic = detail::rd16(ntBase + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER));
    bool is64 = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    if (!is64 && magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return false;

    size_t ntHeaderSize = is64 ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32);
    if (static_cast<uint64_t>(extraInfoOffset) + ntHeaderSize > payload.size()) return false;

    IMAGE_NT_HEADERS32 nt32{};
    IMAGE_NT_HEADERS64 nt64{};
    uint32_t fileAlignment = 0, sectionAlignment = 0;
    int64_t rvaMin = 0;
    int numberOfSections = 0;
    uint32_t baseOfCode = 0, sizeOfCode = 0;

    const uint8_t* cursor = ntBase;

    if (!is64) {
      std::memcpy(&nt32, cursor, sizeof(IMAGE_NT_HEADERS32));
      if (nt32.Signature != IMAGE_NT_SIGNATURE) return false;
      fileAlignment = nt32.OptionalHeader.FileAlignment;
      sectionAlignment = nt32.OptionalHeader.SectionAlignment;
      rvaMin = static_cast<int64_t>(alignUp(nt32.OptionalHeader.SizeOfHeaders, sectionAlignment));
      numberOfSections = nt32.FileHeader.NumberOfSections;
      baseOfCode = nt32.OptionalHeader.BaseOfCode;
      sizeOfCode = nt32.OptionalHeader.SizeOfCode;
      cursor += sizeof(IMAGE_NT_HEADERS32);
    }
    else {
      std::memcpy(&nt64, cursor, sizeof(IMAGE_NT_HEADERS64));
      if (nt64.Signature != IMAGE_NT_SIGNATURE) return false;
      fileAlignment = nt64.OptionalHeader.FileAlignment;
      sectionAlignment = nt64.OptionalHeader.SectionAlignment;
      rvaMin = static_cast<int64_t>(alignUp(nt64.OptionalHeader.SizeOfHeaders, sectionAlignment));
      numberOfSections = nt64.FileHeader.NumberOfSections;
      baseOfCode = nt64.OptionalHeader.BaseOfCode;
      sizeOfCode = nt64.OptionalHeader.SizeOfCode;
      cursor += sizeof(IMAGE_NT_HEADERS64);
    }

    if (numberOfSections < 0 || numberOfSections > 96) return false; 

    std::vector<IMAGE_SECTION_HEADER> sections(numberOfSections);
    size_t sectionsBytes = static_cast<size_t>(numberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if (static_cast<size_t>(cursor - payload.data()) + sectionsBytes > payload.size()) return false;
    std::memcpy(sections.data(), cursor, sectionsBytes);
    cursor += sectionsBytes;

    std::vector<uint8_t> image(static_cast<size_t>(rvaMin) + payload.size(), 0);
    uint8_t* memOut0 = image.data();
    uint8_t* memOut = memOut0 + rvaMin;
    std::memcpy(memOut, payload.data(), payload.size());

    if (sizeOfCode && baseOfCode >= static_cast<uint32_t>(rvaMin) &&
      (static_cast<int64_t>(baseOfCode) - rvaMin + sizeOfCode) <= static_cast<int64_t>(payload.size())) {
      uint8_t* filterData = memOut + (baseOfCode - rvaMin);
      int64_t filterSize = sizeOfCode;
      uint32_t addValue = baseOfCode - static_cast<uint32_t>(rvaMin);

      if (params.applyFilter) {
        if (!params.applyFilter(filterData, filterSize, params.filter, params.filterCTO, addValue)) {
          return false;
        }
      }
    }

    auto dataDir = [&](int index) -> IMAGE_DATA_DIRECTORY {
      if (is64) return nt64.OptionalHeader.DataDirectory[index];
      return nt32.OptionalHeader.DataDirectory[index];
      };
    bool hasImport = dataDir(IMAGE_DIRECTORY_ENTRY_IMPORT).VirtualAddress != 0;
    bool hasTinyRelocs = dataDir(IMAGE_DIRECTORY_ENTRY_BASERELOC).Size == 8;
    bool hasRelocs = dataDir(IMAGE_DIRECTORY_ENTRY_BASERELOC).VirtualAddress != 0 &&
      dataDir(IMAGE_DIRECTORY_ENTRY_BASERELOC).Size != 0 &&
      !(is64 ? (nt64.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
        : (nt32.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED));

    if (hasImport) {
      if (static_cast<size_t>(cursor - payload.data()) + 8 > payload.size()) return false;
      uint32_t importOffset = detail::rd32(cursor);
      uint32_t iNamePosition = detail::rd32(cursor + 4);
      cursor += 8;

      uint8_t* iData = memOut + importOffset;

      if (!params.packedFile) return false;
      auto origImportOpt = parsePEHeaders(packed.data(), packed.size());
      if (!origImportOpt) return false;
      IMAGE_DATA_DIRECTORY origImportDir = origImportOpt->dataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT);
      if (origImportDir.VirtualAddress == 0 || origImportDir.Size == 0) return false;

      auto origSections = readSectionHeaders(*origImportOpt);
      auto rvaToFileOffsetPacked = [&](uint32_t rva) -> int64_t {
        for (auto& s : origSections) {
          if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.SizeOfRawData) {
            return static_cast<int64_t>(s.PointerToRawData) + (rva - s.VirtualAddress);
          }
        }
        return -1;
        };
      int64_t origImportFileOffset = rvaToFileOffsetPacked(origImportDir.VirtualAddress);
      if (origImportFileOffset < 0 ||
        static_cast<uint64_t>(origImportFileOffset) + origImportDir.Size > packed.size()) {
        return false;
      }
      const uint8_t* importDirBytes = packed.data() + origImportFileOffset;
      size_t importDirSize = origImportDir.Size;

      const uint8_t* walk = iData;
      uint32_t dllNamesTotal = 0;
      while (detail::rd32(walk)) {
        uint32_t nameOffset = detail::rd32(walk);
        if (nameOffset >= importDirSize) return false;
        const char* dllName = reinterpret_cast<const char*>(importDirBytes + nameOffset);
        size_t nameLen = strnlen(dllName, importDirSize - nameOffset);
        dllNamesTotal += static_cast<uint32_t>(nameLen) + 1;
        walk += 8;

        while (*walk) {
          if (*walk == 1) {
            walk += 1;
            walk += strlen(reinterpret_cast<const char*>(walk)) + 1;
          }
          else if (*walk == 0xFF) {
            walk += 1 + 2;
          }
          else {
            walk += 1 + 4;
          }
        }
        walk += 1;
      }
      dllNamesTotal = static_cast<uint32_t>(alignUp(dllNamesTotal, 2));

      uint8_t* iid = memOut0 + (is64
        ? nt64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
        : nt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

      uint8_t* dllNames = memOut0 + iNamePosition;
      uint8_t* importedNames = dllNames + dllNamesTotal;
      uint8_t* importedNamesStart = importedNames;

      walk = iData;
      while (detail::rd32(walk)) {
        uint32_t nameOffset = detail::rd32(walk);
        const char* dllName = reinterpret_cast<const char*>(importDirBytes + nameOffset);
        size_t nameLen = strnlen(dllName, importDirSize - nameOffset);
        uint32_t iatRVA = detail::rd32(walk + 4) + static_cast<uint32_t>(rvaMin);

        if (iNamePosition) {
          std::memcpy(dllNames, dllName, nameLen + 1);
          writeU32(reinterpret_cast<uint8_t*>(&iid[offsetof(IMAGE_IMPORT_DESCRIPTOR, Name)]),
            static_cast<uint32_t>(dllNames - memOut0));
          dllNames += nameLen + 1;
        }
        else {
          uint32_t existingNameRVA = detail::rd32(&iid[offsetof(IMAGE_IMPORT_DESCRIPTOR, Name)]);
          std::memcpy(memOut0 + existingNameRVA, dllName, nameLen + 1);
        }

        writeU32(reinterpret_cast<uint8_t*>(&iid[offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk)]), iatRVA);
        uint8_t* iat = memOut0 + iatRVA;
        walk += 8;
        int thunkStep = is64 ? 8 : 4;

        while (*walk) {
          if (*walk == 1) {
            walk += 1;
            size_t importNameLen = strlen(reinterpret_cast<const char*>(walk)) + 1;

            if (iNamePosition) {
              if ((importedNames - importedNamesStart) & 1) importedNames -= 1;
              std::memcpy(importedNames + 2, walk, importNameLen);
              uint32_t delta = static_cast<uint32_t>(importedNames - memOut0);
              writeU32(iat, delta);
              importedNames += 2 + importNameLen;
            }
            else {
              uint32_t iAddress = detail::rd32(iat);
              std::memcpy(memOut0 + iAddress + 2, walk, importNameLen);
            }
            walk += importNameLen;
          }
          else if (*walk == 0xFF) {
            uint16_t ordinal = detail::rd16(walk + 1);
            if (!is64) {
              writeU32(iat, static_cast<uint32_t>(ordinal) + 0x80000000u);
            }
            else {
              writeU64(iat, static_cast<uint64_t>(ordinal) + 0x8000000000000000ULL);
            }
            walk += 1 + 2;
          }
          else {
            uint32_t thunkOffset = detail::rd32(walk + 1);
            if (static_cast<uint64_t>(thunkOffset) + 4 > importDirSize) return false;
            uint32_t thunkValue = detail::rd32(importDirBytes + thunkOffset);
            if (!is64) writeU32(iat, thunkValue);
            else writeU64(iat, thunkValue);
            walk += 1 + 4;
          }
          iat += thunkStep;
        }

        if (!is64) writeU32(iat, 0);
        else writeU64(iat, 0);

        walk += 1; 
        iid += sizeof(IMAGE_IMPORT_DESCRIPTOR);
      }
    }

    if (hasTinyRelocs) {
      uint32_t relocRVA = is64
        ? nt64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
        : nt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
      static const uint8_t emptyBlock[8] = { 0,0,0,0, 8,0,0,0 };
      std::memcpy(memOut0 + relocRVA, emptyBlock, 8);
    }
    else if (hasRelocs) {
      if (static_cast<size_t>(cursor - payload.data()) + 5 > payload.size()) return false;
      uint32_t relocsOffset = detail::rd32(cursor);
      cursor += 5;

      uint8_t* relocs = memOut + relocsOffset;
      int relocsCount = 0;
      for (uint8_t* p = relocs; *p; p++) {
        if (static_cast<uint8_t>(*p) >= 0xF0) {
          if (static_cast<uint8_t>(*p) == 0xF0 && detail::rd16(p + 1) == 0) p += 4;
          p += 2;
        }
        relocsCount++;
      }

      std::vector<uint8_t> relocList(4 * relocsCount + 4, 0);
      uint8_t* outReloc = relocList.data();
      uint32_t jc = static_cast<uint32_t>(-4);
      uint8_t* p = relocs;

      for (; *p; p++) {
        if (static_cast<uint8_t>(*p) < 0xF0) {
          jc += static_cast<uint8_t>(*p);
        }
        else {
          uint32_t dif = (*p & 0x0F) * 0x10000 + detail::rd16(p + 1);
          p += 2;
          if (dif == 0) {
            dif = detail::rd32(p + 1);
            p += 4;
          }
          jc += dif;
        }
        writeU32(outReloc, jc);
        outReloc += 4;

        uint8_t* target = memOut + jc;
        if (!is64) {
          uint32_t v = detail::rd32(target);

          target[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
          target[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
          target[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
          target[3] = static_cast<uint8_t>(v & 0xFF);
        }
        else {
          uint64_t v = readU64(target);
          for (int i = 0; i < 8; i++) target[i] = static_cast<uint8_t>((v >> (56 - 8 * i)) & 0xFF);
        }
      }

      int relocsCount2 = static_cast<int>((outReloc - relocList.data()) / 4);
      std::vector<uint32_t> relocRVAs;
      relocRVAs.reserve(relocsCount2);

      for (int i = 0; i < relocsCount2; i++) {
        uint32_t off = detail::rd32(relocList.data() + 4 * i);
        uint8_t* target = memOut + off;
        if (!is64) {
          uint32_t v = readU32(target);
          writeU32(target, v + static_cast<uint32_t>(nt32.OptionalHeader.ImageBase) + static_cast<uint32_t>(rvaMin));
        }
        else {
          uint64_t v = readU64(target);
          writeU64(target, v + nt64.OptionalHeader.ImageBase + static_cast<uint64_t>(rvaMin));
        }
        relocRVAs.push_back(static_cast<uint32_t>(rvaMin) + off);
      }

      std::vector<uint8_t> relocBlob;
      std::sort(relocRVAs.begin(), relocRVAs.end());
      size_t i = 0;
      while (i < relocRVAs.size()) {
        uint32_t pageBase = relocRVAs[i] & ~0xFFFu;
        size_t start = i;
        while (i < relocRVAs.size() && (relocRVAs[i] & ~0xFFFu) == pageBase) i++;
        size_t count = i - start;
        uint32_t blockSize = static_cast<uint32_t>(8 + count * 2 + ((count & 1) ? 2 : 0));

        size_t base = relocBlob.size();
        relocBlob.resize(base + blockSize, 0);
        writeU32(relocBlob.data() + base, pageBase);
        writeU32(relocBlob.data() + base + 4, blockSize);
        for (size_t j = 0; j < count; j++) {
          uint16_t entry = static_cast<uint16_t>(((is64 ? 0xA : 0x3) << 12) | (relocRVAs[start + j] & 0xFFF));
          writeU16(relocBlob.data() + base + 8 + j * 2, entry);
        }
      }

      uint32_t relocDirVA = is64
        ? nt64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
        : nt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
      if (static_cast<uint64_t>(relocDirVA) + relocBlob.size() > image.size()) return false;
      std::memcpy(memOut0 + relocDirVA, relocBlob.data(), relocBlob.size());
      if (is64) nt64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = static_cast<uint32_t>(relocBlob.size());
      else nt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = static_cast<uint32_t>(relocBlob.size());
    }

    int64_t fileSize = 0;
    for (auto& s : sections) {
      if (s.PointerToRawData) {
        fileSize = std::max<int64_t>(fileSize, static_cast<int64_t>(s.PointerToRawData) + s.SizeOfRawData);
      }
    }
    fileSize = static_cast<int64_t>(alignUp(fileSize, fileAlignment));
    if (fileSize <= 0) return false;

    out->assign(static_cast<size_t>(fileSize), 0);

    size_t offset = 0;
    std::memcpy(out->data() + offset, &dosHeader, sizeof(IMAGE_DOS_HEADER));
    offset += sizeof(IMAGE_DOS_HEADER);
    std::memcpy(out->data() + offset, dosStub.data(), dosStub.size());
    offset += dosStub.size();

    size_t ntOffset = static_cast<size_t>(dosHeader.e_lfanew);
    if (ntOffset + ntHeaderSize > out->size()) return false;

    if (!is64) {
      nt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG] = {};
      nt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] = {};
      nt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT] = {};
      nt32.OptionalHeader.CheckSum = 0;
      std::memcpy(out->data() + ntOffset, &nt32, sizeof(IMAGE_NT_HEADERS32));
    }
    else {
      nt64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG] = {};
      nt64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] = {};
      nt64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT] = {};
      nt64.OptionalHeader.CheckSum = 0;
      std::memcpy(out->data() + ntOffset, &nt64, sizeof(IMAGE_NT_HEADERS64));
    }

    size_t sectionTableOffset = ntOffset + ntHeaderSize;
    if (sectionTableOffset + sectionsBytes > out->size()) return false;
    std::memcpy(out->data() + sectionTableOffset, sections.data(), sectionsBytes);

    for (auto& s : sections) {
      if (s.PointerToRawData) {
        uint64_t copySize = alignUp(s.SizeOfRawData, fileAlignment);
        if (static_cast<uint64_t>(s.VirtualAddress) + copySize > image.size()) return false;
        if (static_cast<uint64_t>(s.PointerToRawData) + copySize > out->size()) return false;
        std::memcpy(out->data() + s.PointerToRawData, memOut0 + s.VirtualAddress, copySize);
      }
    }

    return true;
  }

} // namespace UpxPE
