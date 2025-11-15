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
#include "zlib_decoder.h"

// ---------------------------------------------------------------------
// PUP constants
// ---------------------------------------------------------------------
#define PS3_PUP_MAGIC 0x53434555 
#define PS4_PUP_MAGIC 0x1D3D154F
#define PS5_PUP_MAGIC 0xEEF51454 
#define PS3_SELF      0x53434500
#define TAR_GZ        0x1F8B0800

// ---------------------------------------------------------------------
// PS3 PUP structures (packed)
// ---------------------------------------------------------------------
#pragma pack(push, 1)
struct PS3_PUP_HEADER {
  uint32_t magic;
  uint32_t package_version;
  uint32_t image_version;
  uint32_t file_count;
  uint32_t header_length;
  uint32_t data_length;
  uint64_t reserved;
};

struct PS3_PUP_FILE_ENTRY {
  uint64_t entry_id;
  uint64_t data_offset;
  uint64_t data_length;
  uint64_t reserved;
};

struct PS3_PUP_FILE_HASH {
  uint64_t entry_id;
  uint8_t  hash[0x14];
  uint32_t reserved;
};

// ---------------------------------------------------------------------
// PS4/PS5 PUP structures (packed)
// ---------------------------------------------------------------------
struct PS4_PUP_HEADER {
  uint32_t magic;
  uint32_t unknown04;
  uint16_t unknown08;
  uint8_t  flags;
  uint8_t  unknown0B;
  uint16_t header_size;
  uint16_t hash_size;
  int64_t  file_size;
  uint16_t entry_count;
  uint16_t hash_count;
  uint32_t unknown1C;
};

struct PSX_PUP_ENTRY {
  uint32_t flags;
  uint32_t reserved;
  int64_t  offset;
  int64_t  compressed_size;
  int64_t  uncompressed_size;
};

struct PSX_BLOCK_INFO {
  uint32_t offset;
  uint32_t size;
};
#pragma pack(pop)


class PUPHandler {
private:
  enum PUPType {
    PUP_TYPE_UNKNOWN,
    PUP_TYPE_PS3,
    PUP_TYPE_PS4,
    PUP_TYPE_PS5
  };

  PUPType pupType = PUP_TYPE_UNKNOWN;

  // PS3 data
  PS3_PUP_HEADER                  ps3Header = {};
  std::vector<PS3_PUP_FILE_ENTRY> ps3FileEntries;
  std::vector<PS3_PUP_FILE_HASH>  ps3FileHashes;

  // PS4/PS5 data
  PS4_PUP_HEADER                  ps4Header = {};
  std::vector<PSX_PUP_ENTRY>      psxEntries;

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

  std::string GetPS4FileName(uint32_t id) {
    static std::map<uint32_t, std::string> fileNames = {
        {3, "wlan_firmware.bin"},
        {5, "secure_modules.bin"},
        {6, "system_fs_image.img"},
        {8, "eap_fs_image.img"},
        {9, "recovery_fs_image.img"},
        {11, "preinst_fs_image.img"},
        {12, "system_ex_fs_image.img"},
        {34, "torus2_firmware.bin"},
        {257, "eula.xml"},
        {512, "orbis_swu.self"},
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
      return std::to_string(id) + "_" + fnIt->second;
    }

    auto devIt = deviceNames.find(id);
    if (devIt != deviceNames.end()) {
      std::stringstream ss;
      ss << "devices/" << id << "__dev_" << devIt->second << ".bin";
      return ss.str();
    }

    std::stringstream ss;
    ss << "unknown/" << id << ".img";
    return ss.str();
  }

  std::string GetPS5FileName(uint32_t id) {
    static std::map<uint32_t, std::string> fileNames = {
      {1, "eula.xml"},
      {2, "updatemode.elf"},
      {3, "emc_salina_a0.bin"},
      {4, "mbr.bin"},
      {5, "kernel.bin"},
      {6, "unk_06.bin"},
      {7, "unk_07.bin"},
      {8, "unk_08.bin"},
      {9, "unk_09.bin"},
      {10, "CP.bin"},
      {11, "titania.bls"},
      {12, "version_name.xml"},
      {13, "emc_salina_b0.bin"},
      {14, "eap_kbl.bin"},
      {15, "bd_firm_info.json"},
      {16, "emc_salina_c0.bls"},
      {17, "floyd_salina_c0.bls"},
      {18, "usb_pdc_salina_c0.bls"},
      {20, "emc_salina_d0.bls"},
      {21, "eap_kbl_2.bin"},
      {22, "font.zip"},
      {256, "ariel_a0.bin"},
      {257, "oberon_sec_ldr_a0.bin"},
      {258, "oberon_sec_ldr_b0.bin"},
      {259, "oberon_sec_ldr_c0.bin"},
      {260, "oberon_sec_ldr_d0.bin"},
      {261, "oberon_sec_ldr_f0.bin"},
      {262, "oberon_sec_ldr_e0.bin"},
      {752, "qa_test_1.pkg"},
      {753, "qa_test_2.pkg"},
      {754, "qa_test_3.pkg"}
    };

    static std::map<uint32_t, std::string> deviceNames = {
      {512, "dev/unk_512.bin"},
      {513, "dev/wlanbt.bin"},
      {514, "dev/unk_514.bin"},
      {515, "dev/ssd0.system_b"},
      {516, "dev/ssd0.system_ex_b"},
      {517, "dev/unk_517.bin"},
      {518, "dev/unk_518.bin"},
      {519, "dev/ssd0.preinst"}
    };

    auto fnIt = fileNames.find(id);
    if (fnIt != fileNames.end()) {
      return std::to_string(id) + "_" + fnIt->second;
    }

    auto devIt = deviceNames.find(id);
    if (devIt != deviceNames.end()) {
      std::string device = devIt->second;
      auto pos = device.rfind("/");
      if (pos != std::string::npos) {
        std::string dir = device.substr(0, pos + 1);
        std::string file = device.substr(pos + 1);
        return dir + std::to_string(id) + "_" + file;
      }
      else {
        return std::to_string(id) + "_" + device;
      }
    }

    return "/unknown/" + std::to_string(id) + ".img";
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
    logDebug(L"PS3 PUP header accepted");
    return S_OK;
  }

  HRESULT ParsePS4Header(IInStream* stream, UInt64 fileSize) {
    archiveSize = fileSize;
    RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));

    uint8_t headerBytes[0x20];
    UInt32 bytesRead = 0;
    RINOK(stream->Read(headerBytes, 0x20, &bytesRead));
    if (bytesRead != 0x20) {
      return E_FAIL;
    }

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

    if (ps4Header.entry_count == 0 || ps4Header.entry_count > 1000) {
      return E_FAIL;
    }

    if (ps4Header.header_size < 0x20) {
      return E_FAIL;
    }

    pupType = PUP_TYPE_PS4;
    return S_OK;
  }
  HRESULT ParsePS5Header(IInStream* stream, UInt64 fileSize) {
    archiveSize = fileSize;
    RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));

    uint8_t headerBytes[0x20];
    UInt32 bytesRead = 0;
    RINOK(stream->Read(headerBytes, 0x20, &bytesRead));
    if (bytesRead != 0x20) return E_FAIL;

    ps4Header.magic = headerBytes[0] | (headerBytes[1] << 8) |
      (headerBytes[2] << 16) | (headerBytes[3] << 24);

    if (ps4Header.magic != PS5_PUP_MAGIC) {
      return E_FAIL;
    }

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


    if (ps4Header.entry_count == 0 || ps4Header.entry_count > 1000) {
      return E_FAIL;
    }

    if (ps4Header.header_size < 0x20) {
      return E_FAIL;
    }

    pupType = PUP_TYPE_PS5;
    return S_OK;
  }

  bool ZlibDecode(const uint8_t* compressedData, size_t compressedSize, uint8_t* outputData, size_t outputSize) {
    ByteVector* output = bytevector_create(outputSize);
    if (!output) {
      return false;
    }

    size_t consumed = 0;
    int result = zlib_decompress_no_checksum(compressedData, compressedSize, output, &consumed);

    if (result < 0 || output->length != outputSize) {
      bytevector_free(output);
      return false;
    }

    memcpy(outputData, output->data, output->length);
    bytevector_free(output);
    return true;
  }

public:
  struct FileInfo {
    uint64_t  offset = 0;
    uint64_t  size = 0;
    uint64_t  uncompressed_size = 0;
    uint64_t  entryId = 0;
    uint32_t  type = 0;
    uint32_t  flags = 0;
    uint16_t  entryIndex = 0;
    int tableIndex = -1;
    std::string path;
    bool      isFolder = false;
    bool      isCompressed = false;
    bool      isBlocked = false;
    int64_t   fileTime1 = 0;
    int64_t   fileTime2 = 0;
    int64_t   fileTime3 = 0;
  };

  HRESULT ParseHeader(IInStream* stream, UInt64 fileSize) {

    uint8_t magicBytes[4];
    UInt32 bytesRead = 0;

    RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));
    RINOK(stream->Read(magicBytes, 4, &bytesRead));

    if (bytesRead != 4) {
      return E_FAIL;
    }

    uint32_t magicBE = (magicBytes[0] << 24) | (magicBytes[1] << 16) |
      (magicBytes[2] << 8) | magicBytes[3];

    uint32_t magicLE = magicBytes[0] | (magicBytes[1] << 8) |
      (magicBytes[2] << 16) | (magicBytes[3] << 24);


    if (magicBE == PS3_PUP_MAGIC) {
      return ParsePS3Header(stream, fileSize);
    }

    if (magicLE == PS5_PUP_MAGIC) {
      return ParsePS5Header(stream, fileSize);
    }

    if (magicLE == PS4_PUP_MAGIC) {
      return ParsePS4Header(stream, fileSize);
    }


    uint8_t headerBytes[0x20];
    RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));
    RINOK(stream->Read(headerBytes, 0x20, &bytesRead));

    if (bytesRead != 0x20) {
      return E_FAIL;
    }

    uint16_t header_size = headerBytes[0x0C] | (headerBytes[0x0D] << 8);
    uint16_t entry_count = headerBytes[0x18] | (headerBytes[0x19] << 8);
    uint16_t hash_count = headerBytes[0x1A] | (headerBytes[0x1B] << 8);

    bool headerSizeOK = (header_size >= 0x20 && header_size <= 0x100000);
    bool entryCountOK = (entry_count > 0 && entry_count <= 5000);
    bool hashCountOK = (hash_count <= 5000);

    if (headerSizeOK && entryCountOK && hashCountOK) {
      return ParsePS4Header(stream, fileSize);
    }

    return E_FAIL;
  }

  HRESULT ExtractFileToStream(IInStream* inStream, const FileInfo& fi, ISequentialOutStream* outStream) {
    if (fi.isFolder || fi.size == 0) return S_OK;

    if (fi.size > archiveSize) return E_FAIL;
    if (fi.offset >= archiveSize || fi.offset + fi.size > archiveSize) return E_FAIL;

    if (pupType == PUP_TYPE_PS3) {
      return ExtractPS3File(inStream, fi, outStream);
    }
    else if (pupType == PUP_TYPE_PS4) {
      return ExtractPS4File(inStream, fi, outStream);
    }
    else if (pupType == PUP_TYPE_PS5) {
      return ExtractPS5File(inStream, fi, outStream);
    }

    return E_FAIL;
  }

  HRESULT ParseFileTable(IInStream* stream, std::vector<FileInfo>& items) {
    if (pupType == PUP_TYPE_PS3) {
      return ParsePS3FileTable(stream, items);
    }
    else if (pupType == PUP_TYPE_PS4) {
      return ParsePS4FileTable(stream, items);
    }
    else if (pupType == PUP_TYPE_PS5) {
      return ParsePS5FileTable(stream, items);
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
      fi.entryIndex = i;
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

    RINOK(stream->Seek(ENTRIES_OFFSET, STREAM_SEEK_SET, nullptr));
    psxEntries.resize(ps4Header.entry_count);

    // Read all entries
    for (uint16_t i = 0; i < ps4Header.entry_count; i++) {
      uint8_t entryBytes[0x20];
      UInt32 bytesRead = 0;
      HRESULT hr = stream->Read(entryBytes, 0x20, &bytesRead);
      if (FAILED(hr) || bytesRead != 0x20) return E_FAIL;

      psxEntries[i].flags = entryBytes[0] | (entryBytes[1] << 8) |
        (entryBytes[2] << 16) | (entryBytes[3] << 24);
      psxEntries[i].reserved = entryBytes[4] | (entryBytes[5] << 8) |
        (entryBytes[6] << 16) | (entryBytes[7] << 24);
      psxEntries[i].offset = 0;
      for (int j = 0; j < 8; j++)
        psxEntries[i].offset |= ((int64_t)entryBytes[8 + j] << (j * 8));
      psxEntries[i].compressed_size = 0;
      for (int j = 0; j < 8; j++)
        psxEntries[i].compressed_size |= ((int64_t)entryBytes[16 + j] << (j * 8));
      psxEntries[i].uncompressed_size = 0;
      for (int j = 0; j < 8; j++)
        psxEntries[i].uncompressed_size |= ((int64_t)entryBytes[24 + j] << (j * 8));
    }

    std::vector<int> tableEntries(ps4Header.entry_count, -2);

    for (uint16_t i = 0; i < ps4Header.entry_count; i++) {
      auto& entry = psxEntries[i];
      bool isBlocked = (entry.flags & 0x800) != 0;

      if (!isBlocked) {
        continue;
      }

      uint32_t entry_id = entry.flags >> 20;
      if (((entry_id | 0x100) & 0xF00) == 0xF00) {
        continue;
      }


      int tableIndex = -1;
      for (uint16_t j = 0; j < ps4Header.entry_count; j++) {
        if ((psxEntries[j].flags & 1) != 0) {
          uint32_t table_id = psxEntries[j].flags >> 20;
          if (table_id == i) {
            tableIndex = j;
            break;
          }
        }
      }

      if (tableIndex < 0) {
        continue;
      }

      if (tableEntries[tableIndex] != -2) {
        continue;
      }

      tableEntries[tableIndex] = i;
    }

    for (uint16_t i = 0; i < ps4Header.entry_count; i++) {
      auto& entry = psxEntries[i];
      uint32_t special = entry.flags & 0xF0000000;

      if (special == 0xE0000000 || special == 0xF0000000) {
        continue;
      }

      FileInfo fi;
      fi.offset = entry.offset;
      fi.size = entry.compressed_size;
      fi.uncompressed_size = entry.uncompressed_size;
      fi.entryId = entry.flags >> 20;
      fi.type = entry.flags;
      fi.flags = entry.flags;
      fi.entryIndex = i;
      fi.isFolder = false;
      fi.isCompressed = (entry.flags & 8) != 0;
      fi.isBlocked = (entry.flags & 0x800) != 0;
      fi.tableIndex = -1;

      if (tableEntries[i] >= 0) {
        uint32_t blockedFileIndex = tableEntries[i];
        uint32_t blockedFileId = psxEntries[blockedFileIndex].flags >> 20;
        std::stringstream ss;
        ss << "tables/" << fi.entryId << "_for_" << blockedFileId << ".img";
        fi.path = ss.str();

      }
      else {
        // Regular file (not a table)
        fi.path = GetPS4FileName(static_cast<uint32_t>(fi.entryId));

        if (fi.isBlocked) {
          for (uint16_t j = 0; j < ps4Header.entry_count; j++) {
            if (tableEntries[j] == i) {
              fi.tableIndex = j;
              break;
            }
          }
        }
      }

      std::replace(fi.path.begin(), fi.path.end(), '\\', '/');
      items.push_back(std::move(fi));
    }

    return S_OK;
  }

  HRESULT ParsePS5FileTable(IInStream* stream, std::vector<FileInfo>& items) {
    const uint64_t ENTRIES_OFFSET = 0x20;

    RINOK(stream->Seek(ENTRIES_OFFSET, STREAM_SEEK_SET, nullptr));
    psxEntries.resize(ps4Header.entry_count);

    // Read all entries
    for (uint16_t i = 0; i < ps4Header.entry_count; i++) {
      uint8_t entryBytes[0x20];
      UInt32 bytesRead = 0;
      HRESULT hr = stream->Read(entryBytes, 0x20, &bytesRead);
      if (FAILED(hr) || bytesRead != 0x20) return E_FAIL;

      psxEntries[i].flags = entryBytes[0] | (entryBytes[1] << 8) |
        (entryBytes[2] << 16) | (entryBytes[3] << 24);
      psxEntries[i].reserved = entryBytes[4] | (entryBytes[5] << 8) |
        (entryBytes[6] << 16) | (entryBytes[7] << 24);
      psxEntries[i].offset = 0;
      for (int j = 0; j < 8; j++)
        psxEntries[i].offset |= ((int64_t)entryBytes[8 + j] << (j * 8));
      psxEntries[i].compressed_size = 0;
      for (int j = 0; j < 8; j++)
        psxEntries[i].compressed_size |= ((int64_t)entryBytes[16 + j] << (j * 8));
      psxEntries[i].uncompressed_size = 0;
      for (int j = 0; j < 8; j++)
        psxEntries[i].uncompressed_size |= ((int64_t)entryBytes[24 + j] << (j * 8));
    }

    std::vector<int> blockedToTable(ps4Header.entry_count, -1);

    for (uint16_t i = 0; i < ps4Header.entry_count; i++) {
      auto& entry = psxEntries[i];
      bool isBlocked = (entry.flags & 0x800) != 0;
      if (!isBlocked) continue;

      uint32_t entry_id = entry.flags >> 20;
      if (((entry_id | 0x100) & 0xF00) == 0xF00) continue;

      int tableIndex = -1;
      for (uint16_t j = 0; j < ps4Header.entry_count; j++) {
        if ((psxEntries[j].flags & 1) != 0) {
          uint32_t table_id = psxEntries[j].flags >> 20;
          if (table_id == i) {
            tableIndex = j;
            break;
          }
        }
      }

      if (tableIndex < 0) {
        continue;
      }

      blockedToTable[i] = tableIndex;
    }

    std::vector<int> tableEntries(ps4Header.entry_count, -2);
    for (uint16_t i = 0; i < ps4Header.entry_count; i++) {
      if (blockedToTable[i] >= 0) {
        int tableIdx = blockedToTable[i];
        if (tableEntries[tableIdx] == -2) {
          tableEntries[tableIdx] = i;
        }
      }
    }

    for (uint16_t i = 0; i < ps4Header.entry_count; i++) {
      auto& entry = psxEntries[i];
      uint32_t special = entry.flags & 0xF0000000;

      if (special == 0xE0000000 || special == 0xF0000000) {
        continue;
      }

      FileInfo fi;
      fi.offset = entry.offset;
      fi.size = entry.compressed_size;
      fi.uncompressed_size = entry.uncompressed_size;
      fi.entryId = entry.flags >> 20;
      fi.type = entry.flags;
      fi.flags = entry.flags;
      fi.entryIndex = i;
      fi.isFolder = false;
      fi.isCompressed = (entry.flags & 8) != 0;
      fi.isBlocked = (entry.flags & 0x800) != 0;
      fi.tableIndex = -1;

      if (fi.isBlocked && blockedToTable[i] >= 0) {
        fi.tableIndex = blockedToTable[i];
      }
      else if (fi.isBlocked) {
      }

      bool isTable = (entry.flags & 1) != 0;

      if (isTable && tableEntries[i] >= 0) {
        uint32_t blockedFileIndex = tableEntries[i];
        uint32_t blockedFileId = psxEntries[blockedFileIndex].flags >> 20;
        std::stringstream ss;
        ss << "tables/" << fi.entryId << "_for_" << blockedFileId << ".img";
        fi.path = ss.str();
      }
      else {
        fi.path = GetPS5FileName(static_cast<uint32_t>(fi.entryId));
      }

      std::replace(fi.path.begin(), fi.path.end(), '\\', '/');
      items.push_back(std::move(fi));
    }

    return S_OK;
  }

  HRESULT ExtractPS3File(IInStream* inStream, const FileInfo& fi, ISequentialOutStream* outStream) {
    const size_t CHUNK_SIZE = 2 * 1024 * 1024;
    std::vector<uint8_t> buffer(CHUNK_SIZE);

    uint64_t remaining = fi.size;
    RINOK(inStream->Seek(fi.offset, STREAM_SEEK_SET, nullptr));

    while (remaining > 0) {
      size_t toRead = (size_t)std::min((uint64_t)CHUNK_SIZE, remaining);

      UInt32 read = 0;
      RINOK(inStream->Read(buffer.data(), (UInt32)toRead, &read));
      if (read == 0) return E_FAIL;

      UInt32 written = 0;
      RINOK(outStream->Write(buffer.data(), read, &written));
      if (written != read) return E_FAIL;

      remaining -= read;
    }

    return S_OK;
  }

  HRESULT ExtractPS4File(IInStream* inStream, const FileInfo& fi, ISequentialOutStream* outStream) {
    if (!fi.isBlocked && !fi.isCompressed) {
      return ExtractSimpleFile(inStream, fi, outStream);
    }

    if (fi.isCompressed && !fi.isBlocked) {
      return E_FAIL;
    }

    if (fi.isBlocked) {
      return ExtractBlockedFile(inStream, fi, outStream);
    }

    return E_FAIL;
  }

  // PS5 extraction
  HRESULT ExtractPS5File(IInStream* inStream, const FileInfo& fi, ISequentialOutStream* outStream) {
    if (!fi.isBlocked && !fi.isCompressed) {
      return ExtractSimpleFile(inStream, fi, outStream);
    }

    if (fi.isCompressed && !fi.isBlocked) {
      return E_FAIL;
    }

    if (fi.isBlocked) {
      return ExtractBlockedFile(inStream, fi, outStream);
    }

    return E_FAIL;
  }

  HRESULT ExtractSimpleFile(IInStream* inStream, const FileInfo& fi, ISequentialOutStream* outStream) {
    const size_t CHUNK_SIZE = 2 * 1024 * 1024;
    std::vector<uint8_t> buffer(CHUNK_SIZE);

    uint64_t remaining = fi.size;
    RINOK(inStream->Seek(fi.offset, STREAM_SEEK_SET, nullptr));

    while (remaining > 0) {
      size_t toRead = (size_t)std::min((uint64_t)CHUNK_SIZE, remaining);

      UInt32 read = 0;
      RINOK(inStream->Read(buffer.data(), (UInt32)toRead, &read));
      if (read == 0) return E_FAIL;

      UInt32 written = 0;
      RINOK(outStream->Write(buffer.data(), read, &written));
      if (written != read) return E_FAIL;

      remaining -= read;
    }

    return S_OK;
  }

  HRESULT ExtractBlockedFile(IInStream* inStream, const FileInfo& fi, ISequentialOutStream* outStream) {
    if (fi.tableIndex < 0) {
      return E_FAIL;
    }

    PSX_PUP_ENTRY& tableEntry = psxEntries[fi.tableIndex];

    // Calculate block parameters
    int blockSizeShift = (int)(((fi.flags & 0xF000) >> 12) + 12);
    int blockSize = 1 << blockSizeShift;
    int blockCount = (int)((fi.uncompressed_size + blockSize - 1) / blockSize);
    int tailSize = (int)(fi.uncompressed_size % blockSize);
    if (tailSize == 0) tailSize = blockSize;


    // Read block info table
    std::vector<PSX_BLOCK_INFO> blockInfos(blockCount);

    if (fi.isCompressed) {

      RINOK(inStream->Seek(tableEntry.offset, STREAM_SEEK_SET, nullptr));

      std::vector<uint8_t> tableData;

      if (tableEntry.flags & 8) {
        std::vector<uint8_t> compressedTable(tableEntry.compressed_size);
        UInt32 read = 0;
        RINOK(inStream->Read(compressedTable.data(), (UInt32)tableEntry.compressed_size, &read));
        if (read != tableEntry.compressed_size) {
          return E_FAIL;
        }

        tableData.resize(tableEntry.uncompressed_size);
        if (!ZlibDecode(compressedTable.data(), tableEntry.compressed_size,
          tableData.data(), tableEntry.uncompressed_size)) {
          return E_FAIL;
        }
      }
      else {
        tableData.resize(tableEntry.compressed_size);
        UInt32 read = 0;
        RINOK(inStream->Read(tableData.data(), (UInt32)tableEntry.compressed_size, &read));
        if (read != tableEntry.compressed_size) return E_FAIL;
      }

      // Parse block info
      size_t blockInfoOffset = 32 * blockCount;

      for (int j = 0; j < blockCount; j++) {
        size_t idx = blockInfoOffset + (j * 8);
        if (idx + 8 > tableData.size()) {
          return E_FAIL;
        }

        blockInfos[j].offset = tableData[idx] | (tableData[idx + 1] << 8) |
          (tableData[idx + 2] << 16) | (tableData[idx + 3] << 24);
        blockInfos[j].size = tableData[idx + 4] | (tableData[idx + 5] << 8) |
          (tableData[idx + 6] << 16) | (tableData[idx + 7] << 24);

        if (j < 5 || j >= blockCount - 2) {
        }
      }
    }

    // Allocate output buffer
    std::vector<uint8_t> outputBuffer(fi.uncompressed_size, 0);

    int lastIndex = blockCount - 1;

    // Process blocks
    for (int i = 0; i < blockCount; i++) {
      size_t outputPosition = (size_t)i * blockSize;

      // Calculate expected uncompressed size for THIS block
      int expectedUncompressedSize = (i == lastIndex) ? tailSize : blockSize;

      bool blockIsCompressed = false;
      int compressedReadSize = 0;

      if (fi.isCompressed) {
        PSX_BLOCK_INFO& blockInfo = blockInfos[i];

        if (blockInfo.size == 0) {
          if (i < 5 || i >= blockCount - 2) {
          }
          continue;
        }

        // Determine compression
        int unpaddedSize = (blockInfo.size & ~0xFu) - (blockInfo.size & 0xFu);

        if (unpaddedSize != blockSize) {
          blockIsCompressed = true;
          compressedReadSize = blockInfo.size & ~0xFu;
        }
        else {
          // Uncompressed block
          compressedReadSize = expectedUncompressedSize;
        }

        int64_t blockOffset = fi.offset + blockInfo.offset;
        RINOK(inStream->Seek(blockOffset, STREAM_SEEK_SET, nullptr));

        if (i < 5 || i >= blockCount - 2) {
        }
      }
      else {
        compressedReadSize = expectedUncompressedSize;
        int64_t blockOffset = fi.offset + outputPosition;
        RINOK(inStream->Seek(blockOffset, STREAM_SEEK_SET, nullptr));
      }

      if (blockIsCompressed) {
        // Read and decompress
        std::vector<uint8_t> compressedBlock(compressedReadSize);
        UInt32 read = 0;
        RINOK(inStream->Read(compressedBlock.data(), (UInt32)compressedReadSize, &read));
        if (read != compressedReadSize) {
          return E_FAIL;
        }

        if (!ZlibDecode(compressedBlock.data(), compressedReadSize,
          &outputBuffer[outputPosition], expectedUncompressedSize)) {
          return E_FAIL;
        }

        if (i < 5 || i >= blockCount - 2) {
        }
      }
      else {
        // Read uncompressed
        UInt32 read = 0;
        RINOK(inStream->Read(&outputBuffer[outputPosition],
          (UInt32)compressedReadSize, &read));
        if (read != compressedReadSize) {
          return E_FAIL;
        }

        if (i < 5 || i >= blockCount - 2) {
        }
      }
    }

    // Write output
    UInt32 written = 0;
    RINOK(outStream->Write(outputBuffer.data(), (UInt32)fi.uncompressed_size, &written));
    if (written != fi.uncompressed_size) {
      return E_FAIL;
    }
    return S_OK;
  }

public:
  bool IsPS3() const { return pupType == PUP_TYPE_PS3; }
  bool IsPS4() const { return pupType == PUP_TYPE_PS4; }
  bool IsPS5() const { return pupType == PUP_TYPE_PS5; }

  const PS3_PUP_HEADER& GetPS3Header() const { return ps3Header; }
  const PS4_PUP_HEADER& GetPS4Header() const { return ps4Header; }
  const PS4_PUP_HEADER& GetPS5Header() const { return ps4Header; }
};