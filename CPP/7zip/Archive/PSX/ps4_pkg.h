#pragma once
#include <windows.h>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <string>

// ---------------------------------------------------------------------
// PS4 PKG constants
// ---------------------------------------------------------------------
#define PKG_MAGIC_PS4 0x7F434E54  // PS4 PKG 

enum PS4_PKG_ENTRY_TYPES {
  PS4_PKG_ENTRY_TYPE_DIGEST_TABLE = 0x0001,
  PS4_PKG_ENTRY_TYPE_0x800 = 0x0010,
  PS4_PKG_ENTRY_TYPE_0x200 = 0x0020,
  PS4_PKG_ENTRY_TYPE_0x180 = 0x0080,
  PS4_PKG_ENTRY_TYPE_META_TABLE = 0x0100,
  PS4_PKG_ENTRY_TYPE_NAME_TABLE = 0x0200,
  PS4_PKG_ENTRY_TYPE_LICENSE = 0x0400,
  PS4_PKG_ENTRY_TYPE_FILE1 = 0x1000,
  PS4_PKG_ENTRY_TYPE_FILE2 = 0x1200
};

// ---------------------------------------------------------------------
// PS4 PKG header (packed)
// ---------------------------------------------------------------------
#pragma pack(push, 1)
struct PKG_HEADER_PS4 {
  uint32_t magic;                          // 0x00
  uint32_t type;                           // 0x04
  uint32_t unk_0x08;                       // 0x08
  uint32_t unk_0x0C;                       // 0x0C
  uint16_t unk1_entries_num;               // 0x10
  uint16_t table_entries_num;              // 0x12
  uint16_t system_entries_num;             // 0x14
  uint16_t unk2_entries_num;               // 0x16
  uint32_t file_table_offset;              // 0x18
  uint32_t main_entries_data_size;         // 0x1C
  uint32_t unk_0x20;                       // 0x20
  uint32_t body_offset;                    // 0x24
  uint32_t unk_0x28;                       // 0x28
  uint32_t body_size;                      // 0x2C
  uint8_t  unk_0x30[0x10];                 // 0x30
  uint8_t  content_id[0x30];               // 0x40
  uint32_t unk_0x70;                       // 0x70
  uint32_t unk_0x74;                       // 0x74
  uint32_t unk_0x78;                       // 0x78
  uint32_t unk_0x7C;                       // 0x7C
  uint32_t date;                           // 0x80
  uint32_t time;                           // 0x84
  uint32_t unk_0x88;                       // 0x88
  uint32_t unk_0x8C;                       // 0x8C
  uint8_t  unk_0x90[0x70];                 // 0x90
  uint8_t  main_entries1_digest[0x20];     // 0x100
  uint8_t  main_entries2_digest[0x20];     // 0x120
  uint8_t  digest_table_digest[0x20];      // 0x140
  uint8_t  body_digest[0x20];              // 0x160
};

struct PKG_CONTENT_HEADER_PS4 {
  uint32_t unk_0x400;                      // 0x400
  uint32_t unk_0x404;                      // 0x404
  uint32_t unk_0x408;                      // 0x408
  uint32_t unk_0x40C;                      // 0x40C
  uint32_t unk_0x410;                      // 0x410
  uint32_t content_offset;                 // 0x414
  uint32_t unk_0x418;                      // 0x418
  uint32_t content_size;                   // 0x41C
  uint32_t unk_0x420;                      // 0x420
  uint32_t unk_0x424;                      // 0x424
  uint32_t unk_0x428;                      // 0x428
  uint32_t unk_0x42C;                      // 0x42C
  uint32_t unk_0x430;                      // 0x430
  uint32_t unk_0x434;                      // 0x434
  uint32_t unk_0x438;                      // 0x438
  uint32_t unk_0x43C;                      // 0x43C
  uint8_t  content_digest[0x20];           // 0x440
  uint8_t  content_one_block_digest[0x20]; // 0x460
};

struct PKG_TABLE_ENTRY_PS4 {
  uint32_t type;
  uint32_t unk1;
  uint32_t flags1;
  uint32_t flags2;
  uint32_t offset;
  uint32_t size;
  uint32_t unk2;
  uint32_t unk3;
};
#pragma pack(pop)

// ---------------------------------------------------------------------
// PS4 PKG Handler Class
// ---------------------------------------------------------------------
class PS4PKGHandler {
private:
  PKG_HEADER_PS4 header = {};
  PKG_CONTENT_HEADER_PS4 contentHeader = {};

  uint32_t SwapEndian32(uint32_t v) { return _byteswap_ulong(v); }
  uint64_t SwapEndian64(uint64_t v) { return _byteswap_uint64(v); }
  uint16_t SwapEndian16(uint16_t v) { return _byteswap_ushort(v); }

  const char* GetEntryName(uint32_t type) {
    switch (type) {
    case 0x0001: return "digest_table.bin";
    case 0x0010: return "entry_keys.bin";
    case 0x0020: return "image_key.bin";
    case 0x0080: return "general_digests.bin";
    case 0x0100: return "metas.bin";
    case 0x0200: return "entry_names.bin";
    case 0x0400: return "license.dat";
    case 0x0401: return "license.info";
    case 0x1000: return "param.sfo";
    case 0x1001: return "playgo-chunk.dat";
    case 0x1002: return "playgo-chunk.sha";
    case 0x1003: return "playgo-manifest.xml";
    case 0x1004: return "pronunciation.xml";
    case 0x1005: return "pronunciation.sig";
    case 0x1006: return "pic1.png";
    case 0x1008: return "app/playgo-chunk.dat";
    case 0x1200: return "icon0.png";
    case 0x1220: return "pic0.png";
    case 0x1240: return "snd0.at9";
    case 0x1260: return "changeinfo/changeinfo.xml";
    default: return nullptr;
    }
  }

public:
  struct FileInfo {
    uint64_t  offset = 0;
    uint64_t  size = 0;
    uint32_t  flags = 0;
    uint32_t  type = 0;
    std::string path;
    std::vector<uint8_t> fileData;
    bool      isFolder = false;
    int64_t   fileTime1 = 0;
    int64_t   fileTime2 = 0;
    int64_t   fileTime3 = 0;
  };

  HRESULT ParseHeader(IInStream* stream) {
    RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));

    UInt32 read = 0;

    // Read main header (0x180 bytes)
    RINOK(stream->Read(&header.magic, 4, &read));
    header.magic = SwapEndian32(header.magic);
    if (header.magic != PKG_MAGIC_PS4) return E_FAIL;

    RINOK(stream->Read(&header.type, 4, &read));
    header.type = SwapEndian32(header.type);

    RINOK(stream->Read(&header.unk_0x08, 4, &read));
    header.unk_0x08 = SwapEndian32(header.unk_0x08);

    RINOK(stream->Read(&header.unk_0x0C, 4, &read));
    header.unk_0x0C = SwapEndian32(header.unk_0x0C);

    RINOK(stream->Read(&header.unk1_entries_num, 2, &read));
    header.unk1_entries_num = SwapEndian16(header.unk1_entries_num);

    RINOK(stream->Read(&header.table_entries_num, 2, &read));
    header.table_entries_num = SwapEndian16(header.table_entries_num);

    RINOK(stream->Read(&header.system_entries_num, 2, &read));
    header.system_entries_num = SwapEndian16(header.system_entries_num);

    RINOK(stream->Read(&header.unk2_entries_num, 2, &read));
    header.unk2_entries_num = SwapEndian16(header.unk2_entries_num);

    RINOK(stream->Read(&header.file_table_offset, 4, &read));
    header.file_table_offset = SwapEndian32(header.file_table_offset);

    RINOK(stream->Read(&header.main_entries_data_size, 4, &read));
    header.main_entries_data_size = SwapEndian32(header.main_entries_data_size);

    RINOK(stream->Read(&header.unk_0x20, 4, &read));
    header.unk_0x20 = SwapEndian32(header.unk_0x20);

    RINOK(stream->Read(&header.body_offset, 4, &read));
    header.body_offset = SwapEndian32(header.body_offset);

    RINOK(stream->Read(&header.unk_0x28, 4, &read));
    header.unk_0x28 = SwapEndian32(header.unk_0x28);

    RINOK(stream->Read(&header.body_size, 4, &read));
    header.body_size = SwapEndian32(header.body_size);

    RINOK(stream->Read(header.unk_0x30, 0x10, nullptr));
    RINOK(stream->Read(header.content_id, 0x30, nullptr));
    header.content_id[0x2F] = '\0';

    RINOK(stream->Read(&header.unk_0x70, 4, &read));
    header.unk_0x70 = SwapEndian32(header.unk_0x70);

    RINOK(stream->Read(&header.unk_0x74, 4, &read));
    header.unk_0x74 = SwapEndian32(header.unk_0x74);

    RINOK(stream->Read(&header.unk_0x78, 4, &read));
    header.unk_0x78 = SwapEndian32(header.unk_0x78);

    RINOK(stream->Read(&header.unk_0x7C, 4, &read));
    header.unk_0x7C = SwapEndian32(header.unk_0x7C);

    RINOK(stream->Read(&header.date, 4, &read));
    header.date = SwapEndian32(header.date);

    RINOK(stream->Read(&header.time, 4, &read));
    header.time = SwapEndian32(header.time);

    RINOK(stream->Read(&header.unk_0x88, 4, &read));
    header.unk_0x88 = SwapEndian32(header.unk_0x88);

    RINOK(stream->Read(&header.unk_0x8C, 4, &read));
    header.unk_0x8C = SwapEndian32(header.unk_0x8C);

    RINOK(stream->Read(header.unk_0x90, 0x70, nullptr));
    RINOK(stream->Read(header.main_entries1_digest, 0x20, nullptr));
    RINOK(stream->Read(header.main_entries2_digest, 0x20, nullptr));
    RINOK(stream->Read(header.digest_table_digest, 0x20, nullptr));
    RINOK(stream->Read(header.body_digest, 0x20, nullptr));

    // Read content header at 0x400
    RINOK(stream->Seek(0x400, STREAM_SEEK_SET, nullptr));

    RINOK(stream->Read(&contentHeader.unk_0x400, 4, &read));
    contentHeader.unk_0x400 = SwapEndian32(contentHeader.unk_0x400);

    RINOK(stream->Read(&contentHeader.unk_0x404, 4, &read));
    contentHeader.unk_0x404 = SwapEndian32(contentHeader.unk_0x404);

    RINOK(stream->Read(&contentHeader.unk_0x408, 4, &read));
    contentHeader.unk_0x408 = SwapEndian32(contentHeader.unk_0x408);

    RINOK(stream->Read(&contentHeader.unk_0x40C, 4, &read));
    contentHeader.unk_0x40C = SwapEndian32(contentHeader.unk_0x40C);

    RINOK(stream->Read(&contentHeader.unk_0x410, 4, &read));
    contentHeader.unk_0x410 = SwapEndian32(contentHeader.unk_0x410);

    RINOK(stream->Read(&contentHeader.content_offset, 4, &read));
    contentHeader.content_offset = SwapEndian32(contentHeader.content_offset);

    RINOK(stream->Read(&contentHeader.unk_0x418, 4, &read));
    contentHeader.unk_0x418 = SwapEndian32(contentHeader.unk_0x418);

    RINOK(stream->Read(&contentHeader.content_size, 4, &read));
    contentHeader.content_size = SwapEndian32(contentHeader.content_size);

    RINOK(stream->Seek(0x440, STREAM_SEEK_SET, nullptr));
    RINOK(stream->Read(contentHeader.content_digest, 0x20, nullptr));
    RINOK(stream->Read(contentHeader.content_one_block_digest, 0x20, nullptr));

    return S_OK;
  }

  HRESULT ParseFileTable(IInStream* stream, std::vector<FileInfo>& items) {
    // Read table entries
    RINOK(stream->Seek(header.file_table_offset, STREAM_SEEK_SET, nullptr));

    std::vector<PKG_TABLE_ENTRY_PS4> entries(header.table_entries_num);
    std::vector<std::string> nameTable;

    // Read all entries
    for (uint16_t i = 0; i < header.table_entries_num; i++) {
      UInt32 read = 0;
      RINOK(stream->Read(&entries[i].type, 4, &read));
      entries[i].type = SwapEndian32(entries[i].type);

      RINOK(stream->Read(&entries[i].unk1, 4, &read));
      entries[i].unk1 = SwapEndian32(entries[i].unk1);

      RINOK(stream->Read(&entries[i].flags1, 4, &read));
      entries[i].flags1 = SwapEndian32(entries[i].flags1);

      RINOK(stream->Read(&entries[i].flags2, 4, &read));
      entries[i].flags2 = SwapEndian32(entries[i].flags2);

      RINOK(stream->Read(&entries[i].offset, 4, &read));
      entries[i].offset = SwapEndian32(entries[i].offset);

      RINOK(stream->Read(&entries[i].size, 4, &read));
      entries[i].size = SwapEndian32(entries[i].size);

      RINOK(stream->Read(&entries[i].unk2, 4, &read));
      entries[i].unk2 = SwapEndian32(entries[i].unk2);

      RINOK(stream->Read(&entries[i].unk3, 4, &read));
      entries[i].unk3 = SwapEndian32(entries[i].unk3);
    }

    // Find and parse name table
    for (uint16_t i = 0; i < header.table_entries_num; i++) {
      if (entries[i].type == PS4_PKG_ENTRY_TYPE_NAME_TABLE) {
        RINOK(stream->Seek(entries[i].offset + 1, STREAM_SEEK_SET, nullptr));

        std::vector<uint8_t> nameData(entries[i].size);
        UInt32 read = 0;
        RINOK(stream->Read(nameData.data(), entries[i].size, &read));

        // Parse null-terminated strings
        size_t pos = 0;
        while (pos < nameData.size()) {
          const char* str = reinterpret_cast<const char*>(nameData.data() + pos);
          size_t len = strnlen(str, nameData.size() - pos);
          if (len == 0) break;
          nameTable.push_back(std::string(str, len));
          pos += len + 1;
        }
        break;
      }
    }

    // Create file entries
    int fileIndex = 0;
    int unknownCount = 0;

    for (uint16_t i = 0; i < header.table_entries_num; i++) {
      FileInfo fi;
      fi.offset = entries[i].offset;
      fi.size = entries[i].size;
      fi.type = entries[i].type;
      fi.flags = entries[i].flags1;
      fi.isFolder = false;

      // Check if this is a file entry
      bool isFile = ((entries[i].type & PS4_PKG_ENTRY_TYPE_FILE1) == PS4_PKG_ENTRY_TYPE_FILE1) ||
        ((entries[i].type & PS4_PKG_ENTRY_TYPE_FILE2) == PS4_PKG_ENTRY_TYPE_FILE2);

      // Get name
      const char* predefinedName = GetEntryName(entries[i].type);
      if (predefinedName != nullptr) {
        fi.path = predefinedName;
      }
      else if (isFile && fileIndex < nameTable.size()) {
        fi.path = nameTable[fileIndex];
      }
      else {
        fi.path = "unknown_entry_0x" + std::to_string(entries[i].type) + "_" +
          std::to_string(unknownCount++) + ".bin";
      }

      if (isFile) fileIndex++;

      // Normalize path
      std::replace(fi.path.begin(), fi.path.end(), '\\', '/');

      items.push_back(std::move(fi));
    }

    return S_OK;
  }

  HRESULT ExtractFileData(IInStream* stream, FileInfo& fi) {
    if (fi.isFolder || fi.size == 0) return S_OK;

    fi.fileData.resize(fi.size);
    UInt32 read = 0;
    RINOK(stream->Seek(fi.offset, STREAM_SEEK_SET, nullptr));
    RINOK(stream->Read(fi.fileData.data(), static_cast<UInt32>(fi.size), &read));
    if (read != fi.size) return E_FAIL;

    return S_OK;
  }

  const PKG_HEADER_PS4& GetHeader() const { return header; }
  const PKG_CONTENT_HEADER_PS4& GetContentHeader() const { return contentHeader; }
};