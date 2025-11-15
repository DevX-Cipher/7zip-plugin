#pragma once
#include <windows.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <algorithm>

#pragma pack(push, 1)

typedef struct {
  uint8_t jump_boot[3];
  uint8_t fs_name[8];
  uint8_t must_be_zero[53];
  uint64_t partition_offset;
  uint64_t volume_length;
  uint32_t fat_offset;
  uint32_t fat_length;
  uint32_t cluster_heap_offset;
  uint32_t cluster_count;
  uint32_t first_cluster_of_root;
  uint32_t volume_serial_number;
  uint16_t fs_revision;
  uint16_t volume_flags;
  uint8_t bytes_per_sector_shift;
  uint8_t sectors_per_cluster_shift;
  uint8_t number_of_fats;
  uint8_t drive_select;
  uint8_t percent_in_use;
  uint8_t reserved[7];
  uint8_t boot_code[390];
  uint16_t boot_signature;
} ExtFATBootSector;

typedef struct {
  uint8_t entry_type;
  uint8_t data[31];
} ExtFATDirEntry;

typedef struct {
  uint8_t entry_type;
  uint8_t secondary_count;
  uint16_t set_checksum;
  uint16_t file_attributes;
  uint16_t reserved1;
  uint32_t create_timestamp;
  uint32_t modify_timestamp;
  uint32_t access_timestamp;
  uint8_t create_10ms_increment;
  uint8_t modify_10ms_increment;
  uint8_t create_utc_offset;
  uint8_t modify_utc_offset;
  uint8_t access_utc_offset;
  uint8_t reserved2[7];
} ExtFATFileEntry;

typedef struct {
  uint8_t entry_type;
  uint8_t flags;
  uint8_t reserved1;
  uint8_t name_length;
  uint16_t name_hash;
  uint16_t reserved2;
  uint64_t valid_data_length;
  uint32_t reserved3;
  uint32_t first_cluster;
  uint64_t data_length;
} ExtFATStreamExtension;

typedef struct {
  uint8_t entry_type;
  uint8_t flags;
  uint16_t name_chars[15];
} ExtFATFileNameEntry;

#pragma pack(pop)

// ExtFAT Magic
#define EXFAT_MAGIC 0x54414658

// Forward declaration for IInStream/ISequentialOutStream
struct IInStream;
struct ISequentialOutStream;

// ExtFAT Handler Class
class ExtFATHandler {
private:
  IInStream* stream;
  ExtFATBootSector boot;
  uint32_t bytes_per_sector;
  uint32_t sectors_per_cluster;
  uint32_t bytes_per_cluster;
  uint64_t fat_start;
  uint64_t cluster_heap_start;
  uint64_t volume_size;
  uint64_t base_offset;
  bool initialized;

public:
  struct ExtFATFileInfo {
    std::string name;
    uint64_t size;
    uint64_t valid_size;
    uint32_t first_cluster;
    uint16_t attributes;
    bool is_directory;
    uint32_t create_time;
    uint32_t modify_time;
    uint32_t access_time;
  };

  ExtFATHandler() : stream(nullptr), initialized(false), volume_size(0), base_offset(0) {
    memset(&boot, 0, sizeof(boot));
    bytes_per_sector = 0;
    sectors_per_cluster = 0;
    bytes_per_cluster = 0;
    fat_start = 0;
    cluster_heap_start = 0;
  }

  // Initialize from IInStream (for integration with PUP handler)
  HRESULT Initialize(IInStream* inStream, uint64_t offset = 0, uint64_t size = 0);

  bool IsInitialized() const { return initialized; }

  // Get cluster offset
  uint64_t ClusterToOffset(uint32_t cluster) {
    if (cluster < 2) return 0;
    return cluster_heap_start + ((uint64_t)(cluster - 2) * bytes_per_cluster);
  }

  // Read FAT entry
  HRESULT ReadFAT(uint32_t cluster, uint32_t& next_cluster);

  // Read cluster data
  HRESULT ReadCluster(uint32_t cluster, uint8_t* buffer, uint32_t bufferSize);

  // Parse directory and list files
  HRESULT ParseDirectory(uint32_t dir_cluster, std::vector<ExtFATFileInfo>& files);

  // Read file data by following cluster chain
  HRESULT ReadFileData(uint32_t first_cluster, uint64_t file_size, ISequentialOutStream* outStream);

  // Get root directory cluster
  uint32_t GetRootCluster() const {
    return boot.first_cluster_of_root;
  }

  // Get volume info
  uint32_t GetBytesPerSector() const { return bytes_per_sector; }
  uint32_t GetBytesPerCluster() const { return bytes_per_cluster; }
  uint32_t GetClusterCount() const { return boot.cluster_count; }
};

// Helper function to detect if a stream contains ExtFAT filesystem
inline bool IsExtFATFilesystem(IInStream* stream, uint64_t offset = 0) {
  uint8_t bootSector[512];

  if (FAILED(stream->Seek(offset, STREAM_SEEK_SET, nullptr))) {
    return false;
  }

  UInt32 bytesRead = 0;
  if (FAILED(stream->Read(bootSector, 512, &bytesRead)) || bytesRead != 512) {
    return false;
  }

  // Check for "EXFAT   " signature at offset 0x03
  if (memcmp(&bootSector[3], "EXFAT   ", 8) == 0) {
    // Verify boot signature
    uint16_t bootSig = bootSector[510] | (bootSector[511] << 8);
    if (bootSig == 0xAA55) {
      return true;
    }
  }

  return false;
}

HRESULT ExtFATHandler::Initialize(IInStream* inStream, uint64_t offset, uint64_t size) {
  stream = inStream;
  volume_size = size;
  base_offset = offset;

  // Seek to the boot sector
  RINOK(stream->Seek(offset, STREAM_SEEK_SET, nullptr));

  // Read boot sector
  UInt32 bytesRead = 0;
  RINOK(stream->Read(&boot, sizeof(ExtFATBootSector), &bytesRead));
  if (bytesRead != sizeof(ExtFATBootSector)) {
    logDebug(L"Failed to read ExtFAT boot sector");
    return E_FAIL;
  }

  // Verify ExtFAT signature
  if (memcmp(boot.fs_name, "EXFAT   ", 8) != 0) {
    logDebug(L"Not a valid ExtFAT filesystem");
    return E_FAIL;
  }

  if (boot.boot_signature != 0xAA55) {
    logDebug(L"Invalid boot signature");
    return E_FAIL;
  }

  // Calculate cluster parameters
  bytes_per_sector = 1 << boot.bytes_per_sector_shift;
  sectors_per_cluster = 1 << boot.sectors_per_cluster_shift;
  bytes_per_cluster = bytes_per_sector * sectors_per_cluster;

  fat_start = base_offset + (boot.fat_offset * bytes_per_sector);
  cluster_heap_start = base_offset + (boot.cluster_heap_offset * bytes_per_sector);

  initialized = true;

  logDebug(L"ExtFAT volume initialized:");
  logDebug(L"  Bytes per sector: %u", bytes_per_sector);
  logDebug(L"  Sectors per cluster: %u", sectors_per_cluster);
  logDebug(L"  Bytes per cluster: %u", bytes_per_cluster);
  logDebug(L"  Root cluster: %u", boot.first_cluster_of_root);
  logDebug(L"  Total clusters: %u", boot.cluster_count);

  return S_OK;
}

HRESULT ExtFATHandler::ReadFAT(uint32_t cluster, uint32_t& next_cluster) {
  uint64_t offset = fat_start + (cluster * 4);

  RINOK(stream->Seek(offset, STREAM_SEEK_SET, nullptr));

  UInt32 bytesRead = 0;
  RINOK(stream->Read(&next_cluster, 4, &bytesRead));
  if (bytesRead != 4) return E_FAIL;

  return S_OK;
}

HRESULT ExtFATHandler::ReadCluster(uint32_t cluster, uint8_t* buffer, uint32_t bufferSize) {
  if (bufferSize < bytes_per_cluster) return E_INVALIDARG;

  uint64_t offset = ClusterToOffset(cluster);
  RINOK(stream->Seek(offset, STREAM_SEEK_SET, nullptr));

  UInt32 bytesRead = 0;
  RINOK(stream->Read(buffer, bytes_per_cluster, &bytesRead));
  if (bytesRead != bytes_per_cluster) return E_FAIL;

  return S_OK;
}

HRESULT ExtFATHandler::ParseDirectory(uint32_t dir_cluster, std::vector<ExtFATFileInfo>& files) {
  if (!initialized) return E_FAIL;

  std::vector<uint8_t> cluster_buf(bytes_per_cluster);
  uint32_t cluster = dir_cluster;

  while (cluster >= 2 && cluster < 0xFFFFFFF7) {
    if (FAILED(ReadCluster(cluster, cluster_buf.data(), bytes_per_cluster))) {
      break;
    }

    for (uint32_t i = 0; i < bytes_per_cluster; i += 32) {
      ExtFATDirEntry* entry = (ExtFATDirEntry*)(cluster_buf.data() + i);

      if (entry->entry_type == 0x00) {
        return S_OK; // End of directory
      }

      if (entry->entry_type == 0x85) { // File entry
        ExtFATFileEntry* file = (ExtFATFileEntry*)entry;

        // Check if we have enough space for secondary entries
        if (i + 64 >= bytes_per_cluster) {
          i += file->secondary_count * 32;
          continue;
        }

        ExtFATStreamExtension* stream_ext = (ExtFATStreamExtension*)(cluster_buf.data() + i + 32);

        if (stream_ext->entry_type != 0xC0) {
          i += file->secondary_count * 32;
          continue;
        }

        // Build filename from name entries
        std::wstring filename_wide;
        for (uint8_t j = 0; j < file->secondary_count - 1 && j < 17; j++) {
          if (i + 64 + (j * 32) >= bytes_per_cluster) break;

          ExtFATFileNameEntry* name_entry =
            (ExtFATFileNameEntry*)(cluster_buf.data() + i + 64 + (j * 32));

          if (name_entry->entry_type == 0xC1) {
            for (int k = 0; k < 15; k++) {
              if (name_entry->name_chars[k] == 0) break;
              filename_wide += (wchar_t)name_entry->name_chars[k];
            }
          }
        }

        // Convert to narrow string
        std::string filename;
        for (wchar_t wc : filename_wide) {
          if (wc < 128) {
            filename += (char)wc;
          }
          else {
            filename += '?'; // Non-ASCII character
          }
        }

        // Create file info
        ExtFATFileInfo info;
        info.name = filename;
        info.size = stream_ext->data_length;
        info.valid_size = stream_ext->valid_data_length;
        info.first_cluster = stream_ext->first_cluster;
        info.attributes = file->file_attributes;
        info.is_directory = (file->file_attributes & 0x10) != 0;
        info.create_time = file->create_timestamp;
        info.modify_time = file->modify_timestamp;
        info.access_time = file->access_timestamp;

        files.push_back(info);

        i += file->secondary_count * 32;
      }
    }

    // Get next cluster
    uint32_t next;
    if (FAILED(ReadFAT(cluster, next))) break;
    cluster = next;
  }

  return S_OK;
}

HRESULT ExtFATHandler::ReadFileData(uint32_t first_cluster, uint64_t file_size, ISequentialOutStream* outStream) {
  if (!initialized) return E_FAIL;
  if (file_size == 0) return S_OK;

  std::vector<uint8_t> cluster_buf(bytes_per_cluster);
  uint64_t bytes_written = 0;
  uint32_t cluster = first_cluster;

  while (cluster >= 2 && cluster < 0xFFFFFFF7 && bytes_written < file_size) {
    // Read cluster
    if (FAILED(ReadCluster(cluster, cluster_buf.data(), bytes_per_cluster))) {
      return E_FAIL;
    }

    // Calculate how much to write from this cluster
    uint64_t to_write = (file_size - bytes_written < bytes_per_cluster)
      ? (file_size - bytes_written) : bytes_per_cluster;

    // Write to output stream
    UInt32 written = 0;
    RINOK(outStream->Write(cluster_buf.data(), (UInt32)to_write, &written));
    if (written != to_write) return E_FAIL;

    bytes_written += written;

    // Get next cluster
    uint32_t next;
    if (FAILED(ReadFAT(cluster, next))) break;
    cluster = next;
  }

  return S_OK;
}