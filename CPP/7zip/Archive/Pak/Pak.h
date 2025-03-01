#include <vector>
#include <string>
#include <sstream>
#include <cstdint>
#include <locale>
#include <codecvt>
#include <map>
#include <iomanip>
#include <iostream>
#include "../../Bundles/Pak/Pak/zLib.h"



#include <windows.h>
#include <cassert>
#include <fstream>
#include <shlobj.h>

#define UE4_PAK_MAGIC 0x5a6f12e1

class PakFileHandler {
    UInt64 archiveSize;
    uint64_t overlayPos;
public:
   

    struct Block {
        uint64_t Start;
        uint64_t Size;

        Block(uint64_t start, uint64_t size) : Start(start), Size(size) {}
    };

    struct Record {
        std::string fileName;
        uint64_t offset;
        uint64_t fileSize;
        uint64_t sizeDecompressed;
        uint32_t compressionMethod;
        bool isEncrypted;
        std::vector<Block> compressionBlocks;
        std::vector<uint8_t> Data;
      

        void Read(IInStream* stream, uint32_t fileVersion, bool includesHeader, bool quickread = false) {
            HRESULT result;

            if (includesHeader) {
                uint32_t strLen;
                result = stream->Read(reinterpret_cast<BYTE*>(&strLen), sizeof(strLen), nullptr);
                if (FAILED(result)) {
                    HandleDebug(L"[!] Error: Failed to read filename length.");
                    return;
                }
                fileName.resize(strLen);

                result = stream->Read(reinterpret_cast<BYTE*>(&fileName[0]), strLen, nullptr);
                if (FAILED(result)) {
                    HandleDebug(L"[!] Error: Failed to read filename.");
                    return;
                }
            }

            result = stream->Read(reinterpret_cast<BYTE*>(&offset), sizeof(offset), nullptr);
            if (FAILED(result)) {
                HandleDebug(L"[!] Error: Failed to read offset.");
                return;
            }

            if (quickread) {
                result = stream->Seek(16, STREAM_SEEK_CUR, nullptr); // Skip 16 bytes
                if (FAILED(result)) {
                    HandleDebug(L"[!] Error: Failed to seek (quickread skip 16).");
                    return;
                }
            }
            else {
                result = stream->Read(reinterpret_cast<BYTE*>(&fileSize), sizeof(fileSize), nullptr);
                if (FAILED(result)) {
                    HandleDebug(L"[!] Error: Failed to read file size.");
                    return;
                }

                result = stream->Read(reinterpret_cast<BYTE*>(&sizeDecompressed), sizeof(sizeDecompressed), nullptr);
                if (FAILED(result)) {
                    HandleDebug(L"[!] Error: Failed to read decompressed size.");
                    return;
                }
            }

            result = stream->Read(reinterpret_cast<BYTE*>(&compressionMethod), sizeof(compressionMethod), nullptr);
            if (FAILED(result)) {
                HandleDebug(L"[!] Error: Failed to read compression method.");
                return;
            }

            if (fileVersion <= 1) {
                uint64_t timestamp;
                result = stream->Read(reinterpret_cast<BYTE*>(&timestamp), sizeof(timestamp), nullptr);
                if (FAILED(result)) {
                    HandleDebug(L"[!] Error: Failed to read timestamp.");
                    return;
                }
            }

            if (quickread) {
                result = stream->Seek(20, STREAM_SEEK_CUR, nullptr); // Skip 20 bytes
                if (FAILED(result)) {
                    HandleDebug(L"[!] Error: Failed to seek (quickread skip 20).");
                    return;
                }
            }
            else {
                char sha1hash[20];
                result = stream->Read(reinterpret_cast<BYTE*>(sha1hash), sizeof(sha1hash), nullptr);
                if (FAILED(result)) {
                    HandleDebug(L"[!] Error: Failed to read SHA-1 hash.");
                    return;
                }
            }

            if (fileVersion >= 3) {
                if (compressionMethod != 0) {
                    uint32_t blockCount;
                    result = stream->Read(reinterpret_cast<BYTE*>(&blockCount), sizeof(blockCount), nullptr);
                    if (FAILED(result)) {
                        HandleDebug(L"[!] Error: Failed to read block count.");
                        return;
                    }

                    if (quickread) {
                        result = stream->Seek(blockCount * 16, STREAM_SEEK_CUR, nullptr); // Skip block count * 16 bytes
                        if (FAILED(result)) {
                            HandleDebug(L"[!] Error: Failed to seek (quickread skip blocks).");
                            return;
                        }
                    }
                    else {
                        for (uint32_t i = 0; i < blockCount; ++i) {
                            uint64_t startOffset, endOffset;
                            result = stream->Read(reinterpret_cast<BYTE*>(&startOffset), sizeof(startOffset), nullptr);
                            if (FAILED(result)) {
                                HandleDebug(L"[!] Error: Failed to read block start offset.");
                                return;
                            }

                            result = stream->Read(reinterpret_cast<BYTE*>(&endOffset), sizeof(endOffset), nullptr);
                            if (FAILED(result)) {
                                HandleDebug(L"[!] Error: Failed to read block end offset.");
                                return;
                            }

                            compressionBlocks.emplace_back(startOffset, endOffset - startOffset);
                        }
                    }
                }

                if (quickread) {
                    result = stream->Seek(5, STREAM_SEEK_CUR, nullptr); // Skip 5 bytes
                    if (FAILED(result)) {
                        HandleDebug(L"[!] Error: Failed to seek (quickread skip 5).");
                        return;
                    }
                }
                else {
                    uint8_t isEncrypted;
                    result = stream->Read(reinterpret_cast<BYTE*>(&isEncrypted), sizeof(isEncrypted), nullptr);
                    if (FAILED(result)) {
                        HandleDebug(L"[!] Error: Failed to read encryption flag.");
                        return;
                    }
                    this->isEncrypted = isEncrypted > 0;

                    uint32_t compressionBlockSize;
                    result = stream->Read(reinterpret_cast<BYTE*>(&compressionBlockSize), sizeof(compressionBlockSize), nullptr);
                    if (FAILED(result)) {
                        HandleDebug(L"[!] Error: Failed to read compression block size.");
                        return;
                    }
                }
            }
        }
    };

    uint32_t fileVersion;
    uint64_t indexOffset;
    uint64_t indexSize;
    uint32_t recordCount;
    uint64_t seekStop = 0;
    uint32_t countStop = 0;
    std::string mountPoint;
    std::map<std::string, uint64_t> headers;


    std::vector<std::string> List(IInStream* stream, const std::string& recordName = "");
    HRESULT Open(IInStream* stream, const UInt64*, IArchiveOpenCallback* callback);
    CMyComPtr<IArchiveOpenVolumeCallback> volCallback;
    HRESULT Unpack(IInStream* stream, const std::string& recordName, bool decode = false);
    //HRESULT ParsePakFile(IInStream* stream, const std::string& recordName, std::vector<Record>& items);
    HRESULT zlib_decompress(uint8_t* in, size_t in_size, uint8_t* out, size_t out_size);
    static HRESULT HandleDebug(const std::wstring& message);
    HRESULT SafeRead(IInStream* stream, void* buffer, size_t size, UInt32* bytesRead);
  
    //HRESULT List(IInStream* stream, const std::string& recordName, std::vector<Record>& items);
    std::vector<Record> items;

};

HRESULT PakFileHandler::HandleDebug(const std::wstring& message) {
    MessageBox(NULL, message.c_str(), L"Debug", MB_OK);
    return S_OK; // Return S_OK to indicate success
}


HRESULT PakFileHandler::SafeRead(IInStream* stream, void* buffer, size_t size, UInt32* bytesRead) {
    HRESULT result = stream->Read(buffer, static_cast<UInt32>(size), bytesRead);
    if (result != S_OK || *bytesRead != size) {
        HandleDebug(L"Failed to read from stream");
        return S_FALSE;
    }
    return S_OK;
}



HRESULT PakFileHandler::Open(IInStream* stream, const UInt64*, IArchiveOpenCallback* callback) {
    if (!callback || !stream) {
        HandleDebug(L"[!] Error: Invalid input parameters - callback or stream is null.");
        return S_FALSE;
    }

    // Query interface for volume callback
    HRESULT result = callback->QueryInterface(IID_IArchiveOpenVolumeCallback, (void**)&volCallback);
    if (FAILED(result) || volCallback == nullptr) {
        HandleDebug(L"[!] Error: Failed to get volume callback interface.");
        return E_FAIL;
    }

    // Get the stream length
    UInt64 streamLength;
    result = stream->Seek(0, STREAM_SEEK_END, &streamLength);
    if (FAILED(result)) {
        HandleDebug(L"[!] Error: Failed to seek to end of stream.");
        return result;
    }

    if (streamLength < 44) {
        HandleDebug(L"[!] Error: File too small to be a valid PAK.");
        return E_FAIL;
    }

    // Seek to possible PAK magic number location (-44 bytes from end)
    result = stream->Seek(static_cast<Int64>(streamLength - 44), STREAM_SEEK_SET, nullptr);
    if (FAILED(result)) {
        HandleDebug(L"[!] Error: Failed to seek to magic number location.");
        return result;
    }

    // Read the magic number (4 bytes)
    UInt32 magicNumber;
    UInt32 bytesRead = 0;
    result = stream->Read(reinterpret_cast<BYTE*>(&magicNumber), sizeof(magicNumber), &bytesRead);
    if (FAILED(result) || bytesRead < sizeof(magicNumber)) {
        HandleDebug(L"[!] Error: Failed to read magic number.");
        return E_FAIL;
    }

    // Debug output
    std::wstringstream magicNumberStream;
    magicNumberStream << std::hex << magicNumber;
    HandleDebug(L"Magic number found at offset: " + std::to_wstring(streamLength - 44) + L" -> 0x" + magicNumberStream.str());
    uint32_t fileVersion = 0;
    // Validate magic number
    if (magicNumber == UE4_PAK_MAGIC) {
        HandleDebug(L"[+] Valid PAK magic number found, processing PAK file.");

        // Call List to fill the items vector with all records

        std::vector<std::string> result = PakFileHandler::List(stream, "");
        if (result.empty()) {
            HandleDebug(L"[!] Error: Failed to list records.");
            return E_FAIL;  // Or another appropriate HRESULT value to indicate failure
        }

        // Assuming ParsePakFile returns an HRESULT
        //HRESULT parseResult = ParsePakFile(stream, "", items);
        //if (FAILED(parseResult)) {
          //  HandleDebug(L"[!] Error: Failed to parse PAK file.");
            //return parseResult;  // Return the HRESULT from ParsePakFile
        //}

        return S_OK;  // Return success HRESULT
    }
    HandleDebug(L"[!] Error: Invalid magic number. Expected 0x5a6f12e1.");
    return E_FAIL;

}


// Assuming CompressionMethod maps compression method IDs to strings
const std::map<uint32_t, std::string> CompressionMethod = { {0, "NONE"}, {1, "ZLIB"}, {2, "BIAS_MEMORY"}, {3, "BIAS_SPEED"} };

UInt32 ConvertToUInt32CorrectByteOrder(UInt32 value) {
    return ((value >> 24) & 0x000000FF) |      // Move byte 3 to byte 0
        ((value >> 8) & 0x0000FF00) |      // Move byte 1 to byte 1
        ((value << 8) & 0x00FF0000) |      // Move byte 2 to byte 2
        ((value << 24) & 0xFF000000);       // Move byte 0 to byte 3
}




#include <Windows.h>
#include <sstream> // For stringstream to format the message

std::vector<std::string> PakFileHandler::List(IInStream* stream, const std::string& recordName) {
    UInt64 newPosition = 0;
    HRESULT hr;
    std::stringstream debugMessage;
    UInt32 bytesRead = 0;

    if (seekStop == 0) {
        // Read file version, index offset, and index size
        hr = stream->Read(reinterpret_cast<char*>(&fileVersion), sizeof(fileVersion), &bytesRead);
        if (FAILED(hr) || bytesRead != sizeof(fileVersion)) {
            throw std::runtime_error("Failed to read file version");
        }

        hr = stream->Read(reinterpret_cast<char*>(&indexOffset), sizeof(indexOffset), &bytesRead);
        if (FAILED(hr) || bytesRead != sizeof(indexOffset)) {
            throw std::runtime_error("Failed to read index offset");
        }

        hr = stream->Read(reinterpret_cast<char*>(&indexSize), sizeof(indexSize), &bytesRead);
        if (FAILED(hr) || bytesRead != sizeof(indexSize)) {
            throw std::runtime_error("Failed to read index size");
        }

        // Output index offset
        debugMessage << "PAK Index Offset: "
            << std::hex << indexOffset
            << std::dec << "\n";

        // Seek to the index offset and read the mount point and record count
        hr = stream->Seek(static_cast<Int64>(indexOffset), STREAM_SEEK_SET, &newPosition);
        if (FAILED(hr)) {
            throw std::runtime_error("Failed to seek to index offset");
        }

        uint32_t strLen;
        hr = stream->Read(reinterpret_cast<char*>(&strLen), sizeof(strLen), &bytesRead);
        if (FAILED(hr) || bytesRead != sizeof(strLen)) {
            throw std::runtime_error("Failed to read mount point length");
        }

        mountPoint.resize(strLen);
        hr = stream->Read(&mountPoint[0], strLen, &bytesRead);
        if (FAILED(hr) || bytesRead != strLen) {
            throw std::runtime_error("Failed to read mount point");
        }

        hr = stream->Read(reinterpret_cast<char*>(&recordCount), sizeof(recordCount), &bytesRead);
        if (FAILED(hr) || bytesRead != sizeof(recordCount)) {
            throw std::runtime_error("Failed to read record count");
        }

        debugMessage << "Record Count: " << recordCount << "\n";
    }
    else {
        hr = stream->Seek(static_cast<Int64>(seekStop), STREAM_SEEK_SET, &newPosition);
        if (FAILED(hr)) {
            throw std::runtime_error("Failed to seek to seekStop");
        }
    }

    // Collect all headers if not found
    if (headers.find(recordName) == headers.end()) {
        debugMessage << "Collecting headers...\n";
        for (uint32_t i = 0; i < (recordCount ? recordCount : countStop); ++i) {
            Record rec;
            rec.Read(stream, fileVersion, true, true);

            if (FAILED(hr)) {
                debugMessage << "Failed to read record at index " << i + 1 << "\n";
                continue;
            }

            headers[rec.fileName] = rec.offset;

            // Debug message for each record (only if _DEBUG is defined)
#ifdef _DEBUG
            debugMessage << "Header " << i + 1 << ": " << rec.fileName << "\n";
            // Show a message box for each item found (optional for debugging)
            std::wstring itemMessage = L"Item found: " + std::wstring(rec.fileName.begin(), rec.fileName.end());
            MessageBox(NULL, itemMessage.c_str(), L"Item Found", MB_OK);
#endif

            // Add record to items
            items.emplace_back(rec);
        }
    }

    // Collect all header file names
    std::vector<std::string> headerKeys;
    for (const auto& header : headers) {
        headerKeys.push_back(header.first);
    }

    // Optionally, you could print the list of file names here as well, but only if _DEBUG is enabled
#ifdef _DEBUG
    // Show debug information about collected headers (if necessary)
    for (const auto& header : headerKeys) {
        debugMessage << "Found Header: " << header << "\n";
    }
    // Optionally show the complete list in a message box or log
    MessageBox(NULL, debugMessage.str().c_str(), L"Debug Info", MB_OK);
#endif

    return headerKeys;
}




HRESULT PakFileHandler::Unpack(IInStream* stream, const std::string& recordName, bool decode) {    // Check if recordName exists in headers
    if (headers.find(recordName) == headers.end()) {
        List(stream,recordName);
    }
    if (headers.find(recordName) == headers.end()) {
        return E_INVALIDARG;  // Record not found even after listing
    }

    uint64_t offset = headers[recordName];
    UInt64 newPosition = 0;
    HRESULT hr = stream->Seek(static_cast<Int64>(offset), STREAM_SEEK_SET, &newPosition);
    if (FAILED(hr)) {
        return hr;
    }
    Record rec2;
    // Read the record
    rec2.Read(stream, fileVersion, false);

    if (CompressionMethod.at(rec2.compressionMethod) == "NONE") {
        rec2.Data.resize(rec2.fileSize);

        // Change from size_t to UInt32
        UInt32 bytesRead = 0;
        HRESULT hr = stream->Read(reinterpret_cast<char*>(rec2.Data.data()), static_cast<UInt32>(rec2.fileSize), &bytesRead);
        if (FAILED(hr) || bytesRead != rec2.fileSize) {
            return E_FAIL; // Handle incomplete read
        }

        if (decode) {
            std::string decoded(rec2.Data.begin(), rec2.Data.end());
            std::copy(decoded.begin(), decoded.end(), rec2.Data.begin());
        }
    }

    else if (CompressionMethod.at(rec2.compressionMethod) == "ZLIB") {
        std::vector<uint8_t> dataDecompressed;
        for (const auto& block : rec2.compressionBlocks) {
            uint64_t blockOffset = block.Start;
            if (fileVersion == 8) {
                blockOffset += offset;
            }
            uint64_t blockSize = block.Size;

            UInt64 blockNewPosition = 0;
            hr = stream->Seek(static_cast<Int64>(blockOffset), STREAM_SEEK_SET, &blockNewPosition);
            if (FAILED(hr)) {
                return hr;
            }

            std::vector<uint8_t> memstream(blockSize);

            // Change from size_t to UInt32
            UInt32 bytesRead = 0;
            hr = stream->Read(reinterpret_cast<char*>(memstream.data()), static_cast<UInt32>(blockSize), &bytesRead);
            if (FAILED(hr) || bytesRead != blockSize) {
                return E_FAIL; // Handle incomplete block read
            }


            std::vector<uint8_t> decompressedData(rec2.sizeDecompressed);
            zlib_decompress(memstream.data(), blockSize, decompressedData.data(), rec2.sizeDecompressed);
            dataDecompressed.insert(dataDecompressed.end(), decompressedData.begin(), decompressedData.end());
        }
        rec2.Data = std::move(dataDecompressed);

        if (decode) {
            std::string decoded(rec2.Data.begin(), rec2.Data.end());
            std::copy(decoded.begin(), decoded.end(), rec2.Data.begin());
        }
    }
    else {
        return E_NOTIMPL;  // Unimplemented compression method
    }

    rec2.fileName = recordName;
    return S_OK;
}


HRESULT PakFileHandler::zlib_decompress(uint8_t* in, size_t in_size, uint8_t* out, size_t out_size) {
    z_stream zs;
    memset(&zs, 0, sizeof(zs));

    // Initialize the zlib stream
    int ret = inflateInit(&zs);
    if (ret != Z_OK) {
        HandleDebug(L"[!] Error: Failed to initialize zlib inflate.");
        return E_FAIL; // Return failure HRESULT
    }

    zs.next_in = in;
    zs.avail_in = in_size;
    zs.next_out = out;
    zs.avail_out = out_size;

    // Inflate the data
    ret = inflate(&zs, Z_FINISH);
    if (ret != Z_STREAM_END) {
        inflateEnd(&zs);
        HandleDebug(L"[!] Error: Zlib inflate failed, code: " + std::to_wstring(ret));
        return E_FAIL; // Return failure HRESULT
    }

    // Finalize the stream
    ret = inflateEnd(&zs);
    if (ret != Z_OK) {
        HandleDebug(L"[!] Error: Failed to finalize zlib inflate.");
        return E_FAIL; // Return failure HRESULT
    }

    return S_OK; // Return success HRESULT
}







