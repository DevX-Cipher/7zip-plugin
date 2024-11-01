#include <vector>
#include <string>
#include <sstream>
#include <cstdint>
#include <locale>
#include <codecvt>
#include <map>
#include <iomanip>
#include <iostream>
#include "../../Bundles/PyInstaller/PyInstaller/zLib.h"


#ifdef _DEBUG
#include <windows.h>
#endif

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
            compressionFlag(compressionFlag), compressionType(compressionType), name(name) {}


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


HRESULT PyInstallerHandler::Open(IInStream* stream, const UInt64*, IArchiveOpenCallback* callback) {
    if (!callback || !stream) {
        return S_FALSE; // Early return if inputs are invalid
    }

    // Query interface for volume callback
    HRESULT result = callback->QueryInterface(IID_IArchiveOpenVolumeCallback, (void**)&volCallback);
    RINOK(result); // Use your error handling macro

    if (volCallback == nullptr) {
        HandleError(L"Failed to get volume callback interface.");
        return E_FAIL; // Return error if callback is unavailable
    }

    // Initialize and validate the file size
    UInt64 fileSize;
    RINOK(stream->Seek(0, STREAM_SEEK_END, &fileSize));

    const size_t searchChunkSize = 8192; // Define the chunk size for reading
    uint64_t endPos = fileSize;
    cookiePos = -1; // Initialize cookie position

    // Search for the magic number in reverse order
    while (true) {
        uint64_t startPos = endPos >= searchChunkSize ? endPos - searchChunkSize : 0;
        size_t chunkSize = endPos - startPos;
        if (chunkSize < MAGIC.size()) {
            break; // Exit if the chunk is too small
        }

        RINOK(stream->Seek(startPos, STREAM_SEEK_SET, nullptr));
        std::vector<char> data(chunkSize);
        UInt32 bytesRead = 0;
        RINOK(stream->Read(data.data(), static_cast<UInt32>(chunkSize), &bytesRead));

        if (bytesRead != chunkSize) {
            HandleError(L"Failed to read the stream correctly");
            return S_FALSE; // Return error if reading fails
        }

        // Search for the magic number
        auto offs = std::string(data.data(), chunkSize).rfind(MAGIC);
        if (offs != std::string::npos) {
            cookiePos = startPos + offs; // Update cookie position
            break; // Exit the loop on finding the magic number
        }

        endPos = startPos + MAGIC.size() - 1; // Adjust end position
        if (startPos == 0) {
            break; // Exit if at the beginning
        }
    }

    // Validate cookie position
    if (cookiePos == -1) {
        HandleError(L"[!] Error: Missing cookie, unsupported PyInstaller version or not a PyInstaller archive");
        return S_FALSE; // Return if no cookie found
    }

    // Read version information
    RINOK(stream->Seek(cookiePos + 8, STREAM_SEEK_SET, nullptr));
    char versionBuffer[64];
    UInt32 bytesRead = 0;
    RINOK(stream->Read(versionBuffer, sizeof(versionBuffer), &bytesRead));

    if (bytesRead < sizeof(uint32_t)) {
        HandleError(L"Insufficient data read for the PyInstaller version");
        return S_FALSE; // Return if not enough data is read
    }

    // Determine PyInstaller version based on header contents
    uint32_t pyinstVer = (std::string(versionBuffer, 64).find("python") != std::string::npos) ? 21 : 20;

    // Read the main buffer for package information
    RINOK(stream->Seek(cookiePos, STREAM_SEEK_SET, nullptr));
    const size_t bufferSize = (pyinstVer == 20) ? 32 : 88; // Adjust based on version
    std::vector<char> buffer(bufferSize);
    RINOK(stream->Read(buffer.data(), bufferSize, &bytesRead));

    if (bytesRead != bufferSize) {
        HandleError((pyinstVer == 20) ? L"Failed to read the PyInstaller 2.0 buffer" : L"Failed to read the PyInstaller 2.1 buffer");
        return S_FALSE; // Return if buffer read fails
    }

    // Extract necessary fields from the buffer
    memcpy(&lengthofPackage, buffer.data() + 8, 4);
    memcpy(&toc, buffer.data() + 12, 4);
    memcpy(&tocLen, buffer.data() + 16, 4);
    memcpy(&pyver, buffer.data() + 20, 4);
    lengthofPackage = ByteSwap(lengthofPackage);
    toc = ByteSwap(toc);
    tocLen = ByteSwap(tocLen);
    pyver = ByteSwap(pyver);

    // Validate TOC and length values
    if (tocLen > fileSize || toc < 0 || lengthofPackage < 0) {
        HandleError(L"[!] Error: Invalid TOC or length values detected.");
        return S_FALSE; // Return if invalid values are found
    }

    // Calculate overlay and TOC positions
    uint64_t tailBytes = fileSize - cookiePos - bufferSize;
    uint64_t overlaySize = static_cast<uint64_t>(lengthofPackage) + tailBytes;
    overlayPos = fileSize - overlaySize; // Store in member variable
    tableOfContentsPos = overlayPos + toc;
    tableOfContentsSize = tocLen;

    // Set total for callback
    RINOK(callback->SetTotal(nullptr, &tableOfContentsSize));

    // Parse the archive for entries
    HRESULT parseResult = ParseArchive(stream, fileSize);
    RINOK(parseResult);

    // Read data using metadata
    HRESULT readDataResult = ReadData(stream);
    RINOK(readDataResult);

    // Finalize archive size
    archiveSize = tableOfContentsSize + lengthofPackage;

    return S_OK; // Indicate success
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
            HandleError(L"[!] Error: Failed to read entry size");
            return S_FALSE;
        }
        entrySize = ByteSwap(entrySize);

        if (entrySize > (tableOfContentsSize - parsedLen)) {
            HandleError(L"[!] Error: Entry size exceeds remaining TOC size");
            return S_FALSE;
        }

        uint32_t nameLen = sizeof(uint32_t) + sizeof(uint32_t) * 3 + sizeof(uint8_t) + sizeof(char);
        std::vector<char> nameBuffer(entrySize - nameLen);
        uint32_t entryPos, compressedSize, uncompressedSize;
        uint8_t compressionFlag;
        char compressionType;

        result = SafeRead(stream, &entryPos, sizeof(entryPos), &bytesRead);
        if (result != S_OK || bytesRead != sizeof(entryPos)) {
            HandleError(L"[!] Error: Failed to read entry position");
            return S_FALSE;
        }
        entryPos = ByteSwap(entryPos);

        result = SafeRead(stream, &compressedSize, sizeof(compressedSize), &bytesRead);
        if (result != S_OK || bytesRead != sizeof(compressedSize)) {
            HandleError(L"[!] Error: Failed to read compressed size");
            return S_FALSE;
        }
        compressedSize = ByteSwap(compressedSize);

        result = SafeRead(stream, &uncompressedSize, sizeof(uncompressedSize), &bytesRead);
        if (result != S_OK || bytesRead != sizeof(uncompressedSize)) {
            HandleError(L"[!] Error: Failed to read uncompressed size");
            return S_FALSE;
        }
        uncompressedSize = ByteSwap(uncompressedSize);

        result = SafeRead(stream, &compressionFlag, sizeof(compressionFlag), &bytesRead);
        if (result != S_OK || bytesRead != sizeof(compressionFlag)) {
            HandleError(L"[!] Error: Failed to read compression flag");
            return S_FALSE;
        }

        result = SafeRead(stream, &compressionType, sizeof(compressionType), &bytesRead);
        if (result != S_OK || bytesRead != sizeof(compressionType)) {
            HandleError(L"[!] Error: Failed to read compression type");
            return S_FALSE;
        }

        result = SafeRead(stream, nameBuffer.data(), nameBuffer.size(), &bytesRead);
        if (result != S_OK || bytesRead != nameBuffer.size()) {
            HandleError(L"[!] Error: Failed to read name buffer");
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
            std::wstring w_utf8Name = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(utf8Name);
            std::wcerr << L"[!] Warning: File name " << w_utf8Name << L" contains invalid bytes. Using random name " << newName << std::endl;
            name = newName;
        }

        // Remove leading slash if present
        if (name.front() == L'/') name.erase(0, 1);
        if (name.empty()) name = L"random_" + std::to_wstring(rand());
        if (compressionType == 's' || compressionType == 'M' || compressionType == 'm') name += L".pyc";

        // Calculate actual file offset
        UInt64 actualOffset = overlayPos + entryPos;

        // Debugging: Show extracted metadata
        std::wstringstream entryMsg;
        entryMsg << L"[Debug] Parsed entry metadata:"
            << L"\nEntry Position (relative): " << entryPos
            << L"\nActual Offset (in archive): " << actualOffset
            << L"\nCompressed Size: " << compressedSize
            << L"\nUncompressed Size: " << uncompressedSize
            << L"\nCompression Flag: " << (int)compressionFlag
            << L"\nCompression Type: " << compressionType
            << L"\nFile Name: " << name;
#ifdef _DEBUG
        MessageBox(NULL, entryMsg.str().c_str(), L"Debug Info", MB_OK);
#endif
        // Create and store the archive entry
        ArchiveEntry item(entryPos, compressedSize, uncompressedSize, compressionFlag, std::string(1, compressionType), std::string(name.begin(), name.end()));
        items.emplace_back(item);
        parsedLen += entrySize;
    }

    if (parsedLen != tableOfContentsSize) {
        HandleError(L"[!] Error: Parsed length does not match TOC size");
        return S_FALSE;
    }

    std::wstringstream resultMsg;
    resultMsg << L"[+] Found " << items.size() << L" files in CArchive";
   

    // Call ReadData to decompress the data after parsing
    result = ReadData(stream);
    if (result != S_OK) {
        return result; // Return any error from ReadData
    }

    return S_OK;
}


HRESULT PyInstallerHandler::ReadData(IInStream* stream) {
    if (items.empty()) {
        HandleError(L"[!] Error: No metadata available. ParseArchive must be called first.");
        return S_FALSE;
    }

    for (auto& item : items) {
        if (item.compressedSize == 0) continue;  // Skip if there's no compressed data

        uint64_t actualOffset = overlayPos + item.entryPos;
        HRESULT result = stream->Seek(actualOffset, STREAM_SEEK_SET, nullptr);
        if (result != S_OK) {
            HandleError(L"[!] Error: Failed to seek to actual offset");
            return S_FALSE;
        }

        item.data.resize(item.compressedSize);
        UInt32 bytesRead = 0;
        result = SafeRead(stream, item.data.data(), item.compressedSize, &bytesRead);
        if (result != S_OK || bytesRead != item.compressedSize) {
            HandleError(L"[!] Error: Failed to read file data");
            return S_FALSE;
        }

        bool zlibFound = false;
        size_t zlibHeaderIndex = 0;
        for (; zlibHeaderIndex < item.data.size() - 1; ++zlibHeaderIndex) {
            if (item.data[zlibHeaderIndex] == 0x78) {  // 0x78 is typical for zlib headers
                zlibFound = true;
                break;
            }
        }

        if (zlibFound) {
            std::vector<uint8_t> actualCompressedData(item.data.begin() + zlibHeaderIndex, item.data.end());
            item.decompressedData.resize(item.uncompressedSize);

            // Use zlib to decompress data
            z_stream strm = { 0 };
            strm.next_in = actualCompressedData.data();
            strm.avail_in = actualCompressedData.size();
            strm.next_out = item.decompressedData.data();
            strm.avail_out = item.decompressedData.size();

            if (inflateInit(&strm) != Z_OK) {
                HandleError(L"[!] Error: Failed to initialize zlib");
                return S_FALSE;
            }

            if (inflate(&strm, Z_FINISH) != Z_STREAM_END) {
                inflateEnd(&strm);
                HandleError(L"[!] Error: Failed to decompress data");
                return S_FALSE;
            }

            inflateEnd(&strm);

            if (item.decompressedData.size() != item.uncompressedSize) {
                HandleError(L"[!] Warning: Decompressed size does not match expected uncompressed size");
                return S_FALSE;
            }

        }
        else {
            HandleError(L"[!] Error: No zlib header found in data");
            return S_FALSE;
        }
    }

    return S_OK;
}
