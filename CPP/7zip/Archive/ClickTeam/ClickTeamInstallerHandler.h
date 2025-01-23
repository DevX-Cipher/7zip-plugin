#include <vector>
#include <string>
#include <sstream>
#include <cstdint>
#include <locale>
#include <codecvt>
#include <map>
#include <iomanip>
#include <iostream>
#include "../../Bundles/ClickTeam/ClickTeam/zLib.h"
#include "../../Bundles/ClickTeam/ClickTeam/bzlib.h"
#include <windows.h>

#include <functional>
#include <filesystem>
#include <regex>
#include <set>


class ClickTeamInstallerHandler {
    UInt64 archiveSize;
    uint64_t overlayPos;
public:
    struct FileInfo {
        std::streampos position;  // To track the file's position in the stream
        uint32_t size;            // File size
        uint32_t type;            // File type
        std::string path;     // File name
        uint32_t offset;          // File offset
        uint32_t compressedSize;  // Compressed size
        uint32_t uncompressedSize;// Uncompressed size
        int64_t fileTime1;        // File time 1
        int64_t fileTime2;        // File time 2
        int64_t fileTime3;        // File time 3
        std::vector<uint8_t> decompressedData;
        FileInfo()
			: position(0), size(0), type(0), offset(0), path(""),
            compressedSize(0), uncompressedSize(0), fileTime1(0), fileTime2(0), fileTime3(0) {
        }
        
        // Set file info attributes
        void SetFileInfos(uint32_t offset, uint32_t compressedSize, uint32_t uncompressedSize) {
            this->offset = offset;
            this->compressedSize = compressedSize;
            this->uncompressedSize = uncompressedSize;
        }

        // Set file timestamps
        void SetFileTimes(int64_t time1, int64_t time2, int64_t time3) {
            fileTime1 = time1;
            fileTime2 = time2;
            fileTime3 = time3;
        }
        // Optionally, to help with debugging, add a method to print the file info
        bool IsValid(long fileStreamLength, long offset, long compressedSize, long uncompressedSize, long index, const std::wstring& path) {
            if (offset > fileStreamLength ||
                (compressedSize == 0 && uncompressedSize > 3000000000) ||
                (uncompressedSize > 10 && compressedSize > 10 && compressedSize > uncompressedSize * 5) ||
                index > 1000000000 ||
                PathContainsInvalidChars(path)) {
                return false;
            }
        }
        static bool PathContainsInvalidChars(const std::wstring& path) {
            // Check for invalid characters in the path (you can adjust this as needed)
            // Here, we are checking for characters that are not allowed in file paths
            for (wchar_t ch : path) {
                if (ch == L'/' || ch == L'\\' || ch == L':' || ch == L'<' || ch == L'>' || ch == L'"' || ch == L'|' || ch == L'?') {
                    return true;
                }
            }
            return false;
        }
    };
    HRESULT Open(IInStream* stream, const UInt64* fileSize, IArchiveOpenCallback* callback);
    CMyComPtr<IArchiveOpenVolumeCallback> volCallback;
    HRESULT ExtractFileData(IInStream* stream, FileInfo& fileInfo);
    HRESULT ParseArchive(IInStream* stream, const std::vector<char>& decompressedData);
    HRESULT unpackStream(IInStream* stream, long dataStreamLength, std::vector<char>& decompressedData, std::vector<FileInfo>& filesInfos, int installerVersion);
    

  
    const int BLOCK_HEADER_SIZE = 16 + 16 + 32;
    const std::string DATA_SECTION_SIGNATURE_STR = "\x77\x77\x67\x54\x29\x48";
    std::vector<FileInfo> items;

};
void tryParse20(IInStream* stream, ClickTeamInstallerHandler::FileInfo& fileInfo);
void tryParse24(IInStream* stream, ClickTeamInstallerHandler::FileInfo& fileInfo);
void tryParse30(IInStream* stream, ClickTeamInstallerHandler::FileInfo& fileInfo);
void tryParse35(IInStream* stream, ClickTeamInstallerHandler::FileInfo& fileInfo);
void tryParse40(IInStream* stream, ClickTeamInstallerHandler::FileInfo& fileInfo);
std::vector<char> decompressedData;
HRESULT readUint32(IInStream* stream, uint32_t* value) {
    UInt32 bytesRead = 0;
    return stream->Read(reinterpret_cast<BYTE*>(value), sizeof(uint32_t), &bytesRead);
}
HRESULT readUint16(IInStream* stream, uint16_t* value) {
    UInt32 bytesRead = 0;
    return stream->Read(reinterpret_cast<BYTE*>(value), sizeof(uint16_t), &bytesRead);
}
HRESULT readInt64(IInStream* stream, int64_t* value) {
    UInt32 bytesRead = 0;
    return stream->Read(reinterpret_cast<BYTE*>(value), sizeof(int64_t), &bytesRead);
}
HRESULT readByte(IInStream* stream, char* value) {
    UInt32 bytesRead = 0;
    return stream->Read(reinterpret_cast<BYTE*>(value), sizeof(char), &bytesRead);
}

bool isValidFileNameCharacter(char c) {
    return std::isalnum(c) || c == '.' || c == '_' || c == '-' || c == ' ' || c == '#'; // Add any other chars you expect
}
bool isValidFileName(const std::string& name) {
    // We can refine this to match specific file extensions or other criteria if needed
    return !name.empty() && (name.find(".exe") != std::string::npos || name.find(".lnk") != std::string::npos || name.find(".dll") != std::string::npos);
}
void filterInvalidChars(std::vector<char>& decompressedData) {
    for (auto& byte : decompressedData) {
        // If byte is outside the valid ASCII range, replace with a space (0x20) or another valid character
        if (byte < 0 || byte > 255) {
            byte = 0x20;  // Replace invalid byte with a space (0x20)
        }
    }
}

enum CompressionMethod {
    NONE = 0,
    DEFLATE = 1,
    BZ2 = 2
};
enum BLOCK_TYPE {
    FILE_LIST = 0x143A,
    FILE_DATA = 0x7F7F,
    STRINGS = 0x143E,
    UNKNOWN_FONT = 0x1435,
    UNKNOWN_DATA = 0x1436,
    BACKGROUND_IMAGE = 0x1437,
    UNKNOWN_NUMBERS = 0x1444,
    REGISTRY_CHANGES = 0x1445,
    UNINSTALLER = 0x143F
};


void skipBytes(IInStream* stream, uint64_t numBytes) {
    // Initialize the current position to track the stream manually
    static uint64_t currentPosition = 0; // Static variable to maintain the current position across function calls

    // Perform the seek operation to skip the bytes
    HRESULT result = stream->Seek(numBytes, STREAM_SEEK_CUR, nullptr);

    if (FAILED(result)) {
        std::cerr << "Failed to skip bytes. Current position: " << currentPosition << std::endl;
        return;
    }

    // Manually update the position after skipping bytes
    currentPosition += numBytes;

    std::cout << "Skipped " << numBytes << " bytes. Position before: " << currentPosition - numBytes << ", New position: " << currentPosition << std::endl;
}

bool TestInstallerVersion(int version, std::function<void(IInStream*, ClickTeamInstallerHandler::FileInfo&)> parsingFunction, IInStream* stream, uint16_t fileNumber, long dataStreamLength) {
    // Temporary buffer to read data from the stream
    const size_t bufferSize = 4096;  // 4KB buffer size, adjust as needed
    std::vector<BYTE> buffer(bufferSize);

    uint64_t currentPosition = 0;  // Tracking the stream position manually
    HRESULT hr;

    // Use a variable of type UInt32 for bytesRead to match the expected type in Read
    UInt32 bytesRead = 0;

    for (int i = 0; i < fileNumber; ++i) {
        try {
            ClickTeamInstallerHandler::FileInfo fileInfo;  // Use ClickTeamInstallerHandler::FileInfo

            // Read the necessary data into the buffer
            hr = stream->Read(buffer.data(), static_cast<UInt32>(bufferSize), &bytesRead);
            if (FAILED(hr) || bytesRead == 0) {
                std::cerr << "Error reading from stream" << std::endl;
                return false;
            }

            // Use the parsing function to extract file info from the read buffer
            parsingFunction(stream, fileInfo);

            std::cout << "Node " << i << " at offset " << fileInfo.position
                << ", size: " << fileInfo.size
                << ", end: " << (static_cast<uint64_t>(fileInfo.position) + static_cast<uint64_t>(fileInfo.size))
                << std::endl;

            if (!fileInfo.IsValid(dataStreamLength, fileInfo.offset, fileInfo.compressedSize, fileInfo.uncompressedSize, i, std::wstring(fileInfo.path.begin(), fileInfo.path.end()))) {
                std::cerr << "Invalid file info" << std::endl;
                return false;
            }

            // Skip to the next file if necessary
            if (fileInfo.type != 0) {
                currentPosition = static_cast<uint64_t>(fileInfo.position) + static_cast<uint64_t>(fileInfo.size);
                // Simulate the seek operation by updating currentPosition
            }
        }
        catch (const std::ios_base::failure& e) {
            std::cerr << "End of Stream reached while parsing file list" << std::endl;
            return false;
        }
    }

    return true;
}

int GetInstallerVersion(IInStream* stream, uint16_t fileNumber, long dataStreamLength) {
    static int installerVersion = -1;

    if (installerVersion > -1) {
        return installerVersion;
    }

    std::map<int, std::function<void(IInStream*, ClickTeamInstallerHandler::FileInfo&)>> versionMap = {
        {40, tryParse40},
        {35, tryParse35},
        {30, tryParse30},
        {24, tryParse24},
        {20, tryParse20}
    };

    for (const auto& versionPair : versionMap) {
        if (TestInstallerVersion(versionPair.first, versionPair.second, stream, fileNumber, dataStreamLength)) {
            installerVersion = versionPair.first;
            return installerVersion;
        }
    }

    std::cerr << "Failed to determine installer version. Please send a bug report if you want the file to be supported in a future version." << std::endl;
    return -1;
}





HRESULT ClickTeamInstallerHandler::unpackStream(IInStream* stream, long dataStreamLength, std::vector<char>& decompressedData,
    std::vector<FileInfo>& filesInfos, int installerVersion) {

    // Step 1: Track the initial position before reading any data
    ULONGLONG initialPosition = 0;
    HRESULT hr = stream->Seek(0, STREAM_SEEK_CUR, &initialPosition);
    if (FAILED(hr)) {
        MessageBox(nullptr, L"[DECOMPRESSION] Failed to get stream position.", L"Debug", MB_OK | MB_ICONERROR);
        return E_FAIL;
    }

    // Step 2: Read decompressed size and compression method
    uint32_t decompressedSize;
    hr = stream->Read(reinterpret_cast<BYTE*>(&decompressedSize), sizeof(decompressedSize), nullptr);
    if (FAILED(hr)) {
        MessageBox(nullptr, L"[DECOMPRESSION] Failed to read decompressed size.", L"Debug", MB_OK | MB_ICONERROR);
        return E_FAIL;
    }

    uint8_t compressionMethod;
    hr = stream->Read(reinterpret_cast<BYTE*>(&compressionMethod), sizeof(compressionMethod), nullptr);
    if (FAILED(hr)) {
        MessageBox(nullptr, L"[DECOMPRESSION] Failed to read compression method.", L"Debug", MB_OK | MB_ICONERROR);
        return E_FAIL;
    }

    // Step 3: Adjust initial position after reading 5 bytes (4 for decompressedSize + 1 for compressionMethod)
    initialPosition += 5; // Adjust for the bytes read
    std::wostringstream oss;
    oss << L"[DECOMPRESSION] Decompressing " << dataStreamLength << L" bytes at position " << initialPosition
        << L"\nCompression method: " << static_cast<int>(compressionMethod)
        << L", Decompressed size: " << decompressedSize;

    MessageBox(nullptr, oss.str().c_str(), L"Debug", MB_OK | MB_ICONINFORMATION);

    // Step 4: Prepare for decompression (resize decompressed data buffer)
    decompressedData.resize(decompressedSize);

    // Step 5: Handle different compression methods
    switch (compressionMethod) {
    case NONE:
        MessageBox(nullptr, L"[DECOMPRESSION] No compression. Copying data directly.", L"Debug", MB_OK | MB_ICONINFORMATION);
        hr = stream->Read(reinterpret_cast<BYTE*>(decompressedData.data()), decompressedSize, nullptr);
        if (FAILED(hr)) {
            MessageBox(nullptr, L"[DECOMPRESSION] Failed to read decompressed data.", L"Debug", MB_OK | MB_ICONERROR);
            return E_FAIL;
        }
        break;

    case DEFLATE:
        MessageBox(nullptr, L"[DECOMPRESSION] DEFLATE compression detected.", L"Debug", MB_OK | MB_ICONINFORMATION);
        {
            size_t compressedDataSize = dataStreamLength - 5;  // Adjust size after reading header
            std::vector<char> compressedData(compressedDataSize);
            hr = stream->Read(reinterpret_cast<BYTE*>(compressedData.data()), compressedData.size(), nullptr);
            if (FAILED(hr)) {
                MessageBox(nullptr, L"[DECOMPRESSION] Failed to read compressed data.", L"Debug", MB_OK | MB_ICONERROR);
                return E_FAIL;
            }

            // Perform decompression (using zlib, for example)
            z_stream strm = {};
            strm.next_in = reinterpret_cast<Bytef*>(compressedData.data());
            strm.avail_in = compressedData.size();
            strm.next_out = reinterpret_cast<Bytef*>(decompressedData.data());
            strm.avail_out = decompressedSize;

            if (inflateInit2(&strm, 15 + 32) != Z_OK) {
                MessageBox(nullptr, L"[DECOMPRESSION] Failed to initialize zlib inflate.", L"Debug", MB_OK | MB_ICONERROR);
                return E_FAIL;
            }

            int ret = inflate(&strm, Z_FINISH);
            if (ret != Z_STREAM_END) {
                std::wostringstream inflateErr;
                inflateErr << L"[DECOMPRESSION] Failed to decompress DEFLATE data: " << ret;
                MessageBox(nullptr, inflateErr.str().c_str(), L"Debug", MB_OK | MB_ICONERROR);
                inflateEnd(&strm);
                return E_FAIL;
            }

            inflateEnd(&strm);
        }
        break;

    case BZ2:
        MessageBox(nullptr, L"[DECOMPRESSION] BZ2 compression detected.", L"Debug", MB_OK | MB_ICONINFORMATION);
        {
            size_t compressedDataSize = dataStreamLength - 5;  // Adjust size after reading header
            std::vector<char> compressedData(compressedDataSize);
            hr = stream->Read(reinterpret_cast<BYTE*>(compressedData.data()), compressedData.size(), nullptr);
            if (FAILED(hr)) {
                MessageBox(nullptr, L"[DECOMPRESSION] Failed to read compressed data.", L"Debug", MB_OK | MB_ICONERROR);
                return E_FAIL;
            }

            unsigned int destLen = decompressedSize;
            if (BZ2_bzBuffToBuffDecompress(decompressedData.data(), &destLen, compressedData.data(), compressedData.size(), 0, 0) != BZ_OK) {
                MessageBox(nullptr, L"[DECOMPRESSION] Failed to decompress BZ2 data.", L"Debug", MB_OK | MB_ICONERROR);
                return E_FAIL;
            }
        }
        break;

    default:
        std::wostringstream errMsg;
        errMsg << L"[DECOMPRESSION] Unknown compression method: " << static_cast<int>(compressionMethod)
            << L". Skipping block.";
        MessageBox(nullptr, errMsg.str().c_str(), L"Debug", MB_OK | MB_ICONERROR);

        // Seek back to compensate for the read bytes
        hr = stream->Seek(dataStreamLength - 5, STREAM_SEEK_CUR, nullptr);
        if (FAILED(hr)) {
            MessageBox(nullptr, L"[DECOMPRESSION] Failed to seek stream position.", L"Debug", MB_OK | MB_ICONERROR);
            return E_FAIL;
        }

        return E_FAIL;
    }

    // After decompression, call filterInvalidChars
    filterInvalidChars(decompressedData);
    MessageBox(nullptr, L"[DECOMPRESSION] Decompressed data stored successfully.", L"Debug", MB_OK | MB_ICONINFORMATION);

   // ParseArchive(stream, decompressedData);

    return S_OK;  // Return success HRESULT
}




HRESULT ClickTeamInstallerHandler::ExtractFileData(IInStream* stream, FileInfo& fileInfo) {
    // Seek to the file offset within the stream
    RINOK(stream->Seek(fileInfo.offset, STREAM_SEEK_SET, nullptr));

    // Read the file data into a buffer
    std::vector<char> fileData(static_cast<size_t>(fileInfo.uncompressedSize));
    RINOK(stream->Read(reinterpret_cast<BYTE*>(fileData.data()), static_cast<UInt32>(fileData.size()), nullptr));

    // Now, fileData contains the uncompressed data.
    // You can now use fileData directly in your application without further processing.

    // Optionally, you could pass this data to another function to display or process as needed.

    return S_OK;
}





HRESULT ClickTeamInstallerHandler::Open(IInStream* stream, const UInt64* fileSize, IArchiveOpenCallback* callback) {
    if (!callback || !stream) {
        return S_FALSE; // Early return if inputs are invalid
    }

    // Query interface for volume callback
    HRESULT result = callback->QueryInterface(IID_IArchiveOpenVolumeCallback, (void**)&volCallback);
    RINOK(result);

    if (volCallback == nullptr) {
        MessageBox(NULL, L"Error: Failed to get volume callback interface.", L"Debug - ClickTeamInstallerHandler::Open", MB_OK | MB_ICONERROR);
        return E_FAIL;
    }

    // Initialize and validate the file size
    UInt64 streamLength;
    RINOK(stream->Seek(0, STREAM_SEEK_END, &streamLength));


    std::vector<char> buffer(static_cast<size_t>(streamLength));
    RINOK(stream->Read(reinterpret_cast<BYTE*>(buffer.data()), static_cast<UInt32>(streamLength), nullptr));

    uint16_t fileNumber = 0;
    int installerVersion = GetInstallerVersion(stream, fileNumber, streamLength);
    if (installerVersion == -1) {
        MessageBox(NULL, L"Error: Failed to detect installer version!", L"Debug - ClickTeamInstallerHandler::Open", MB_OK | MB_ICONERROR);
        return E_FAIL;
    }

    // Reset the stream state after version detection
    RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));

    // Set position to DATA_SECTION_SIGNATURE_STR.size()
    UInt64 position = DATA_SECTION_SIGNATURE_STR.size();
    RINOK(stream->Seek(position, STREAM_SEEK_SET, nullptr));

    std::set<uint64_t> processedBlocks;
    std::vector<FileInfo> filesInfos;

    while (position + BLOCK_HEADER_SIZE <= streamLength) {
        uint16_t blockId;
        RINOK(stream->Read(reinterpret_cast<BYTE*>(&blockId), sizeof(blockId), nullptr));
        position += sizeof(blockId);

        skipBytes(stream, 2);
        position += 2;
        uint32_t blockSize;
        RINOK(stream->Read(reinterpret_cast<BYTE*>(&blockSize), sizeof(blockSize), nullptr));
        position += sizeof(blockSize);

        uint64_t currentPosition = position;
        uint64_t nextBlockPos = currentPosition + blockSize;

        if (nextBlockPos > streamLength || blockSize == 0 || blockSize > INT_MAX) {
            MessageBox(NULL, L"Error: Invalid block size or position!", L"Debug - ClickTeamInstallerHandler::Open", MB_OK | MB_ICONERROR);
            break;
        }

        RINOK(stream->Seek(position, STREAM_SEEK_SET, nullptr));
         
		BLOCK_TYPE blockType = static_cast<BLOCK_TYPE>(blockId);
        if (blockType == FILE_LIST) {
           
            UInt64 totalSize = streamLength;
            RINOK(callback->SetTotal(nullptr, &totalSize));
            HRESULT unpackResult = unpackStream(stream, blockSize, decompressedData, filesInfos, installerVersion);
            RINOK(unpackResult);
            HRESULT parseResult = ParseArchive(stream, decompressedData);
            RINOK(parseResult);
        }
        else if (blockType == FILE_DATA) {
            for (auto& fileInfo : filesInfos) {
                HRESULT extractResult = ExtractFileData(stream, fileInfo);
                RINOK(extractResult);
            }
        }

        position = nextBlockPos;
        RINOK(stream->Seek(position, STREAM_SEEK_SET, nullptr));
    }

    

  

    return S_OK;
}






HRESULT ClickTeamInstallerHandler::ParseArchive(IInStream* stream, const std::vector<char>& decompressedData) {
    std::wstring msg;

    // Debug message for decompressed data
    msg = L"Start parsing decompressed data. Data size: " + std::to_wstring(decompressedData.size());
    MessageBox(NULL, msg.c_str(), L"Debug - Parsing", MB_OK | MB_ICONINFORMATION);

    // Seek to the beginning of the decompressed data section
    HRESULT result = stream->Seek(0, STREAM_SEEK_SET, nullptr);
    RINOK(result);

    bool insideFileName = false;
    std::string currentFileName;
    std::vector<std::wstring> validFileNames; // To accumulate valid file names

    for (size_t i = 0; i < decompressedData.size(); ++i) {
        if (isValidFileNameCharacter(decompressedData[i])) {
            if (!insideFileName) {
                // If starting a new file name, clear the previous one
                currentFileName.clear();
                insideFileName = true;
            }
            currentFileName += decompressedData[i]; // Append valid character
        }
        else if (insideFileName) {
            if (isValidFileName(currentFileName)) {
                // Add valid file name to the list
                validFileNames.push_back(std::wstring(currentFileName.begin(), currentFileName.end()));
                currentFileName.clear(); // Reset for the next potential file
            }
            insideFileName = false; // Exit file name state
        }
    }

    // Debugging the valid file names
    if (!validFileNames.empty()) {
        msg = L"Found the following valid file names:\n";
        for (const auto& fileName : validFileNames) {
            msg += fileName + L"\n"; // Add each valid file name to the message
            std::wcout << L"Valid file: " << fileName << std::endl; // Debugging output
        }
        msg += L"\nTotal files found: " + std::to_wstring(validFileNames.size());

        // Display all the file names in one message box
        MessageBox(NULL, msg.c_str(), L"Debug - File Names Found", MB_OK | MB_ICONINFORMATION);

        // Add the files to the items vector
        for (const auto& fileName : validFileNames) {
            FileInfo item;
            item.path = std::string(fileName.begin(), fileName.end()); // Convert wstring to string
            this->items.emplace_back(item);  // Assuming `items` is a member variable
        }
    }
    else {
        msg = L"No valid file names found in the decompressed data.";
        MessageBox(NULL, msg.c_str(), L"Debug - No Files Found", MB_OK | MB_ICONINFORMATION);
    }

    return S_OK;
}






void tryParse20(IInStream* stream, ClickTeamInstallerHandler::FileInfo& fileInfo) {
    try {
        HRESULT result;

        // Read the file size
        uint32_t fileSize;
        result = readUint32(stream, &fileSize);
        if (FAILED(result)) {
            std::cerr << "Error reading file size. Skipping file." << std::endl;
            return;
        }
        fileInfo.size = fileSize;

        // Read the file type
        uint16_t fileType;
        result = readUint16(stream, &fileType);
        if (FAILED(result)) {
            std::cerr << "Error reading file type. Skipping file." << std::endl;
            return;
        }
        fileInfo.type = fileType;

        // If the file type is not 0, return early
        if (fileInfo.type != 0) {
            return;
        }

        // Skip 14 bytes
        result = stream->Seek(14, STREAM_SEEK_CUR, nullptr);
        if (FAILED(result)) {
            std::cerr << "Error skipping 14 bytes. Skipping file." << std::endl;
            return;
        }

        // Read uncompressed size
        uint32_t uncompressedSize;
        result = readUint32(stream, &uncompressedSize);
        if (FAILED(result)) {
            std::cerr << "Error reading uncompressed size. Skipping file." << std::endl;
            return;
        }

        // Read offset
        uint32_t offset;
        result = readUint32(stream, &offset);
        if (FAILED(result)) {
            std::cerr << "Error reading offset. Skipping file." << std::endl;
            return;
        }

        // Read compressed size
        uint32_t compressedSize;
        result = readUint32(stream, &compressedSize);
        if (FAILED(result)) {
            std::cerr << "Error reading compressed size. Skipping file." << std::endl;
            return;
        }

        fileInfo.SetFileInfos(offset, compressedSize, uncompressedSize);

        // Read file times
        int64_t creationTime, accessTime, modificationTime;
        result = readInt64(stream, &creationTime);
        if (FAILED(result)) {
            std::cerr << "Error reading creation time. Skipping file." << std::endl;
            return;
        }
        result = readInt64(stream, &accessTime);
        if (FAILED(result)) {
            std::cerr << "Error reading access time. Skipping file." << std::endl;
            return;
        }
        result = readInt64(stream, &modificationTime);
        if (FAILED(result)) {
            std::cerr << "Error reading modification time. Skipping file." << std::endl;
            return;
        }
        fileInfo.SetFileTimes(creationTime, accessTime, modificationTime);

        // Read file name directly (null-terminated string)
        std::string fileName;
        char ch;

        // Read until the null terminator is found
        while (readByte(stream, &ch) == S_OK && ch != '\0') {
            fileName += ch;
        }

        // Check if the file name is valid and not empty
        if (!fileName.empty()) {
            fileInfo.path = fileName;
            std::cout << "File name: " << fileName << std::endl;
        }
        else {
            std::cerr << "Warning: Invalid or empty file name encountered at position " << fileInfo.offset << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error reading file info: " << e.what() << ". Skipping file." << std::endl;
    }
}

void tryParse24(IInStream* stream, ClickTeamInstallerHandler::FileInfo& fileInfo) {
    try {
        HRESULT result;

        // Skip unnecessary data
        result = stream->Seek(2, STREAM_SEEK_CUR, nullptr);  // Skip 2 bytes
        if (FAILED(result)) {
            std::cerr << "Error skipping 2 bytes. Skipping file." << std::endl;
            return;
        }

        // Discard 4x uint32 metadata
        uint32_t discard;
        for (int i = 0; i < 4; ++i) {
            result = readUint32(stream, &discard);
            if (FAILED(result)) {
                std::cerr << "Error discarding uint32 metadata. Skipping file." << std::endl;
                return;
            }
        }

        result = stream->Seek(16, STREAM_SEEK_CUR, nullptr);  // Skip another 16 bytes
        if (FAILED(result)) {
            std::cerr << "Error skipping 16 bytes. Skipping file." << std::endl;
            return;
        }

        // Now read the file information
        uint32_t fileSize;
        result = readUint32(stream, &fileSize);  // Assuming the size is read here
        if (FAILED(result)) {
            std::cerr << "Error reading file size. Skipping file." << std::endl;
            return;
        }
        fileInfo.size = fileSize;
        fileInfo.type = 0;  // Set the type to 0 as per the logic in FileInfo

        // Read the file name directly
        std::string fileName;
        char ch;

        // Read until the null terminator is found
        while ((result = readByte(stream, &ch)) == S_OK && ch != '\0') {
            fileName += ch;
        }
        if (FAILED(result) && result != S_FALSE) {
            std::cerr << "Error reading byte for file name. Skipping file." << std::endl;
            return;
        }

        // Set the file name in the FileInfo object
        fileInfo.path = fileName;

        // Display the file name if valid
        if (!fileName.empty()) {
            std::cout << "File name: " << fileName << std::endl;
        }
        else {
            std::cerr << "Warning: Invalid or empty file name encountered." << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error reading file info: " << e.what() << ". Skipping file." << std::endl;
    }
}

void tryParse30(IInStream* stream, ClickTeamInstallerHandler::FileInfo& fileInfo) {
    try {
        HRESULT result;

        // Skip unnecessary data
        result = stream->Seek(2, STREAM_SEEK_CUR, nullptr);  // Skip 2 bytes
        if (FAILED(result)) {
            std::cerr << "Error skipping 2 bytes. Skipping file." << std::endl;
            return;
        }

        // Discard 4x uint32 metadata
        uint32_t discard;
        for (int i = 0; i < 4; ++i) {
            result = readUint32(stream, &discard);
            if (FAILED(result)) {
                std::cerr << "Error discarding uint32 metadata. Skipping file." << std::endl;
                return;
            }
        }

        result = stream->Seek(18, STREAM_SEEK_CUR, nullptr);  // Skip another 18 bytes
        if (FAILED(result)) {
            std::cerr << "Error skipping 18 bytes. Skipping file." << std::endl;
            return;
        }

        // Now read the file information
        uint32_t fileSize;
        result = readUint32(stream, &fileSize);  // Assuming the size is read here
        if (FAILED(result)) {
            std::cerr << "Error reading file size. Skipping file." << std::endl;
            return;
        }
        fileInfo.size = fileSize;
        fileInfo.type = 0;  // Set the type to 0 as per the logic in FileInfo

        // Read the file name directly
        std::string fileName;
        char ch;

        // Read until the null terminator is found
        while ((result = readByte(stream, &ch)) == S_OK && ch != '\0') {
            fileName += ch;
        }
        if (FAILED(result) && result != S_FALSE) {
            std::cerr << "Error reading byte for file name. Skipping file." << std::endl;
            return;
        }

        // Set the file name in the FileInfo object
        fileInfo.path = fileName;

        // Display the file name if valid
        if (!fileName.empty()) {
            std::cout << "File name: " << fileName << std::endl;
        }
        else {
            std::cerr << "Warning: Invalid or empty file name encountered." << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error reading file info: " << e.what() << ". Skipping file." << std::endl;
    }
}

void tryParse35(IInStream* stream, ClickTeamInstallerHandler::FileInfo& fileInfo) {
    try {
        HRESULT result;

        // Skip unnecessary data
        result = stream->Seek(22, STREAM_SEEK_CUR, nullptr);  // Skip 22 bytes
        if (FAILED(result)) {
            std::cerr << "Error skipping 22 bytes. Skipping file." << std::endl;
            return;
        }

        // Discard uncompressed size, offset, and compressed size
        uint32_t discard;
        for (int i = 0; i < 3; ++i) {
            result = readUint32(stream, &discard);
            if (FAILED(result)) {
                std::cerr << "Error discarding metadata. Skipping file." << std::endl;
                return;
            }
        }

        // Now read the file information
        uint32_t fileSize;
        result = readUint32(stream, &fileSize);  // Assuming the size is read here
        if (FAILED(result)) {
            std::cerr << "Error reading file size. Skipping file." << std::endl;
            return;
        }
        fileInfo.size = fileSize;
        fileInfo.type = 0;  // Set the type to 0 as per the logic in FileInfo

        // Read the file name directly
        std::string fileName;
        char ch;

        // Read until the null terminator is found
        while ((result = readByte(stream, &ch)) == S_OK && ch != '\0') {
            fileName += ch;
        }
        if (FAILED(result) && result != S_FALSE) {
            std::cerr << "Error reading byte for file name. Skipping file." << std::endl;
            return;
        }

        // Set the file name in the FileInfo object
        fileInfo.path = fileName;

        // Display the file name if valid
        if (!fileName.empty()) {
            std::cout << "File name: " << fileName << std::endl;
        }
        else {
            std::cerr << "Warning: Invalid or empty file name encountered." << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error reading file info: " << e.what() << ". Skipping file." << std::endl;
    }
}

void tryParse40(IInStream* stream, ClickTeamInstallerHandler::FileInfo& fileInfo) {
    try {
        UInt64 streamPos = 0;
        HRESULT hr = stream->Seek(0, STREAM_SEEK_CUR, &streamPos);  // Get current position
        if (FAILED(hr)) {
            std::cerr << "Error: Failed to get stream position." << std::endl;
            return;
        }

        fileInfo.position = streamPos; // Capture the position in the stream
        std::cout << "Stream position before reading size: " << fileInfo.position << std::endl;

        // Read file size and type
        uint32_t fileSize;
        hr = readUint32(stream, &fileSize);  // Read the file size
        if (FAILED(hr)) {
            std::cerr << "Error reading file size. Skipping file." << std::endl;
            return;
        }
        fileInfo.size = fileSize;

        uint16_t fileType;
        hr = readUint16(stream, &fileType);  // Read the file type
        if (FAILED(hr)) {
            std::cerr << "Error reading file type. Skipping file." << std::endl;
            return;
        }
        fileInfo.type = fileType;

        std::cout << "Position: " << fileInfo.position << ", Size: " << fileInfo.size << ", Type: " << fileInfo.type << std::endl;

        // Skip if file type is not 0
        if (fileInfo.type != 0) {
            std::cerr << "Invalid file type detected: " << fileInfo.type << ". Skipping file." << std::endl;
            return;
        }

        // Skip 3 bytes
        hr = stream->Seek(3, STREAM_SEEK_CUR, nullptr);
        if (FAILED(hr)) {
            std::cerr << "Error skipping 3 bytes. Skipping file." << std::endl;
            return;
        }

        // Peek byte to handle special cases (you can't peek directly in IInStream, so we read the byte)
        char peekByte;
        hr = stream->Read(&peekByte, 1, nullptr);
        if (FAILED(hr)) {
            std::cerr << "Failed to peek byte from stream." << std::endl;
            return;
        }

        std::cout << "Peek byte: " << std::hex << (int)peekByte << std::dec << std::endl;

        if (peekByte == 0xE2) {
            hr = stream->Seek(1, STREAM_SEEK_CUR, nullptr);  // Skip the peeked byte
            if (FAILED(hr)) {
                std::cerr << "Error skipping 1 byte. Skipping file." << std::endl;
                return;
            }

            hr = stream->Seek(30, STREAM_SEEK_CUR, nullptr); // Skip 30 bytes
            if (FAILED(hr)) {
                std::cerr << "Error skipping 30 bytes. Skipping file." << std::endl;
                return;
            }
        }
        else {
            hr = stream->Seek(14, STREAM_SEEK_CUR, nullptr);  // Skip 14 bytes otherwise
            if (FAILED(hr)) {
                std::cerr << "Error skipping 14 bytes. Skipping file." << std::endl;
                return;
            }

            uint32_t uncompressedSize;
            hr = readUint32(stream, &uncompressedSize);
            if (FAILED(hr)) {
                std::cerr << "Error reading uncompressed size. Skipping file." << std::endl;
                return;
            }

            uint32_t offset;
            hr = readUint32(stream, &offset);
            if (FAILED(hr)) {
                std::cerr << "Error reading offset. Skipping file." << std::endl;
                return;
            }

            uint32_t compressedSize;
            hr = readUint32(stream, &compressedSize);
            if (FAILED(hr)) {
                std::cerr << "Error reading compressed size. Skipping file." << std::endl;
                return;
            }

            hr = stream->Seek(4, STREAM_SEEK_CUR, nullptr); // Skip 4 bytes
            if (FAILED(hr)) {
                std::cerr << "Error skipping 4 bytes. Skipping file." << std::endl;
                return;
            }

            fileInfo.SetFileInfos(offset, compressedSize, uncompressedSize);

            int64_t creationTime, accessTime, modificationTime;
            hr = readInt64(stream, &creationTime);
            if (FAILED(hr)) {
                std::cerr << "Error reading creation time. Skipping file." << std::endl;
                return;
            }
            hr = readInt64(stream, &accessTime);
            if (FAILED(hr)) {
                std::cerr << "Error reading access time. Skipping file." << std::endl;
                return;
            }
            hr = readInt64(stream, &modificationTime);
            if (FAILED(hr)) {
                std::cerr << "Error reading modification time. Skipping file." << std::endl;
                return;
            }
            fileInfo.SetFileTimes(creationTime, accessTime, modificationTime);
        }

        // Ensure we handle the file name properly, taking into account null-terminated strings.
        std::string fileName;
        char ch;

        // Read until the null terminator is found
        while ((hr = readByte(stream, &ch)) == S_OK && ch != '\0') {
            fileName += ch;
        }
        if (FAILED(hr) && hr != S_FALSE) {
            std::cerr << "Error reading byte for file name. Skipping file." << std::endl;
            return;
        }

        // Log the entire file name read
        std::cout << "Full file name read: " << fileName << std::endl;

        // Validate the file name
        if (!fileName.empty()) {
            fileInfo.path = fileName;
            std::cout << "Extracted file name: " << fileName << std::endl;
        }
        else {
            std::cerr << "Warning: Invalid or empty file name encountered at position " << streamPos << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error reading file info: " << e.what() << ". Skipping file." << std::endl;
    }
}
