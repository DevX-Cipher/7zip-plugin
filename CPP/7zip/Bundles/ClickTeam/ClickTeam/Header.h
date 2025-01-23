


bool isValidFileNameCharacter(char c) {
    return std::isalnum(c) || c == '.' || c == '_' || c == '-' || c == ' ' || c == '#'; // Add any other chars you expect
}

// Helper function to check if the string looks like a valid file name
bool isValidFileName(const std::string& name) {
    // We can refine this to match specific file extensions or other criteria if needed
    return !name.empty() && (name.find(".exe") != std::string::npos || name.find(".lnk") != std::string::npos || name.find(".dll") != std::string::npos);
}

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



uint32_t readUint32(IInStream* stream) {
    uint32_t value = 0;
    HRESULT hr = stream->Read(&value, sizeof(value), nullptr);  // Read 4 bytes into value
    if (FAILED(hr)) {
        std::cerr << "Error reading uint32 from stream." << std::endl;
        return 0;
    }
    return value;
}

uint16_t readUint16(IInStream* stream) {
    uint16_t value = 0;
    HRESULT hr = stream->Read(&value, sizeof(value), nullptr);  // Read 2 bytes into value
    if (FAILED(hr)) {
        std::cerr << "Error reading uint16 from stream." << std::endl;
        return 0;
    }
    return value;
}

int64_t readInt64(IInStream* stream) {
    int64_t value = 0;
    HRESULT hr = stream->Read(&value, sizeof(value), nullptr);  // Read 8 bytes into value
    if (FAILED(hr)) {
        std::cerr << "Error reading int64 from stream." << std::endl;
        return 0;
    }
    return value;
}

bool readByte(IInStream* stream, char& byte) {
    return stream->Read(&byte, 1, nullptr) == S_OK;
}

void seek(IInStream* stream, int64_t offset) {
    stream->Seek(offset, STREAM_SEEK_CUR, nullptr);
}


void tryParse20(IInStream* stream, FileInfo& fileInfo) {
    try {
        fileInfo.size = readUint32(stream);  // Read the file size
        fileInfo.type = readUint16(stream);  // Read the file type

        if (fileInfo.type != 0) {
            return; // If the file type is not 0, return early
        }

        seek(stream, 14); // Skip 14 bytes

        uint32_t uncompressedSize = readUint32(stream);
        uint32_t offset = readUint32(stream);
        uint32_t compressedSize = readUint32(stream);
        fileInfo.SetFileInfos(offset, compressedSize, uncompressedSize);

        fileInfo.SetFileTimes(readInt64(stream), readInt64(stream), readInt64(stream));

        // Read file name directly (null-terminated string)
        std::string fileName;
        char ch;

        // Read until the null terminator is found
        while (readByte(stream, ch) && ch != '\0') {
            fileName += ch;
        }

        // Check if the file name is valid and not empty
        if (!fileName.empty()) {
            fileInfo.SetFileName(fileName);
            std::cout << "File name: " << fileName << std::endl;
        }
        else {
            std::cerr << "Warning: Invalid or empty file name encountered at position " << fileInfo.position << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error reading file info: " << e.what() << ". Skipping file." << std::endl;
    }
}

void tryParse24(IInStream* stream, FileInfo& fileInfo) {
    // Skip unnecessary data
    seek(stream, 2);  // Skip 2 bytes
    readUint32(stream);  // Discard 4x uint32 metadata
    readUint32(stream);
    readUint32(stream);
    readUint32(stream);
    seek(stream, 16);  // Skip another 16 bytes

    // Now read the file information
    fileInfo.size = readUint32(stream);  // Assuming the size is read here
    fileInfo.type = 0;                   // Set the type to 0 as per the logic in FileInfo

    // Read the file name directly
    std::string fileName;
    char ch;

    // Read until the null terminator is found
    while (readByte(stream, ch) && ch != '\0') {
        fileName += ch;
    }

    // Set the file name in the FileInfo object
    fileInfo.SetFileName(fileName);

    // Display the file name if valid
    if (!fileName.empty()) {
        std::cout << "File name: " << fileName << std::endl;
    }
}

void tryParse30(IInStream* stream, FileInfo& fileInfo) {
    // Skip unnecessary data
    seek(stream, 2);  // Skip 2 bytes
    readUint32(stream);  // Discard 4x uint32 metadata
    readUint32(stream);
    readUint32(stream);
    readUint32(stream);
    seek(stream, 18);  // Skip another 18 bytes

    // Now read the file information
    fileInfo.size = readUint32(stream);  // Assuming the size is read here
    fileInfo.type = 0;                   // Set the type to 0 as per the logic in FileInfo

    // Read the file name directly
    std::string fileName;
    char ch;

    // Read until the null terminator is found
    while (readByte(stream, ch) && ch != '\0') {
        fileName += ch;
    }

    // Set the file name in the FileInfo object
    fileInfo.SetFileName(fileName);

    // Display the file name if valid
    if (!fileName.empty()) {
        std::cout << "File name: " << fileName << std::endl;
    }
}

void tryParse35(IInStream* stream, FileInfo& fileInfo) {
    // Skip unnecessary data
    seek(stream, 22);  // Skip 22 bytes
    readUint32(stream);  // Discard uncompressed size
    readUint32(stream);  // Discard offset
    readUint32(stream);  // Discard compressed size

    // Now read the file information
    fileInfo.size = readUint32(stream);  // Assuming the size is read here
    fileInfo.type = 0;                   // Set the type to 0 as per the logic in FileInfo

    // Read the file name directly
    std::string fileName;
    char ch;

    // Read until the null terminator is found
    while (readByte(stream, ch) && ch != '\0') {
        fileName += ch;
    }

    // Set the file name in the FileInfo object
    fileInfo.SetFileName(fileName);

    // Display the file name if valid
    if (!fileName.empty()) {
        std::cout << "File name: " << fileName << std::endl;
    }
}




void tryParse40(IInStream* stream, FileInfo& fileInfo) {
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
        fileInfo.size = readUint32(stream);  // Read the file size
        fileInfo.type = readUint16(stream);  // Read the file type

        std::cout << "Position: " << fileInfo.position << ", Size: " << fileInfo.size << ", Type: " << fileInfo.type << std::endl;

        // Skip if file type is not 0
        if (fileInfo.type != 0) {
            std::cerr << "Invalid file type detected: " << fileInfo.type << ". Skipping file." << std::endl;
            return;
        }

        // Skip 3 bytes
        stream->Seek(3, STREAM_SEEK_CUR, &streamPos);

        // Peek byte to handle special cases (you can't peek directly in IInStream, so we read the byte)
        char peekByte;
        hr = stream->Read(&peekByte, 1, nullptr);
        if (FAILED(hr)) {
            std::cerr << "Failed to peek byte from stream." << std::endl;
            return;
        }

        std::cout << "Peek byte: " << std::hex << (int)peekByte << std::dec << std::endl;

        if (peekByte == 0xE2) {
            stream->Seek(1, STREAM_SEEK_CUR, &streamPos);  // Skip the peeked byte
            stream->Seek(30, STREAM_SEEK_CUR, &streamPos); // Skip 30 bytes
        }
        else {
            stream->Seek(14, STREAM_SEEK_CUR, &streamPos);  // Skip 14 bytes otherwise

            uint32_t uncompressedSize = readUint32(stream);
            uint32_t offset = readUint32(stream);
            uint32_t compressedSize = readUint32(stream);
            stream->Seek(4, STREAM_SEEK_CUR, &streamPos); // Skip 4 bytes

            fileInfo.SetFileInfos(offset, compressedSize, uncompressedSize);
            fileInfo.SetFileTimes(readInt64(stream), readInt64(stream), readInt64(stream));
        }

        // Ensure we handle the file name properly, taking into account null-terminated strings.
        std::string fileName;
        char ch;

        // Read until the null terminator is found
        while (stream->Read(&ch, 1, nullptr) == S_OK && ch != '\0') {
            fileName += ch;
        }

        // Log the entire file name read
        std::cout << "Full file name read: " << fileName << std::endl;

        // Validate the file name
        if (!fileName.empty()) {
            fileInfo.SetFileName(fileName);  // Set the file name in the file info object
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
