#define NOMINMAX
#include <windows.h>
#undef min
#undef max
#include <algorithm>
#include <vector>
#include <string>
#include <sstream>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <ctime>
#include <chrono>

// Forward declarations
#ifdef _DEBUG
static void logDebug(const std::string& message);
static void logDebug(const std::wstring& message);
#else
#define logDebug(...) ((void)0)
#endif

// Constants
static const char* ISSIG = "InstallShield";
static const char* ISSIG_STRM = "ISSetupStream";
static const uint8_t MAGIC_DEC[4] = { 0x13, 0x35, 0x86, 0x07 };

enum CompressionType {
	CT_NONE = 0,
	CT_DEFLATE = 1
};

#pragma pack(push, 1)
// Archive header (46 bytes, 0x2E)
struct IS_HEADER {
	char signature[14];
	uint16_t num_files;
	uint32_t type;
	uint8_t x4[8];
	uint16_t x5;
	uint8_t x6[16];
};

// File attributes (312 bytes, 0x138)
struct IS_FILE_ATTRIBUTES {
	char file_name[260]; // MAX_PATH
	uint32_t encoded_flags;
	uint32_t x3;
	uint32_t file_len;
	uint8_t x5[8];
	uint16_t is_unicode_launcher;
	uint8_t x7[30];
};

// ISSetupStream attributes (24 bytes, 0x18)
struct IS_FILE_ATTRIBUTES_X {
	uint32_t filename_len;
	uint32_t encoded_flags;
	uint8_t x3[2];
	uint32_t file_len;
	uint8_t x5[8];
	uint16_t is_unicode_launcher;
};
#pragma pack(pop)

class InstallShieldHandler {
public:
	struct FileInfo {
		std::string path;
		uint32_t offset;
		uint32_t compressedSize;
		uint32_t uncompressedSize;
		uint32_t encodedFlags;
		uint16_t isUnicodeLauncher;
		int64_t creationTime;
		int64_t accessTime;
		int64_t modificationTime;
		std::vector<uint8_t> decompressedData;

		FileInfo() : offset(0), compressedSize(0), uncompressedSize(0),
			encodedFlags(0), isUnicodeLauncher(0),
			creationTime(0), accessTime(0), modificationTime(0) {
		}
	};

	std::vector<FileInfo> items;
	CMyComPtr<IArchiveOpenVolumeCallback> volCallback;

	HRESULT Open(IInStream* stream, const UInt64* fileSize, IArchiveOpenCallback* callback);

private:
	uint32_t dataOffset;
	IS_HEADER header;
	bool isStreamFormat;
	std::vector<uint8_t> currentKey;

	// Helper methods
	HRESULT FindDataOffset(IInStream* stream);
	HRESULT ReadHeader(IInStream* stream);
	HRESULT ParseFileList(IInStream* stream);
	HRESULT ReadFileAttributes(IInStream* stream, FileInfo& fileInfo);
	HRESULT ReadFileAttributesStream(IInStream* stream, FileInfo& fileInfo);
	HRESULT ExtractFileData(IInStream* stream, FileInfo& fileInfo);

	std::vector<uint8_t> GenerateKey(const std::string& seed);
	void DecodeData(uint8_t* data, uint32_t dataLen, uint32_t offset,
		const std::vector<uint8_t>& key);
	void DecodeDataStream(uint8_t* data, uint32_t dataLen, uint32_t offset,
		const std::vector<uint8_t>& key);
	uint8_t DecodeByte(uint8_t byte, uint8_t key);
};

// Utility functions
static HRESULT readUint32(IInStream* stream, uint32_t* value) {
	UInt32 bytesRead = 0;
	return stream->Read(reinterpret_cast<BYTE*>(value), sizeof(uint32_t), &bytesRead);
}

static HRESULT readUint16(IInStream* stream, uint16_t* value) {
	UInt32 bytesRead = 0;
	return stream->Read(reinterpret_cast<BYTE*>(value), sizeof(uint16_t), &bytesRead);
}

static std::wstring Utf8ToWide(const std::string& utf8) {
	if (utf8.empty()) return L"";
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
	if (size_needed <= 0) return L"";
	std::wstring wstr(size_needed - 1, 0);
	MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &wstr[0], size_needed - 1);
	return wstr;
}

static std::string WideToUtf8(const std::wstring& wstr) {
	if (wstr.empty()) return "";
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
	if (size_needed <= 0) return "";
	std::string utf8(size_needed - 1, 0);
	WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &utf8[0], size_needed - 1, nullptr, nullptr);
	return utf8;
}

std::string GetDesktopPath() {
	char* userProfile = nullptr;
	size_t len = 0;
	errno_t err = _dupenv_s(&userProfile, &len, "USERPROFILE");
	if (err || !userProfile) {
		return "C:\\Desktop"; // fallback
	}

	std::string desktopPath = std::string(userProfile) + "\\Desktop";
	free(userProfile);
	return desktopPath;
}

#ifdef _DEBUG
static void logDebug(const std::string& message) {
	static std::string logFilePath;
	if (logFilePath.empty()) {
		logFilePath = GetDesktopPath() + "\\installshield_debug.log";
	}

	std::ofstream logFile(logFilePath, std::ios::app);
	if (!logFile.is_open()) return;

	auto now = std::chrono::system_clock::now();
	std::time_t now_c = std::chrono::system_clock::to_time_t(now);
	char timeStr[64] = {};
	ctime_s(timeStr, sizeof(timeStr), &now_c);
	timeStr[strcspn(timeStr, "\n")] = 0;

	logFile << "[" << timeStr << "] " << message << "\n";
}

static void logDebug(const std::wstring& message) {
	// Simple UTF-8 conversion
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, message.c_str(), (int)message.size(), nullptr, 0, nullptr, nullptr);
	std::string utf8(size_needed, 0); // allocate writable buffer
	WideCharToMultiByte(CP_UTF8, 0, message.c_str(), (int)message.size(), &utf8[0], size_needed, nullptr, nullptr);

	logDebug(utf8);
}

#endif


// InstallShieldHandler implementation
std::vector<uint8_t> InstallShieldHandler::GenerateKey(const std::string& seed) {
	std::vector<uint8_t> key(seed.size());
	for (size_t i = 0; i < seed.size(); i++) {
		key[i] = static_cast<uint8_t>(seed[i]) ^ MAGIC_DEC[i % 4];
	}
	return key;
}

uint8_t InstallShieldHandler::DecodeByte(uint8_t byte, uint8_t key) {
	return ~(key ^ (byte * 16 | byte >> 4));
}

void InstallShieldHandler::DecodeData(uint8_t* data, uint32_t dataLen,
	uint32_t offset, const std::vector<uint8_t>& key) {
	if (key.empty()) return;
	for (uint32_t i = 0; i < dataLen; i++) {
		data[i] = DecodeByte(data[i], key[(i + offset) % key.size()]);
	}
}

void InstallShieldHandler::DecodeDataStream(uint8_t* data, uint32_t dataLen,
	uint32_t offset, const std::vector<uint8_t>& key) {
	if (key.empty()) return;

	uint32_t decodedLen = 0;
	while (decodedLen < dataLen) {
		uint32_t decodeStart = (decodedLen + offset) % 1024;
		uint32_t taskLen = 1024 - decodeStart;
		uint32_t leftLen = dataLen - decodedLen;
		if (taskLen > leftLen) taskLen = leftLen;

		DecodeData(data + decodedLen, taskLen, decodeStart % key.size(), key);
		decodedLen += taskLen;
	}
}

HRESULT InstallShieldHandler::FindDataOffset(IInStream* stream) {
	// Read DOS header
	IMAGE_DOS_HEADER dosHeader;
	UInt32 bytesRead = 0;
	RINOK(stream->Read(&dosHeader, sizeof(dosHeader), &bytesRead));

	if (dosHeader.e_magic != 0x5A4D) {
		logDebug("Not a valid PE file (DOS signature mismatch)");
		return S_FALSE;
	}

	// Read PE header
	RINOK(stream->Seek(dosHeader.e_lfanew, STREAM_SEEK_SET, nullptr));
	IMAGE_NT_HEADERS32 peHeader;
	RINOK(stream->Read(&peHeader, sizeof(peHeader), &bytesRead));

	if (peHeader.Signature != 0x4550) {
		logDebug("Not a valid PE file (PE signature mismatch)");
		return S_FALSE;
	}

	// Handle 64-bit executables
	if (peHeader.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ||
		peHeader.FileHeader.Machine == 0xAA64) { // ARM64
		RINOK(stream->Seek(sizeof(IMAGE_NT_HEADERS64) - sizeof(IMAGE_NT_HEADERS32),
			STREAM_SEEK_CUR, nullptr));
	}

	// Jump to last section header
	RINOK(stream->Seek((peHeader.FileHeader.NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER),
		STREAM_SEEK_CUR, nullptr));

	IMAGE_SECTION_HEADER sectionHeader;
	RINOK(stream->Read(&sectionHeader, sizeof(sectionHeader), &bytesRead));

	dataOffset = sectionHeader.PointerToRawData + sectionHeader.SizeOfRawData;

	logDebug("Data offset found at: 0x" + std::to_string(dataOffset));
	return S_OK;
}

HRESULT InstallShieldHandler::ReadHeader(IInStream* stream) {
	RINOK(stream->Seek(dataOffset, STREAM_SEEK_SET, nullptr));

	UInt32 bytesRead = 0;
	RINOK(stream->Read(&header, sizeof(IS_HEADER), &bytesRead));

	if (bytesRead != sizeof(IS_HEADER)) {
		logDebug("Failed to read header");
		return S_FALSE;
	}

	isStreamFormat = (strcmp(header.signature, ISSIG_STRM) == 0);

	if (strcmp(header.signature, ISSIG) != 0 && !isStreamFormat) {
		logDebug("Invalid InstallShield signature");
		return S_FALSE;
	}

	if (header.type > 4) {
		logDebug("Unsupported InstallShield type: " + std::to_string(header.type));
		return S_FALSE;
	}

	logDebug("Header: " + std::string(header.signature) +
		", Files: " + std::to_string(header.num_files) +
		", Type: " + std::to_string(header.type));

	dataOffset += sizeof(IS_HEADER);
	return S_OK;
}

HRESULT InstallShieldHandler::ReadFileAttributes(IInStream* stream, FileInfo& fileInfo) {
	IS_FILE_ATTRIBUTES attr;
	UInt32 bytesRead = 0;
	RINOK(stream->Read(&attr, sizeof(attr), &bytesRead));

	if (bytesRead != sizeof(attr)) {
		return S_FALSE;
	}

	fileInfo.path = attr.file_name;
	fileInfo.encodedFlags = attr.encoded_flags;
	fileInfo.compressedSize = attr.file_len;
	fileInfo.uncompressedSize = attr.file_len;
	fileInfo.isUnicodeLauncher = attr.is_unicode_launcher;

	return S_OK;
}

HRESULT InstallShieldHandler::ReadFileAttributesStream(IInStream* stream, FileInfo& fileInfo) {
	IS_FILE_ATTRIBUTES_X attrX;
	UInt32 bytesRead = 0;
	RINOK(stream->Read(&attrX, sizeof(attrX), &bytesRead));

	if (bytesRead != sizeof(attrX) || attrX.filename_len == 0 || attrX.filename_len >= 520) {
		return S_FALSE;
	}

	// Skip extra data for type 4
	if (header.type == 4) {
		RINOK(stream->Seek(sizeof(IS_FILE_ATTRIBUTES_X), STREAM_SEEK_CUR, nullptr));
	}

	// Read unicode filename
	std::vector<wchar_t> filenameW(attrX.filename_len / 2 + 1);
	RINOK(stream->Read(filenameW.data(), attrX.filename_len, &bytesRead));

	if (bytesRead != attrX.filename_len) {
		return S_FALSE;
	}

	fileInfo.path = WideToUtf8(filenameW.data());
	fileInfo.encodedFlags = attrX.encoded_flags;
	fileInfo.compressedSize = attrX.file_len;
	fileInfo.uncompressedSize = attrX.file_len;
	fileInfo.isUnicodeLauncher = attrX.is_unicode_launcher;

	return S_OK;
}

HRESULT InstallShieldHandler::ParseFileList(IInStream* stream) {
	RINOK(stream->Seek(dataOffset, STREAM_SEEK_SET, nullptr));

	for (uint16_t i = 0; i < header.num_files; i++) {
		FileInfo fileInfo;

		HRESULT hr;
		if (isStreamFormat) {
			hr = ReadFileAttributesStream(stream, fileInfo);
		}
		else {
			hr = ReadFileAttributes(stream, fileInfo);
		}

		if (FAILED(hr)) {
			logDebug("Failed to read file attributes for file " + std::to_string(i));
			continue;
		}

		// Store current position
		UInt64 currentPos = 0;
		stream->Seek(0, STREAM_SEEK_CUR, &currentPos);
		fileInfo.offset = static_cast<uint32_t>(currentPos);

		// Skip file data
		RINOK(stream->Seek(fileInfo.compressedSize, STREAM_SEEK_CUR, nullptr));

		logDebug("File " + std::to_string(i) + ": " + fileInfo.path +
			" (" + std::to_string(fileInfo.compressedSize) + " bytes)");

		items.push_back(fileInfo);
	}

	return S_OK;
}

HRESULT InstallShieldHandler::ExtractFileData(IInStream* stream, FileInfo& fileInfo) {
	if (fileInfo.compressedSize == 0) {
		return S_OK;
	}

	// Read compressed data
	std::vector<uint8_t> compressedData(fileInfo.compressedSize);
	RINOK(stream->Seek(fileInfo.offset, STREAM_SEEK_SET, nullptr));

	UInt32 bytesRead = 0;
	RINOK(stream->Read(compressedData.data(), fileInfo.compressedSize, &bytesRead));

	if (bytesRead != fileInfo.compressedSize) {
		logDebug("Failed to read complete file data for: " + fileInfo.path);
		return S_FALSE;
	}

	// Check if file needs decoding
	bool hasType2Or4 = fileInfo.encodedFlags & 6;
	bool hasType4 = fileInfo.encodedFlags & 4;

	if (hasType4 && hasType2Or4) {
		// Generate decryption key
		std::string seed = isStreamFormat ? fileInfo.path : fileInfo.path;
		currentKey = GenerateKey(seed);

		// Decode in 1024-byte blocks
		if (isStreamFormat) {
			DecodeDataStream(compressedData.data(), compressedData.size(), 0, currentKey);
		}
		else {
			DecodeData(compressedData.data(), compressedData.size(), 0, currentKey);
		}

		logDebug("Decoded file: " + fileInfo.path);
	}

	// Store decompressed data
	fileInfo.decompressedData = compressedData;
	fileInfo.uncompressedSize = compressedData.size();

	return S_OK;
}

HRESULT InstallShieldHandler::Open(IInStream* stream, const UInt64* fileSize,
	IArchiveOpenCallback* callback) {
	if (!callback || !stream) {
		logDebug("Invalid stream or callback");
		return S_FALSE;
	}

	// Get volume callback interface
	HRESULT result = callback->QueryInterface(IID_IArchiveOpenVolumeCallback, (void**)&volCallback);
	RINOK(result);

	if (!volCallback) {
		logDebug("Failed to get volume callback interface");
		return E_FAIL;
	}

	// Get stream length
	UInt64 streamLength;
	RINOK(stream->Seek(0, STREAM_SEEK_END, &streamLength));
	RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));

	// Find data offset (after PE sections)
	RINOK(FindDataOffset(stream));

	if (dataOffset >= streamLength) {
		logDebug("No extra data found in file");
		return S_FALSE;
	}

	// Read InstallShield header
	RINOK(ReadHeader(stream));

	// Parse file list
	RINOK(ParseFileList(stream));

	// Extract all files
	for (auto& item : items) {
		HRESULT hr = ExtractFileData(stream, item);
		if (FAILED(hr)) {
			logDebug("Failed to extract: " + item.path);
		}
	}

	logDebug("Archive parsed successfully. Total items: " + std::to_string(items.size()));
	return S_OK;
}