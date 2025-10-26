#define NOMINMAX
#include <windows.h>
#undef min
#undef max
#include <algorithm>
#include <vector>
#include <string>
#include <sstream>
#include <cstdint>
#include <map>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <ctime>
#include <chrono>
#include <shlobj.h>
#include "../ClickTeam/zlib_decoder.h"
#include "../ClickTeam/bzip2_decoder.h"

// Debug logging only in debug builds
#ifdef _DEBUG
static void logDebug(const std::string& message);
static void logDebug(const std::wstring& message);
static void logDebug(const std::wstringstream& wss);
#else
	// No-op in release builds
#define logDebug(...) ((void)0)
#endif

static std::string wideToUtf8(const std::wstring& wstr);

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

class ClickTeamInstallerHandler {
	UInt64 archiveSize;
	uint64_t overlayPos;
	std::vector<char> decompressedData;

	const int BLOCK_HEADER_SIZE = 16 + 16 + 32;
	const std::string DATA_SECTION_SIGNATURE_STR = "\x77\x77\x67\x54\x29\x48";

public:
	struct FileInfo {
		std::streampos position;
		uint32_t size;
		uint32_t type;
		std::string path;
		uint32_t offset;
		uint32_t compressedSize;
		uint32_t uncompressedSize;
		int64_t fileTime1;
		int64_t fileTime2;
		int64_t fileTime3;
		std::vector<uint8_t> decompressedData;

		FileInfo()
			: position(0), size(0), type(0), offset(0), path(""),
			compressedSize(0), uncompressedSize(0), fileTime1(0), fileTime2(0), fileTime3(0) {
		}

		void SetFileInfos(uint32_t offset, uint32_t compressedSize, uint32_t uncompressedSize) {
			this->offset = offset;
			this->compressedSize = compressedSize;
			this->uncompressedSize = uncompressedSize;
		}

		void SetFileTimes(int64_t time1, int64_t time2, int64_t time3) {
			fileTime1 = time1;
			fileTime2 = time2;
			fileTime3 = time3;
		}

		bool IsValid(long fileStreamLength, long offset, long compressedSize,
			long uncompressedSize, long index, const std::wstring& path) {
			if (offset > fileStreamLength ||
				(compressedSize == 0 && uncompressedSize > 3000000000) ||
				(uncompressedSize > 10 && compressedSize > 10 && compressedSize > uncompressedSize * 5) ||
				index > 1000000000 ||
				PathContainsInvalidChars(path)) {
				return false;
			}
			return true;
		}

		static bool PathContainsInvalidChars(const std::wstring& path) {
			for (wchar_t ch : path) {
				if (ch == L'/' || ch == L'\\' || ch == L':' || ch == L'<' ||
					ch == L'>' || ch == L'"' || ch == L'|' || ch == L'?') {
					return true;
				}
			}
			return false;
		}
	};

	std::vector<FileInfo> items;
	CMyComPtr<IArchiveOpenVolumeCallback> volCallback;

	HRESULT Open(IInStream* stream, const UInt64* fileSize, IArchiveOpenCallback* callback);
	HRESULT ParseArchive(IInStream* stream, const std::vector<char>& decompressedData);
	HRESULT unpackStream(IInStream* stream, long dataStreamLength, std::vector<char>& decompressedData,
	std::vector<FileInfo>& filesInfos, int installerVersion);
	HRESULT ExtractFilesFromBlock(IInStream* stream, UInt64 fileDataStart, int installerVersion);
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

static HRESULT readInt64(IInStream* stream, int64_t* value) {
	UInt32 bytesRead = 0;
	return stream->Read(reinterpret_cast<BYTE*>(value), sizeof(int64_t), &bytesRead);
}

static HRESULT readByte(IInStream* stream, char* value) {
	UInt32 bytesRead = 0;
	return stream->Read(reinterpret_cast<BYTE*>(value), sizeof(char), &bytesRead);
}

static void filterInvalidChars(std::vector<char>& decompressedData) {
	for (auto& byte : decompressedData) {
		if (byte < 0 || byte > 255) {
			byte = 0x20;
		}
	}
}

static std::wstring getDesktopPath() {
	wchar_t path[MAX_PATH];
	if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_DESKTOP, nullptr, SHGFP_TYPE_CURRENT, path))) {
		return std::wstring(path);
	}
	return L".";
}

#ifdef _DEBUG
static void logDebug(const std::string& message) {
	static std::string logFilePath;
	if (logFilePath.empty()) {
		std::wstring desktopPath = getDesktopPath();
		std::wstring logPathW = desktopPath + L"\\decompression_debug.log";

		int size_needed = WideCharToMultiByte(CP_UTF8, 0, logPathW.c_str(), -1, nullptr, 0, nullptr, nullptr);
		if (size_needed <= 0) return;

		std::string utf8Path(size_needed - 1, 0);
		WideCharToMultiByte(CP_UTF8, 0, logPathW.c_str(), -1, &utf8Path[0], size_needed - 1, nullptr, nullptr);
		logFilePath = utf8Path;
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
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, message.c_str(), -1, nullptr, 0, nullptr, nullptr);
	if (size_needed <= 0) return;

	std::string utf8Message(size_needed - 1, 0);
	WideCharToMultiByte(CP_UTF8, 0, message.c_str(), -1, &utf8Message[0], size_needed - 1, nullptr, nullptr);
	logDebug(utf8Message);
}

static void logDebug(const std::wstringstream& wss) {
	logDebug(wss.str());
}
#endif // _DEBUG

static std::string wideToUtf8(const std::wstring& wstr) {
	if (wstr.empty()) return {};
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
	if (size_needed <= 1) return {};
	std::string strTo(size_needed - 1, 0);
	WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &strTo[0], size_needed - 1, nullptr, nullptr);
	return strTo;
}

// Version detection
static HRESULT tryParse(IInStream* stream, ClickTeamInstallerHandler::FileInfo& fileInfo, int version) {
	try {
		UInt64 nodeStart = 0;
		stream->Seek(0, STREAM_SEEK_CUR, &nodeStart);
		fileInfo.position = nodeStart;

		// Read node size and type
		if (version == 20) {
			uint32_t nodeSize;
			RINOK(readUint32(stream, &nodeSize));
			fileInfo.size = nodeSize;
		}
		else {
			uint16_t nodeSize;
			RINOK(readUint16(stream, &nodeSize));
			fileInfo.size = nodeSize;
		}

		uint16_t fileType;
		RINOK(readUint16(stream, &fileType));
		fileInfo.type = fileType;

		if (fileInfo.type != 0) return S_OK;

		char peekByte = 0;

		// Handle version-specific skips
		switch (version) {
		case 20: stream->Seek(14, STREAM_SEEK_CUR, nullptr); break;
		case 24: case 30: stream->Seek(2, STREAM_SEEK_CUR, nullptr); break;
		case 35: case 40: stream->Seek(3, STREAM_SEEK_CUR, nullptr); break;
		}

		// Handle 0xE2 marker for empty files (versions 35 & 40)
		if (version == 35 || version == 40) {
			RINOK(readByte(stream, &peekByte));
			if (peekByte == (char)0xE2) {
				stream->Seek(30, STREAM_SEEK_CUR, nullptr);
			}
			else {
				stream->Seek(14, STREAM_SEEK_CUR, nullptr);
			}
		}

		// Read file info
		uint32_t offset = 0, compressedSize = 0, uncompressedSize = 0, unknown = 0;
		switch (version) {
		case 20:
			RINOK(readUint32(stream, &uncompressedSize));
			RINOK(readUint32(stream, &offset));
			RINOK(readUint32(stream, &compressedSize));
			fileInfo.SetFileInfos(offset, compressedSize, uncompressedSize);
			break;
		case 24: case 30: case 35:
			RINOK(readUint32(stream, &offset));
			RINOK(readUint32(stream, &compressedSize));
			RINOK(readUint32(stream, &unknown));
			RINOK(readUint32(stream, &uncompressedSize));
			fileInfo.SetFileInfos(offset, compressedSize, uncompressedSize);
			break;
		case 40:
			if (peekByte != (char)0xE2) {
				RINOK(readUint32(stream, &uncompressedSize));
				RINOK(readUint32(stream, &offset));
				RINOK(readUint32(stream, &compressedSize));
				stream->Seek(4, STREAM_SEEK_CUR, nullptr);
				fileInfo.SetFileInfos(offset, compressedSize, uncompressedSize);
			}
			break;
		}

		// Read index for versions 30, 35
		if (version == 30 || version == 35) {
			uint32_t index;
			RINOK(readUint32(stream, &index));
		}

		// Read file times
		if (!(version == 40 && peekByte == (char)0xE2)) {
			int64_t created, accessed, modified;
			RINOK(readInt64(stream, &created));
			RINOK(readInt64(stream, &accessed));
			RINOK(readInt64(stream, &modified));
			fileInfo.SetFileTimes(created, accessed, modified);
		}

		// Read file path
		std::string fileName;
		char ch;
		while (readByte(stream, &ch) == S_OK && ch != '\0') {
			fileName += ch;
		}
		fileInfo.path = fileName;

		return S_OK;
	}
	catch (const std::exception& e) {
		std::cerr << "Error in tryParse (version " << version << "): " << e.what() << std::endl;
		return E_FAIL;
	}
}

static bool TestInstallerVersion(int version, IInStream* stream, uint16_t fileNumber, long dataStreamLength) {
	const size_t bufferSize = 4096;
	std::vector<BYTE> buffer(bufferSize);
	UInt32 bytesRead = 0;
	HRESULT hr;

	for (int i = 0; i < fileNumber; ++i) {
		try {
			ClickTeamInstallerHandler::FileInfo fileInfo;

			hr = stream->Read(buffer.data(), static_cast<UInt32>(bufferSize), &bytesRead);
			if (FAILED(hr) || bytesRead == 0) {
				return false;
			}

			stream->Seek(0, STREAM_SEEK_SET, nullptr);

			hr = tryParse(stream, fileInfo, version);
			if (FAILED(hr)) {
				return false;
			}

			if (!fileInfo.IsValid(dataStreamLength, fileInfo.offset,
				fileInfo.compressedSize, fileInfo.uncompressedSize,
				i, std::wstring(fileInfo.path.begin(), fileInfo.path.end()))) {
				return false;
			}

			if (fileInfo.type != 0) {
				UInt64 newPos = static_cast<UInt64>(fileInfo.position) + fileInfo.size;
				stream->Seek(newPos, STREAM_SEEK_SET, nullptr);
			}
		}
		catch (const std::exception&) {
			return false;
		}
	}

	return true;
}

static int GetInstallerVersion(IInStream* stream, uint16_t fileNumber, long dataStreamLength) {
	static int installerVersion = -1;

	if (installerVersion > -1)
		return installerVersion;

	std::vector<int> versionsToTry = { 40, 35, 30, 24, 20 };

	for (int version : versionsToTry) {
		ClickTeamInstallerHandler::FileInfo fileInfo;
		stream->Seek(0, STREAM_SEEK_SET, nullptr);

		HRESULT hr = tryParse(stream, fileInfo, version);

		if (SUCCEEDED(hr)) {
			if (TestInstallerVersion(version, stream, fileNumber, dataStreamLength)) {
				installerVersion = version;
				return installerVersion;
			}
		}
	}

	std::cerr << "Failed to determine installer version. Please send a bug report." << std::endl;
	return -1;
}

// Decompression
HRESULT ClickTeamInstallerHandler::unpackStream(IInStream* stream, long dataStreamLength,
	std::vector<char>& decompressedData, std::vector<FileInfo>& filesInfos, int installerVersion) {

	ULONGLONG initialPosition = 0;
	HRESULT hr = stream->Seek(0, STREAM_SEEK_CUR, &initialPosition);
	if (FAILED(hr)) {
		logDebug("[DECOMPRESSION] Failed to get stream position.");
		return E_FAIL;
	}

	uint32_t blockSizeOrDecompressedSize;
	hr = stream->Read(reinterpret_cast<BYTE*>(&blockSizeOrDecompressedSize), sizeof(blockSizeOrDecompressedSize), nullptr);
	if (FAILED(hr)) {
		logDebug("[DECOMPRESSION] Failed to read size field.");
		return E_FAIL;
	}

	uint8_t compressionMethod;
	hr = stream->Read(reinterpret_cast<BYTE*>(&compressionMethod), sizeof(compressionMethod), nullptr);
	if (FAILED(hr)) {
		logDebug("[DECOMPRESSION] Failed to read compression method.");
		return E_FAIL;
	}

	initialPosition += 5;
	std::ostringstream oss;
	oss << "[DECOMPRESSION] Decompressing " << dataStreamLength << " bytes at position " << initialPosition
		<< "\nCompression method: " << static_cast<int>(compressionMethod)
		<< ", Size field: " << blockSizeOrDecompressedSize;
	logDebug(oss.str());

	decompressedData.clear();

	switch (compressionMethod) {
	case NONE:
		logDebug("[DECOMPRESSION] No compression. Copying data directly.");
		{
			size_t uncompressedDataSize = dataStreamLength - 5;
			decompressedData.resize(uncompressedDataSize);
			hr = stream->Read(reinterpret_cast<BYTE*>(decompressedData.data()), uncompressedDataSize, nullptr);
			if (FAILED(hr)) {
				logDebug("[DECOMPRESSION] Failed to read uncompressed data.");
				return E_FAIL;
			}
		}
		break;

	case DEFLATE:
		logDebug("[DECOMPRESSION] DEFLATE compression detected.");
		{
			size_t compressedDataSize = dataStreamLength - 5;
			std::vector<uint8_t> compressedData(compressedDataSize);
			UInt32 bytesRead = 0;
			hr = stream->Read(reinterpret_cast<BYTE*>(compressedData.data()),
				static_cast<UInt32>(compressedData.size()), &bytesRead);
			if (FAILED(hr)) {
				logDebug("[DECOMPRESSION] Failed to read compressed data.");
				return E_FAIL;
			}

			struct DeflateStream {
				size_t offset;
				size_t compressedSize;
				size_t decompressedSize;
				std::vector<uint8_t> data;
			};

			std::vector<DeflateStream> streams;
			size_t offset = 0;
			int streamCount = 0;

			// Decompress all streams individually
			while (offset < compressedData.size()) {
				if (compressedData.size() - offset >= 2 && compressedData[offset] == 0x78) {
					streamCount++;

					ByteVector* output = bytevector_create(compressedDataSize * 2);
					if (!output) {
						logDebug("[DECOMPRESSION] Failed to allocate output buffer.");
						return E_FAIL;
					}

					size_t bytes_consumed = 0;
					int result = zlib_decompress_no_checksum(compressedData.data() + offset,
						compressedData.size() - offset, output, &bytes_consumed);

					if (result < 0) {
						bytevector_free(output);
						break;
					}

					DeflateStream stream;
					stream.offset = offset;
					stream.compressedSize = bytes_consumed;
					stream.decompressedSize = output->length;
					stream.data.assign(output->data, output->data + output->length);
					streams.push_back(stream);

					bytevector_free(output);
					offset += bytes_consumed;

					// Skip Adler-32 checksum (4 bytes)
					if (offset + 4 <= compressedData.size()) {
						offset += 4;
					}
				}
				else {
					// Look for next stream
					bool foundNext = false;
					for (size_t lookahead = 1; lookahead <= 10 && offset + lookahead < compressedData.size(); lookahead++) {
						if (compressedData[offset + lookahead] == 0x78) {
							offset += lookahead;
							foundNext = true;
							break;
						}
					}

					if (!foundNext) break;
				}
			}

			if (streams.empty()) {
				logDebug("[DECOMPRESSION] No streams decompressed!");
				return E_FAIL;
			}

			// Decide which streams to use
			if (streams.size() == 1) {
				decompressedData.assign(streams[0].data.begin(), streams[0].data.end());
			}
			else if (streams.size() >= 2) {
				if (streams[0].decompressedSize < streams[1].decompressedSize / 20) {
					decompressedData.assign(streams[1].data.begin(), streams[1].data.end());
				}
				else if (streams[0].decompressedSize == blockSizeOrDecompressedSize) {
					decompressedData.assign(streams[0].data.begin(), streams[0].data.end());
				}
				else if (streams[1].decompressedSize == blockSizeOrDecompressedSize) {
					decompressedData.assign(streams[1].data.begin(), streams[1].data.end());
				}
				else {
					// Concatenate all streams
					for (const auto& s : streams) {
						decompressedData.insert(decompressedData.end(), s.data.begin(), s.data.end());
					}
				}
			}
		}
		break;

	case BZ2:
		logDebug("[DECOMPRESSION] BZ2 compression detected.");
		{
			size_t compressedDataSize = dataStreamLength - 5;
			std::vector<uint8_t> compressedData(compressedDataSize);
			hr = stream->Read(reinterpret_cast<BYTE*>(compressedData.data()), compressedData.size(), nullptr);
			if (FAILED(hr)) {
				logDebug("[DECOMPRESSION] Failed to read compressed data.");
				return E_FAIL;
			}

			BZ2ByteVector output = { 0 };
			int result = bzip2_decompress(compressedData.data(), compressedData.size(), &output);
			if (result < 0) {
				logDebug("[DECOMPRESSION] Failed to decompress BZ2 data.");
				if (output.data) free(output.data);
				return E_FAIL;
			}

			decompressedData.assign(output.data, output.data + output.length);
			if (output.data) free(output.data);
		}
		break;

	default:
		logDebug("[DECOMPRESSION] Unknown compression method: " + std::to_string(compressionMethod));
		hr = stream->Seek(dataStreamLength - 5, STREAM_SEEK_CUR, nullptr);
		if (FAILED(hr)) {
			logDebug("[DECOMPRESSION] Failed to seek stream position.");
			return E_FAIL;
		}
		return E_FAIL;
	}

	filterInvalidChars(decompressedData);
	logDebug("[DECOMPRESSION] Decompressed data stored successfully.");
	return S_OK;
}

HRESULT ClickTeamInstallerHandler::ParseArchive(IInStream* stream, const std::vector<char>& decompressedData) {
	logDebug(L"Start parsing decompressed data. Data size: " + std::to_wstring(decompressedData.size()));

	this->decompressedData = decompressedData;
	size_t pos = 0;

	// Read file count (2 bytes)
	if (pos + 2 > decompressedData.size()) {
		logDebug(L"Not enough data to read file count");
		return E_FAIL;
	}

	uint16_t fileCount = *reinterpret_cast<const uint16_t*>(&decompressedData[pos]);
	pos += 2;
	pos += 2; // Skip unknown bytes

	logDebug(L"FILE_LIST contains " + std::to_wstring(fileCount) + L" files");

	for (uint16_t i = 0; i < fileCount; i++) {
		FileInfo fileInfo;
		size_t nodeStart = pos;

		if (pos + 2 > decompressedData.size()) break;

		uint16_t nodeSize = *reinterpret_cast<const uint16_t*>(&decompressedData[pos]);
		pos += 2;

		if (pos + 2 > decompressedData.size()) break;
		uint16_t fileType = *reinterpret_cast<const uint16_t*>(&decompressedData[pos]);
		pos += 2;

		fileInfo.size = nodeSize;
		fileInfo.type = fileType;
		fileInfo.position = nodeStart;

		size_t nodeEnd = nodeStart + nodeSize;

		if (fileType != 0) {
			pos = nodeEnd;
			continue;
		}

		pos += 2; // Skip unknown

		if (pos + 16 > decompressedData.size()) break;
		uint32_t offset = *reinterpret_cast<const uint32_t*>(&decompressedData[pos]); pos += 4;
		uint32_t compressedSize = *reinterpret_cast<const uint32_t*>(&decompressedData[pos]); pos += 4;
		uint32_t unknown32 = *reinterpret_cast<const uint32_t*>(&decompressedData[pos]); pos += 4;
		uint32_t uncompressedSize = *reinterpret_cast<const uint32_t*>(&decompressedData[pos]); pos += 4;

		fileInfo.offset = offset;
		fileInfo.compressedSize = compressedSize;
		fileInfo.uncompressedSize = uncompressedSize;

		pos += 18; // Skip unknown

		if (pos + 4 > decompressedData.size()) break;
		uint32_t index = *reinterpret_cast<const uint32_t*>(&decompressedData[pos]); pos += 4;

		if (pos + 24 > decompressedData.size()) break;
		int64_t created = *reinterpret_cast<const int64_t*>(&decompressedData[pos]); pos += 8;
		int64_t accessed = *reinterpret_cast<const int64_t*>(&decompressedData[pos]); pos += 8;
		int64_t modified = *reinterpret_cast<const int64_t*>(&decompressedData[pos]); pos += 8;

		fileInfo.SetFileTimes(created, accessed, modified);

		// Read null-terminated path
		std::string filePath;
		while (pos < nodeEnd && decompressedData[pos] != '\0') {
			filePath += decompressedData[pos];
			pos++;
		}
		if (pos < nodeEnd && decompressedData[pos] == '\0') pos++;

		fileInfo.path = filePath;
		pos = nodeEnd;

		if (!filePath.empty()) {
			this->items.push_back(fileInfo);
		}
	}

	logDebug(L"Successfully parsed " + std::to_wstring(this->items.size()) + L" file entries");
	return S_OK;
}

HRESULT ClickTeamInstallerHandler::Open(IInStream* stream, const UInt64* fileSize, IArchiveOpenCallback* callback) {
	if (!callback || !stream) {
		logDebug("Error: Invalid stream or callback in Open()");
		return S_FALSE;
	}

	HRESULT result = callback->QueryInterface(IID_IArchiveOpenVolumeCallback, (void**)&volCallback);
	RINOK(result);

	if (!volCallback) {
		logDebug("Error: Failed to get volume callback interface.");
		return E_FAIL;
	}

	UInt64 streamLength;
	RINOK(stream->Seek(0, STREAM_SEEK_END, &streamLength));
	RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));

	uint16_t fileNumber = 0;
	int installerVersion = GetInstallerVersion(stream, fileNumber, streamLength);
	if (installerVersion == -1) {
		logDebug("Error: Failed to detect installer version!");
		return E_FAIL;
	}

	UInt64 position = DATA_SECTION_SIGNATURE_STR.size();
	RINOK(stream->Seek(position, STREAM_SEEK_SET, nullptr));

	while (position + BLOCK_HEADER_SIZE <= streamLength) {
		uint16_t blockId;
		uint32_t blockSize;
		RINOK(stream->Read(reinterpret_cast<BYTE*>(&blockId), sizeof(blockId), nullptr));
		position += sizeof(blockId);

		stream->Seek(2, STREAM_SEEK_CUR, nullptr);
		position += 2;

		RINOK(stream->Read(reinterpret_cast<BYTE*>(&blockSize), sizeof(blockSize), nullptr));
		position += sizeof(blockSize);

		uint64_t nextBlockPos = position + blockSize;
		if (nextBlockPos > streamLength || blockSize == 0 || blockSize > INT_MAX) {
			logDebug("Error: Invalid block size or position!");
			break;
		}

		RINOK(stream->Seek(position, STREAM_SEEK_SET, nullptr));
		BLOCK_TYPE blockType = static_cast<BLOCK_TYPE>(blockId);

		if (blockType == FILE_LIST) {
			UInt64 totalSize = streamLength;
			RINOK(callback->SetTotal(nullptr, &totalSize));

			std::vector<char> fileListData;
			std::vector<FileInfo> fileInfos;

			RINOK(unpackStream(stream, blockSize, fileListData, fileInfos, installerVersion));
			RINOK(ParseArchive(stream, fileListData));

		}
		else if (blockType == FILE_DATA) {
			RINOK(ExtractFilesFromBlock(stream, position, installerVersion));
		}

		position = nextBlockPos;
		RINOK(stream->Seek(position, STREAM_SEEK_SET, nullptr));
	}

	logDebug("Archive parsed. Total items: " + std::to_string(items.size()));
	for (const auto& item : items) {
		logDebug("  " + item.path + ": " + std::to_string(item.decompressedData.size()) + " bytes");
	}

	return S_OK;
}

HRESULT ClickTeamInstallerHandler::ExtractFilesFromBlock(IInStream* stream, UInt64 fileDataStart, int installerVersion) {
	if (items.empty()) {
		return S_OK;
	}

	for (auto& item : items) {
		UInt64 absoluteOffset = fileDataStart + item.offset;

		logDebug("Extracting: " + item.path);
		logDebug("  Offset: " + std::to_string(absoluteOffset));
		logDebug("  Compressed: " + std::to_string(item.compressedSize));
		logDebug("  Uncompressed: " + std::to_string(item.uncompressedSize));

		// Seek to file data (skip 4-byte header, read compression method)
		RINOK(stream->Seek(absoluteOffset + 4, STREAM_SEEK_SET, nullptr));

		uint8_t compressionMethod;
		RINOK(stream->Read(&compressionMethod, 1, nullptr));

		// Currently only DEFLATE is supported
		if (compressionMethod != DEFLATE) {
			logDebug("  Unsupported compression method: " + std::to_string(compressionMethod));
			continue;
		}

		// Read compressed data (after 4-byte header + 1-byte compression method)
		uint32_t compressedDataSize = item.compressedSize - 5;
		std::vector<uint8_t> compressedData(compressedDataSize);

		UInt32 bytesRead = 0;
		HRESULT hr = stream->Read(compressedData.data(), compressedDataSize, &bytesRead);
		if (FAILED(hr) || bytesRead != compressedDataSize) {
			logDebug("  Failed to read compressed data");
			continue;
		}

		// Verify zlib header
		if (compressedData.size() < 2 || compressedData[0] != 0x78) {
			logDebug("  Missing zlib header");
			continue;
		}

		// Decompress
		ByteVector* output = bytevector_create(item.uncompressedSize * 2);
		if (!output) {
			logDebug("  Failed to allocate buffer");
			continue;
		}

		size_t bytes_consumed = 0;
		int result = zlib_decompress_no_checksum(compressedData.data(), compressedData.size(),
			output, &bytes_consumed);

		if (output->length > 0) {
			item.decompressedData.assign(output->data, output->data + output->length);
			item.uncompressedSize = output->length;

			logDebug("  SUCCESS: Decompressed " + std::to_string(output->length) + " bytes" +
				(result < 0 ? " (with warnings)" : ""));
		}
		else {
			logDebug("  FAILED: Decompression produced no output");
		}

		bytevector_free(output);
	}

	return S_OK;
}