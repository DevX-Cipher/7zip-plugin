#pragma once
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "IArchive.h"
#include "MyCom.h"
#include <chrono>
#include "lzmadecoder.h"  

namespace {
	inline void DbgLog(const char* fmt, ...)
	{
		char buf[512];
		va_list args;
		va_start(args, fmt);
		vsnprintf(buf, sizeof(buf), fmt, args);
		va_end(args);
		OutputDebugStringA(buf);
	}
}


class InnoSetupInstallerHandler {
public:
	struct FileInfo {
		std::string path;
		uint64_t uncompressedSize = 0;
		uint64_t compressedSize = 0;
		std::string sha256Hex;
		std::vector<uint8_t> decompressedData;

		bool hasChunkData = false;
		UInt64 chunkFileOffset = 0;
		int64_t chunkStreamCompressedSize = 0;
		int64_t chunkSubOffset = 0;
	};

	std::string version;
	std::vector<FileInfo> items;

	HRESULT Open(IInStream* stream, const UInt64* maxCheckStartPosition, IArchiveOpenCallback* callback);
	void Close();

	const std::vector<uint8_t>* GetFileData(size_t index);

private:

	IInStream* m_stream = nullptr;
	UInt64 m_fileSize = 0;

	std::map<UInt64, std::vector<char>> m_chunkCache;

	UInt64 GetSize();
	bool ReadArray(UInt64 offset, UInt64 size, std::vector<char>& out);
	uint8_t ReadU8(UInt64 offset);
	uint16_t ReadU16LE(UInt64 offset);
	uint32_t ReadU32LE(UInt64 offset);
	uint64_t ReadU64LE(UInt64 offset);

	int64_t FindUtf8String(UInt64 offset, UInt64 size, const std::string& needle);
	int64_t FindByteArray(UInt64 offset, UInt64 size, const uint8_t* pattern, size_t patternSize);

	struct InternalInfo {
		bool isValid = false;
		UInt64 signatureOffset = 0;
		std::string version;
	};

	struct OffsetTable {
		bool isValid = false;
		UInt64 tableOffset = 0;
		uint32_t revision = 0;
		uint32_t headerOffset = 0;
		uint32_t dataOffset = 0;
	};

	struct DataEntry {
		int64_t chunkSubOffset = 0;
		int64_t originalSize = 0;
		int64_t chunkCompressedSize = 0;
		std::vector<uint8_t> sha256;  // 32 bytes
	};

	struct FileEntry {
		std::string destName;
		int32_t locationEntry = -1;
	};

	struct ChunkInfo {
		int64_t chunkCompressedSize = 0;
		UInt64 chunkFileOffset = 0;
		std::vector<int32_t> entryIndices;
	};

	InternalInfo Analyse();

	OffsetTable FindOffsetTable();                                           // _findOffsetTable
	std::vector<char> StripCRCChunks(const std::vector<char>& data);         // _stripCRCChunks
	std::vector<char> DecompressLZMA1(const std::vector<char>& data);        // _decompressLZMA1
	std::vector<char> ReadBlockStream(UInt64 offset, UInt64* consumed);      // _readBlockStream
	std::string ReadWideString(const std::vector<char>& data, int32_t offset, int32_t* newOffset);  // _readWideString
	std::vector<DataEntry> ParseDataEntries(const std::vector<char>& block2);                        // _parseDataEntries
	std::vector<FileEntry> ParseFileEntries(const std::vector<char>& block1, int32_t numFiles);       // _parseFileEntries
	bool ParseRealInnoSetup(UInt64 signatureOffset);                                                  // _parseRealInnoSetup
	std::vector<char> DecompressDataChunk(UInt64 chunkOffset, int64_t chunkCompressedSize);           // _decompressDataChunk

	bool ParseSyntheticFileEntries(UInt64 signatureOffset);
};

namespace {

	const uint8_t g_aRDlPtSMagic[] = { 0x72, 0x44, 0x6C, 0x50, 0x74, 0x53, 0xCD, 0xE6, 0xD7, 0x7B, 0x0B, 0x2A };
	const size_t g_nRDlPtSMagicSize = 12;

	bool isSpaceChar(char c)
	{
		return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
	}

}  // namespace


UInt64 InnoSetupInstallerHandler::GetSize()
{
	if (m_fileSize != 0) return m_fileSize;
	if (!m_stream) return 0;

	UInt64 size = 0;
	m_stream->Seek(0, STREAM_SEEK_END, &size);
	m_fileSize = size;
	return size;
}

bool InnoSetupInstallerHandler::ReadArray(UInt64 offset, UInt64 size, std::vector<char>& out)
{
	out.clear();

	if (!m_stream || size == 0) return false;
	if (FAILED(m_stream->Seek(offset, STREAM_SEEK_SET, nullptr))) return false;

	out.resize((size_t)size);

	size_t totalRead = 0;
	while (totalRead < size) {
		UInt32 chunkRead = 0;
		HRESULT hr = m_stream->Read(out.data() + totalRead, (UInt32)(size - totalRead), &chunkRead);
		if (FAILED(hr) || chunkRead == 0) break;
		totalRead += chunkRead;
	}

	out.resize(totalRead);
	return totalRead > 0;
}

uint8_t InnoSetupInstallerHandler::ReadU8(UInt64 offset)
{
	std::vector<char> data;
	if (!ReadArray(offset, 1, data) || data.size() != 1) return 0;
	return (uint8_t)data[0];
}

uint16_t InnoSetupInstallerHandler::ReadU16LE(UInt64 offset)
{
	std::vector<char> data;
	if (!ReadArray(offset, 2, data) || data.size() != 2) return 0;
	return (uint16_t)((uint8_t)data[0] | ((uint16_t)(uint8_t)data[1] << 8));
}

uint32_t InnoSetupInstallerHandler::ReadU32LE(UInt64 offset)
{
	std::vector<char> data;
	if (!ReadArray(offset, 4, data) || data.size() != 4) return 0;
	return (uint8_t)data[0] | ((uint32_t)(uint8_t)data[1] << 8) | ((uint32_t)(uint8_t)data[2] << 16) | ((uint32_t)(uint8_t)data[3] << 24);
}

uint64_t InnoSetupInstallerHandler::ReadU64LE(UInt64 offset)
{
	std::vector<char> data;
	if (!ReadArray(offset, 8, data) || data.size() != 8) return 0;
	uint64_t v = 0;
	for (int i = 0; i < 8; i++) {
		v |= ((uint64_t)(uint8_t)data[i]) << (8 * i);
	}
	return v;
}

int64_t InnoSetupInstallerHandler::FindUtf8String(UInt64 offset, UInt64 size, const std::string& needle)
{
	if (needle.empty()) return -1;
	return FindByteArray(offset, size, (const uint8_t*)needle.data(), needle.size());
}

int64_t InnoSetupInstallerHandler::FindByteArray(UInt64 offset, UInt64 size, const uint8_t* pattern, size_t patternSize)
{
	if (!m_stream || patternSize == 0) return -1;

	const UInt64 chunkSize = 1 << 24;
	UInt64 overlap = (patternSize > 0) ? (UInt64)(patternSize - 1) : 0;
	UInt64 pos = offset;
	UInt64 end = offset + size;


	int32_t nIterations = 0;

	while (pos < end) {
		nIterations++;
		if ((nIterations % 4) == 0) {
		}

		UInt64 readSize = std::min<UInt64>(chunkSize, end - pos);
		std::vector<char> data;
		if (!ReadArray(pos, readSize, data) || data.empty()) {
			break;
		}

		if (data.size() >= patternSize) {
			auto it = std::search(data.begin(), data.end(), (const char*)pattern, (const char*)pattern + patternSize);
			if (it != data.end()) {
				return (int64_t)(pos + std::distance(data.begin(), it));
			}
		}

		if (data.size() < readSize) {
			break;
		}

		UInt64 nAdvance = (readSize > overlap) ? (readSize - overlap) : readSize;
		if (nAdvance == 0) nAdvance = 1;
		pos += nAdvance;
	}
	return -1;
}

InnoSetupInstallerHandler::InternalInfo InnoSetupInstallerHandler::Analyse()
{
	InternalInfo result;

	const char* apszSignatures[] = { "Inno Setup Setup Data", "Inno Setup: Setup Data" };
	const int32_t nSignatureCount = 2;
	UInt64 nFileSize = GetSize();

	const UInt64 nQuickScanLimit = (UInt64)16 * 1024 * 1024;
	UInt64 nFirstPassSize = (nFileSize < nQuickScanLimit) ? nFileSize : nQuickScanLimit;

	for (int32_t i = 0; (i < nSignatureCount) && (!result.isValid); i++) {
		std::string sSignature = apszSignatures[i];

		int64_t nOffset = FindUtf8String(0, nFirstPassSize, sSignature);

		if (nOffset != -1) {
			result.isValid = true;
			result.signatureOffset = (UInt64)nOffset;

			const int32_t nWindowSize = 0x80;
			int64_t nRemaining = (int64_t)nFileSize - nOffset;
			if (nRemaining < 0) nRemaining = 0;

			int64_t nBytesToRead = (nRemaining < (int64_t)nWindowSize)
				? nRemaining
				: (int64_t)nWindowSize;

			if (nBytesToRead > 0) {
				std::vector<char> baData;
				ReadArray((UInt64)nOffset, (UInt64)nBytesToRead, baData);
				std::string sWindow(baData.begin(), baData.end());

				size_t nLeftBracket = sWindow.find('(');
				if (nLeftBracket != std::string::npos) {
					size_t nRightBracket = sWindow.find(')', nLeftBracket + 1);
					if ((nRightBracket != std::string::npos) && (nRightBracket > nLeftBracket)) {
						std::string sVersionCandidate =
							sWindow.substr(nLeftBracket + 1, nRightBracket - nLeftBracket - 1);

						size_t nStart = sVersionCandidate.find_first_not_of(" \t\r\n");
						size_t nEnd = sVersionCandidate.find_last_not_of(" \t\r\n");

						if (nStart != std::string::npos) {
							sVersionCandidate =
								sVersionCandidate.substr(nStart, nEnd - nStart + 1);
						}
						else {
							sVersionCandidate.clear();
						}

						result.version = sVersionCandidate;
					}
				}


				if (result.version.empty()) {
					size_t nSignaturePos = sWindow.find(sSignature);
					if (nSignaturePos != std::string::npos) {
						int32_t nSearchPos = (int32_t)(nSignaturePos + sSignature.size());
						while ((nSearchPos < (int32_t)sWindow.size()) && isSpaceChar(sWindow[nSearchPos])) {
							nSearchPos++;
						}
						if ((nSearchPos < (int32_t)sWindow.size()) && (sWindow[nSearchPos] == 'v')) {
							nSearchPos++;
						}
						int32_t nVersionStart = nSearchPos;
						while ((nSearchPos < (int32_t)sWindow.size()) &&
							(isdigit((unsigned char)sWindow[nSearchPos]) || (sWindow[nSearchPos] == '.') || (sWindow[nSearchPos] == '_'))) {
							nSearchPos++;
						}
						if (nSearchPos > nVersionStart) {
							result.version = sWindow.substr(nVersionStart, nSearchPos - nVersionStart);
						}
					}
				}
			}
		}
	}

	return result;
}

InnoSetupInstallerHandler::OffsetTable InnoSetupInstallerHandler::FindOffsetTable()
{
	OffsetTable result;
	result.isValid = false;

	UInt64 nFileSize = GetSize();

	const UInt64 nQuickScanLimit = (UInt64)16 * 1024 * 1024;
	UInt64 nFirstPassSize = (nFileSize < nQuickScanLimit) ? nFileSize : nQuickScanLimit;

	int64_t nTableOffset = FindByteArray(0, nFirstPassSize, g_aRDlPtSMagic, g_nRDlPtSMagicSize);

	if (nTableOffset == -1) {
		return result;
	}

	UInt64 nDataOffset = (UInt64)nTableOffset + g_nRDlPtSMagicSize;

	if (nDataOffset + 52 > nFileSize) {
		return result;
	}

	result.tableOffset = (UInt64)nTableOffset;
	result.revision = ReadU32LE(nDataOffset + 0);

	UInt64 nSizeForCheck = GetSize();

	uint32_t nHeaderOffsetOld = ReadU32LE(nDataOffset + 20);
	uint32_t nDataOffsetOld = ReadU32LE(nDataOffset + 24);
	uint64_t nHeaderOffsetNew = ReadU64LE(nDataOffset + 28);
	uint64_t nDataOffsetNew = ReadU64LE(nDataOffset + 36);

	DbgLog("[InnoSetup]   FindOffsetTable DEBUG: headerOld=0x%X dataOld=0x%X headerNew=0x%llX dataNew=0x%llX revision=%u fileSize=0x%llX\n",
		nHeaderOffsetOld, nDataOffsetOld,
		(unsigned long long)nHeaderOffsetNew, (unsigned long long)nDataOffsetNew,
		result.revision, (unsigned long long)nSizeForCheck);

	if (result.revision >= 2) {
		result.headerOffset = (uint32_t)nHeaderOffsetNew;
		result.dataOffset = (uint32_t)nDataOffsetNew;
		DbgLog("[InnoSetup]   FindOffsetTable: revision=%u -> using 64-bit Offset0/Offset1 layout\n", result.revision);
	}
	else {
		result.headerOffset = nHeaderOffsetOld;
		result.dataOffset = nDataOffsetOld;
		DbgLog("[InnoSetup]   FindOffsetTable: revision=%u -> using 32-bit legacy layout\n", result.revision);
	}
	result.isValid = true;

	DbgLog("[InnoSetup]   FindOffsetTable: tableOffset=0x%llX revision=%u headerOffset=0x%X dataOffset=0x%X fileSize=0x%llX\n",
		(unsigned long long)result.tableOffset, result.revision, result.headerOffset, result.dataOffset,
		(unsigned long long)GetSize());

	{
		std::vector<char> baRaw;
		if (ReadArray(nDataOffset, 52, baRaw) && baRaw.size() == 52) {
			char hexBuf[3 * 52 + 1];
			hexBuf[0] = 0;
			for (int i = 0; i < 52; i++) {
				char tmp[4];
				snprintf(tmp, sizeof(tmp), "%02X ", (uint8_t)baRaw[i]);
				strcat_s(hexBuf, tmp);
			}
			DbgLog("[InnoSetup]   raw table bytes (52): %s\n", hexBuf);
		}
		else {
			DbgLog("[InnoSetup]   raw table dump FAILED, got %zu bytes (wanted 52)\n", baRaw.size());
		}
	}

	return result;
}

std::vector<char> InnoSetupInstallerHandler::StripCRCChunks(const std::vector<char>& baData)
{
	std::vector<char> baResult;
	int32_t nPos = 0;
	int32_t nSize = (int32_t)baData.size();

	while (nPos < nSize) {
		if (nPos + 4 > nSize) break;

		nPos += 4;  // Skip chunk CRC32

		int32_t nRemaining = nSize - nPos;
		int32_t nChunkSize = (nRemaining < 4096) ? nRemaining : 4096;

		baResult.insert(baResult.end(),
			baData.begin() + nPos,
			baData.begin() + nPos + nChunkSize);

		nPos += nChunkSize;
	}

	return baResult;
}

std::vector<char> InnoSetupInstallerHandler::DecompressLZMA1(const std::vector<char>& baData)
{
	if (baData.size() < 6) {
		return std::vector<char>();
	}

	uint32_t nDictSize = (uint8_t)baData[1] | ((uint32_t)(uint8_t)baData[2] << 8)
		| ((uint32_t)(uint8_t)baData[3] << 16) | ((uint32_t)(uint8_t)baData[4] << 24);
	bool bIsLzma1 = (nDictSize > 0) && (nDictSize <= 0x10000000);

	LZMAByteVector out;
	memset(&out, 0, sizeof(out));

	const size_t nMaxOutput = (size_t)256 * 1024 * 1024;
	int status = -1;

	if (bIsLzma1) {
		std::vector<uint8_t> baInput;
		baInput.reserve(13 + baData.size() - 5);
		baInput.insert(baInput.end(), baData.begin(), baData.begin() + 5);
		baInput.insert(baInput.end(), 8, 0xFF);
		baInput.insert(baInput.end(), baData.begin() + 5, baData.end());

		status = lzma_decompress(baInput.data(), baInput.size(), &out, nMaxOutput);
	}
	else {
		status = lzma2_decompress((const uint8_t*)baData.data(), baData.size(), &out, nMaxOutput);
	}

	std::vector<char> result;
	if (status == 0 && out.data && out.length > 0) {
		result.assign((const char*)out.data, (const char*)out.data + out.length);
	}

	free(out.data);
	return result;
}

std::vector<char> InnoSetupInstallerHandler::ReadBlockStream(UInt64 offset, UInt64* consumed)
{
	UInt64 nFileSize = GetSize();

	{
		std::vector<char> baDump;
		if (ReadArray(offset, 16, baDump) && baDump.size() == 16) {
			char hexBuf[3 * 16 + 1];
			hexBuf[0] = 0;
			for (int i = 0; i < 16; i++) {
				char tmp[4];
				snprintf(tmp, sizeof(tmp), "%02X ", (uint8_t)baDump[i]);
				strcat_s(hexBuf, tmp);
			}
			DbgLog("[InnoSetup]     ReadBlockStream @0x%llX raw16: %s\n", (unsigned long long)offset, hexBuf);
		}
		else {
			DbgLog("[InnoSetup]     ReadBlockStream @0x%llX: failed to read 16 bytes for dump\n", (unsigned long long)offset);
		}
	}

	uint64_t nStoredSize = 0;
	uint8_t nCompressedFlag = 0;
	UInt64 nHeaderSize = 0;

	if (offset + 13 <= nFileSize) {
		uint64_t nTryStoredSize = ReadU64LE(offset + 4);
		uint8_t nTryFlag = ReadU8(offset + 12);
		bool bNewLooksSane = (nTryFlag == 0 || nTryFlag == 1)
			&& (offset + 13 + nTryStoredSize <= nFileSize);
		if (bNewLooksSane) {
			nStoredSize = nTryStoredSize;
			nCompressedFlag = nTryFlag;
			nHeaderSize = 13;
		}
	}

	if (nHeaderSize == 0 && offset + 9 <= nFileSize) {
		uint32_t nTryStoredSize32 = ReadU32LE(offset + 4);
		uint8_t nTryFlag = ReadU8(offset + 8);
		bool bOldLooksSane = (nTryFlag == 0 || nTryFlag == 1)
			&& (offset + 9 + (UInt64)nTryStoredSize32 <= nFileSize);
		if (bOldLooksSane) {
			nStoredSize = nTryStoredSize32;
			nCompressedFlag = nTryFlag;
			nHeaderSize = 9;
		}
	}

	if (nHeaderSize == 0) {
		DbgLog("[InnoSetup]     ReadBlockStream @0x%llX: neither old(9) nor new(13) header format looked sane -- ABORT\n",
			(unsigned long long)offset);
		if (consumed) *consumed = 0;
		return std::vector<char>();
	}

	UInt64 nConsumed = nHeaderSize + nStoredSize;

	DbgLog("[InnoSetup]     ReadBlockStream @0x%llX: headerSize=%llu storedSize=%llu compressedFlag=%u consumed=%llu (fileSize=0x%llX)\n",
		(unsigned long long)offset, (unsigned long long)nHeaderSize, (unsigned long long)nStoredSize, nCompressedFlag, (unsigned long long)nConsumed, (unsigned long long)nFileSize);

	if (offset + nConsumed > nFileSize) {
		DbgLog("[InnoSetup]     ReadBlockStream @0x%llX: offset+consumed (0x%llX) exceeds fileSize -- ABORT\n",
			(unsigned long long)offset, (unsigned long long)(offset + nConsumed));
		if (consumed) *consumed = 0;
		return std::vector<char>();
	}
	std::vector<char> baStoredData;
	ReadArray(offset + nHeaderSize, (UInt64)nStoredSize, baStoredData);

	std::vector<char> baPayload = StripCRCChunks(baStoredData);

	if (consumed) *consumed = nConsumed;

	if (nCompressedFlag == 1) {
		return DecompressLZMA1(baPayload);
	}

	return baPayload;
}

std::string InnoSetupInstallerHandler::ReadWideString(const std::vector<char>& baData, int32_t nOffset, int32_t* pnNewOffset)
{
	if (nOffset + 4 > (int32_t)baData.size()) {
		if (pnNewOffset) *pnNewOffset = nOffset;
		return std::string();
	}

	uint32_t nByteLen = (uint8_t)baData[nOffset] | ((uint32_t)(uint8_t)baData[nOffset + 1] << 8) |
		((uint32_t)(uint8_t)baData[nOffset + 2] << 16) | ((uint32_t)(uint8_t)baData[nOffset + 3] << 24);

	if (nByteLen == 0) {
		if (pnNewOffset) *pnNewOffset = nOffset + 4;
		return std::string();
	}

	if ((nByteLen > 0x1000000) || (nOffset + 4 + (int32_t)nByteLen > (int32_t)baData.size())) {
		if (pnNewOffset) *pnNewOffset = nOffset;
		return std::string();
	}

	std::string sResult;
	sResult.reserve(nByteLen / 2);

	const unsigned char* pData = (const unsigned char*)baData.data() + nOffset + 4;
	uint32_t nNumChars = nByteLen / 2;

	for (uint32_t i = 0; i < nNumChars; i++) {
		uint16_t nCodeUnit = pData[i * 2] | ((uint16_t)pData[i * 2 + 1] << 8);

		if (nCodeUnit < 0x80) {
			sResult.push_back((char)nCodeUnit);
		}
		else if (nCodeUnit < 0x800) {
			sResult.push_back((char)(0xC0 | (nCodeUnit >> 6)));
			sResult.push_back((char)(0x80 | (nCodeUnit & 0x3F)));
		}
		else {
			sResult.push_back((char)(0xE0 | (nCodeUnit >> 12)));
			sResult.push_back((char)(0x80 | ((nCodeUnit >> 6) & 0x3F)));
			sResult.push_back((char)(0x80 | (nCodeUnit & 0x3F)));
		}
	}

	if (pnNewOffset) *pnNewOffset = nOffset + 4 + (int32_t)nByteLen;

	return sResult;
}

std::vector<InnoSetupInstallerHandler::DataEntry> InnoSetupInstallerHandler::ParseDataEntries(const std::vector<char>& baBlock2)
{
	std::vector<DataEntry> listResult;

	int32_t nBlockSize = (int32_t)baBlock2.size();
	if (nBlockSize <= 0) return listResult;

	auto readLE64 = [](const char* p) -> int64_t {
		uint64_t v = 0;
		for (int i = 0; i < 8; i++) {
			v |= ((uint64_t)(uint8_t)p[i]) << (8 * i);
		}
		return (int64_t)v;
		};
	auto readLE32 = [](const char* p) -> uint32_t {
		return (uint8_t)p[0] | ((uint32_t)(uint8_t)p[1] << 8) | ((uint32_t)(uint8_t)p[2] << 16) | ((uint32_t)(uint8_t)p[3] << 24);
		};

	const int32_t nCandidateFieldBases[] = { 12, 16 };
	const int32_t nMinEntrySize = 68;  
	const int32_t nMaxEntrySize = 128;
	const int64_t nSaneMaxSize = (int64_t)1 << 40;

	int32_t nBestEntrySize = 0;
	int32_t nBestFieldBase = 0;
	int32_t nBestSaneCount = -1;

	for (int32_t nCandidateSize = nMinEntrySize; nCandidateSize <= nMaxEntrySize; nCandidateSize++) {
		if (nBlockSize % nCandidateSize != 0) continue;

		int32_t nCandidateCount = nBlockSize / nCandidateSize;
		if (nCandidateCount <= 0) continue;

		for (int32_t nFieldBase : nCandidateFieldBases) {
			if (nFieldBase + 56 > nCandidateSize) continue;

			int32_t nSaneCount = 0;

			for (int32_t i = 0; i < nCandidateCount; i++) {
				const char* pEntry = baBlock2.data() + (i * nCandidateSize);

				int64_t nChunkSubOffset = readLE64(pEntry + nFieldBase);
				int64_t nOriginalSize = readLE64(pEntry + nFieldBase + 8);
				int64_t nChunkCompressedSize = readLE64(pEntry + nFieldBase + 16);

				bool bSane = (nChunkSubOffset >= 0) && (nChunkSubOffset < nSaneMaxSize) && (nOriginalSize >= 0) &&
					(nOriginalSize < nSaneMaxSize) && (nChunkCompressedSize >= 0) && (nChunkCompressedSize < nSaneMaxSize);

				if (bSane) nSaneCount++;
			}

			if (nSaneCount == nCandidateCount && nSaneCount > nBestSaneCount) {
				nBestSaneCount = nSaneCount;
				nBestEntrySize = nCandidateSize;
				nBestFieldBase = nFieldBase;
			}
		}
	}

	if (nBestEntrySize == 0) return listResult;

	int32_t nEntrySize = nBestEntrySize;
	int32_t nFieldBase = nBestFieldBase;
	int32_t nNumEntries = nBlockSize / nEntrySize;

	for (int32_t i = 0; i < nNumEntries; i++) {
		int32_t nBase = i * nEntrySize;
		const char* pEntry = baBlock2.data() + nBase;

		DataEntry entry;
		entry.chunkSubOffset = readLE64(pEntry + nFieldBase);
		entry.originalSize = readLE64(pEntry + nFieldBase + 8);
		entry.chunkCompressedSize = readLE64(pEntry + nFieldBase + 16);
		entry.sha256.assign((const uint8_t*)pEntry + nFieldBase + 24, (const uint8_t*)pEntry + nFieldBase + 24 + 32);

		listResult.push_back(entry);
	}

	return listResult;
}

std::vector<InnoSetupInstallerHandler::FileEntry> InnoSetupInstallerHandler::ParseFileEntries(const std::vector<char>& baBlock1, int32_t nNumFiles)
{
	std::vector<FileEntry> listResult;

	auto readLE32At = [&](int32_t nOff) -> uint32_t {
		const unsigned char* p = (const unsigned char*)baBlock1.data() + nOff;
		return p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
		};

	std::vector<char> baAppU16;
	{
		std::string sApp = "{app}";
		for (char c : sApp) { baAppU16.push_back(c); baAppU16.push_back('\0'); }
	}

	std::vector<char> baTmpU16;
	{
		std::string sTmp = "{tmp}";
		for (char c : sTmp) { baTmpU16.push_back(c); baTmpU16.push_back('\0'); }
	}

	std::vector<int32_t> listPatternPositions;

	{
		auto scanFor = [&](const std::vector<char>& needle) {
			auto it = baBlock1.begin();
			while (true) {
				it = std::search(it, baBlock1.end(), needle.begin(), needle.end());
				if (it == baBlock1.end()) break;
				listPatternPositions.push_back((int32_t)std::distance(baBlock1.begin(), it));
				++it;
			}
			};

		scanFor(baAppU16);
		scanFor(baTmpU16);

		std::sort(listPatternPositions.begin(), listPatternPositions.end());
	}

	DbgLog("[InnoSetup]   ParseFileEntries: found %zu {app}/{tmp} pattern positions\n", listPatternPositions.size());
	if (listPatternPositions.empty()) return listResult;

	const int32_t nDefaultNumericSize = 39;
	int32_t nBestScore = 0;
	int32_t nBestEntryStart = -1;
	int32_t nBestNumStrings = 0;
	int32_t nBestNumericSize = 0;

	std::vector<int32_t> listTestedStarts;

	const size_t nMaxCandidatesToTest = 2000;
	size_t nCandidatesTested = 0;

	for (size_t p = 0; p < listPatternPositions.size(); p++) {
		if (nCandidatesTested >= nMaxCandidatesToTest) break;
		int32_t nPatternPos = listPatternPositions[p];

		int32_t nDestNameOff = -1;

		for (int32_t nBack = 4; nBack < 500; nBack += 2) {
			int32_t nTestOff = nPatternPos - nBack;
			if (nTestOff < 4) break;

			uint32_t nLen = readLE32At(nTestOff);

			if ((nLen > 0) && (nLen < 2000) && (nLen % 2 == 0) && (nTestOff + 4 + (int32_t)nLen <= (int32_t)baBlock1.size())) {
				uint32_t nPrevLen = readLE32At(nTestOff - 4);
				if (nPrevLen == 0) nDestNameOff = nTestOff;
				break;
			}
		}

		if (nDestNameOff == -1) continue;

		int32_t nCandidateStart = nDestNameOff - 4;

		if (std::find(listTestedStarts.begin(), listTestedStarts.end(), nCandidateStart) != listTestedStarts.end()) {
			continue;
		}

		listTestedStarts.push_back(nCandidateStart);
		nCandidatesTested++;

		int32_t nOff = nCandidateStart;
		int32_t nStringCount = 0;

		for (int32_t s = 0; s < 20; s++) {
			int32_t nNewOff = 0;
			ReadWideString(baBlock1, nOff, &nNewOff);
			if (nNewOff == nOff) break;
			nStringCount++;
			nOff = nNewOff;
		}

		if (nStringCount < 2) continue;

		int32_t nStringsEnd = nOff;
		int32_t nProbeNumericSize = 0;

		int32_t nProbeLimit = ((nStringsEnd + 200) < ((int32_t)baBlock1.size() - 8))
			? (nStringsEnd + 200)
			: ((int32_t)baBlock1.size() - 8);

		for (int32_t nProbe = nStringsEnd; nProbe < nProbeLimit; nProbe++) {
			uint32_t nVal1 = readLE32At(nProbe);

			if (nVal1 == 0) {
				uint32_t nVal2 = readLE32At(nProbe + 4);

				if ((nVal2 > 4) &&
					(nVal2 < 2000) &&
					(nVal2 % 2 == 0) &&
					(nProbe + 8 + (int32_t)nVal2 <= (int32_t)baBlock1.size())) {

					nProbeNumericSize = nProbe - nStringsEnd;
					break;
				}
			}
		}

		if (nProbeNumericSize <= 0) nProbeNumericSize = nDefaultNumericSize;

		int32_t nScore = 0;
		int32_t nTrialOff = nCandidateStart;
		const int32_t nTrialCap = ((nNumFiles + 100) < 20000) ? (nNumFiles + 100) : 20000;

		for (int32_t nTrial = 0; nTrial < nTrialCap; nTrial++) {
			if (nTrialOff + 4 > (int32_t)baBlock1.size()) break;

			int32_t nTrialStrOff = nTrialOff;
			int32_t nTrialStrings = 0;

			for (int32_t s = 0; s < nStringCount; s++) {
				int32_t nNewOff = 0;
				ReadWideString(baBlock1, nTrialStrOff, &nNewOff);
				if (nNewOff == nTrialStrOff) break;
				nTrialStrings++;
				nTrialStrOff = nNewOff;
			}

			if (nTrialStrings < 2) break;

			if (nTrialStrOff + 20 <= (int32_t)baBlock1.size()) {
				int32_t nLocIdx = (int32_t)readLE32At(nTrialStrOff + 16);
				if ((nLocIdx >= 0) && (nLocIdx < nNumFiles)) nScore++;
			}

			nTrialOff = nTrialStrOff + nProbeNumericSize;
		}

		if (nScore > nBestScore) {
			nBestScore = nScore;
			nBestEntryStart = nCandidateStart;
			nBestNumStrings = nStringCount;
			nBestNumericSize = nProbeNumericSize;
			DbgLog("[InnoSetup]   candidate %zu/%zu: new best score=%d strings=%d numericSize=%d\n",
				p, listPatternPositions.size(), nBestScore, nBestNumStrings, nBestNumericSize);
		}

		if ((p % 200) == 0) {
			DbgLog("[InnoSetup]   ...scanned %zu/%zu candidates so far, bestScore=%d\n",
				p, listPatternPositions.size(), nBestScore);
		}

		if (nBestScore >= 10) break;
	}

	DbgLog("[InnoSetup]   ParseFileEntries: candidate scan finished, bestScore=%d bestStart=%d\n",
		nBestScore, nBestEntryStart);

	if (nBestEntryStart == -1) return listResult;

	int32_t nAnchor = nBestEntryStart;

	for (int32_t nAttempt = 0; nAttempt < 500; nAttempt++) {
		int32_t nPrevStringsEnd = nAnchor - nBestNumericSize;
		if (nPrevStringsEnd < 4) break;

		bool bFoundPrev = false;
		int32_t nMaxLookback = nBestNumStrings * 2004;

		// no std::max, no max macro
		int32_t nSearchFrom = (nPrevStringsEnd - nMaxLookback > 0)
			? (nPrevStringsEnd - nMaxLookback)
			: 0;

		for (int32_t nTest = nPrevStringsEnd - (nBestNumStrings * 4);
			nTest >= nSearchFrom;
			nTest--) {

			if (nTest < 0) break;

			uint32_t nFirstLen = readLE32At(nTest);
			if (nFirstLen != 0) continue;

			int32_t nCheckOff = nTest;
			int32_t nCheckCount = 0;

			for (int32_t s = 0; s < nBestNumStrings; s++) {
				int32_t nNewOff = 0;
				ReadWideString(baBlock1, nCheckOff, &nNewOff);
				if (nNewOff == nCheckOff) break;
				nCheckCount++;
				nCheckOff = nNewOff;
			}

			if ((nCheckCount == nBestNumStrings) &&
				(nCheckOff == nPrevStringsEnd)) {

				if (nPrevStringsEnd + 20 <= (int32_t)baBlock1.size()) {
					int32_t nLocIdx = (int32_t)readLE32At(nPrevStringsEnd + 16);
					if ((nLocIdx >= 0) && (nLocIdx < nNumFiles)) {
						nAnchor = nTest;
						bFoundPrev = true;
						break;
					}
				}
			}
		}

		if (!bFoundPrev) break;
	}


	int32_t nOff = nAnchor;

	for (int32_t nEntry = 0; nEntry < nNumFiles + 100; nEntry++) {
		if (nOff + 4 > (int32_t)baBlock1.size()) break;

		std::vector<std::string> listStrings;
		int32_t nStrOff = nOff;

		for (int32_t i = 0; i < nBestNumStrings; i++) {
			int32_t nNewOff = 0;
			std::string sStr = ReadWideString(baBlock1, nStrOff, &nNewOff);
			if (nNewOff == nStrOff) break;
			listStrings.push_back(sStr);
			nStrOff = nNewOff;
		}

		if (listStrings.size() < 2) break;

		int32_t nNumOff = nStrOff;
		if (nNumOff + nBestNumericSize > (int32_t)baBlock1.size()) break;

		int32_t nLocationEntry = -1;
		if (nBestNumericSize >= 20) {
			nLocationEntry = (int32_t)readLE32At(nNumOff + 16);
		}

		FileEntry fileEntry;
		fileEntry.destName = listStrings.at(1);
		fileEntry.locationEntry = nLocationEntry;

		listResult.push_back(fileEntry);

		nOff = nNumOff + nBestNumericSize;
	}

	return listResult;
}

std::vector<char> InnoSetupInstallerHandler::DecompressDataChunk(UInt64 nChunkOffset, int64_t nChunkCompressedSize)
{
	UInt64 nFileSize = GetSize();

	if (nChunkOffset + 4 > nFileSize) return std::vector<char>();

	std::vector<char> baMagic;
	if (!ReadArray(nChunkOffset, 4, baMagic) || baMagic.size() != 4) return std::vector<char>();

	// Verify zlb magic
	if ((baMagic[0] != 'z') || (baMagic[1] != 'l') || (baMagic[2] != 'b') || ((uint8_t)baMagic[3] != 0x1A)) {
		return std::vector<char>();
	}

	int64_t nDataAfterMagic = nChunkCompressedSize;
	if (nDataAfterMagic > 4) nDataAfterMagic -= 4;

	UInt64 nAfterMagicOffset = nChunkOffset + 4;

	if (nAfterMagicOffset + nDataAfterMagic > nFileSize) {
		nDataAfterMagic = (int64_t)nFileSize - (int64_t)nAfterMagicOffset;
	}

	if (nDataAfterMagic <= 5) return std::vector<char>();

	std::vector<char> baHeader;
	if (!ReadArray(nAfterMagicOffset, 5, baHeader) || baHeader.size() != 5) return std::vector<char>();

	uint32_t nDictSize = (uint8_t)baHeader[1] | ((uint32_t)(uint8_t)baHeader[2] << 8) | ((uint32_t)(uint8_t)baHeader[3] << 16) |
		((uint32_t)(uint8_t)baHeader[4] << 24);
	bool bIsLzma1 = (nDictSize > 0) && (nDictSize <= 0x10000000);

	UInt64 nCompressedDataOffset = bIsLzma1 ? (nAfterMagicOffset + 5) : (nAfterMagicOffset + 1);
	int64_t nCompressedDataSize = bIsLzma1 ? (nDataAfterMagic - 5) : (nDataAfterMagic - 1);

	if (nCompressedDataSize <= 0) return std::vector<char>();

	std::vector<char> baCompressedSlice;
	if (!ReadArray(nCompressedDataOffset, (UInt64)nCompressedDataSize, baCompressedSlice)) {
		return std::vector<char>();
	}

	LZMAByteVector out;
	memset(&out, 0, sizeof(out));

	const size_t nMaxOutput = (size_t)1024 * 1024 * 1024;
	int status = -1;

	if (bIsLzma1) {

		std::vector<uint8_t> baInput;
		baInput.reserve(13 + baCompressedSlice.size());
		baInput.insert(baInput.end(), baHeader.begin(), baHeader.end());
		baInput.insert(baInput.end(), 8, 0xFF);
		baInput.insert(baInput.end(), baCompressedSlice.begin(), baCompressedSlice.end());

		status = lzma_decompress(baInput.data(), baInput.size(), &out, nMaxOutput);
	}
	else {
		status = lzma2_decompress((const uint8_t*)baCompressedSlice.data(),
			baCompressedSlice.size(), &out, nMaxOutput);
	}

	std::vector<char> result;
	if (status == 0 && out.data && out.length > 0) {
		result.assign((const char*)out.data, (const char*)out.data + out.length);
	}

	free(out.data);
	return result;
}

bool InnoSetupInstallerHandler::ParseRealInnoSetup(UInt64 /*signatureOffset*/)
{
	auto t0 = std::chrono::steady_clock::now();
	DbgLog("[InnoSetup] ParseRealInnoSetup: BEGIN, calling FindOffsetTable...\n");

	OffsetTable offsetTable = FindOffsetTable();

	DbgLog("[InnoSetup] FindOffsetTable done, isValid=%d headerOffset=0x%X dataOffset=0x%X\n",
		offsetTable.isValid, offsetTable.headerOffset, offsetTable.dataOffset);

	if (!offsetTable.isValid) {
		std::fprintf(stderr, "[diag] offset table (rDlPtS) NOT FOUND\n");
		return false;
	}

	UInt64 nSetup0Offset = offsetTable.headerOffset;
	UInt64 nDataStreamOffset = offsetTable.dataOffset;
	UInt64 nFileSize = GetSize();

	if ((nSetup0Offset >= nFileSize) || (nDataStreamOffset >= nFileSize)) {
		DbgLog("[InnoSetup] ABORT: header/data offset OUT OF BOUNDS. headerOffset=0x%llX dataOffset=0x%llX fileSize=0x%llX\n",
			(unsigned long long)nSetup0Offset, (unsigned long long)nDataStreamOffset, (unsigned long long)nFileSize);
		std::fprintf(stderr, "[diag] header/data offset out of file bounds (fileSize=%llu)\n", (unsigned long long)nFileSize);
		return false;
	}

	if (nSetup0Offset + 64 > nFileSize) {
		std::fprintf(stderr, "[diag] setup-0 header + 64 bytes exceeds file size\n");
		return false;
	}

	{
		const int nDumpLen = 320;
		std::vector<char> baIdDump;
		if (ReadArray(nSetup0Offset, nDumpLen, baIdDump) && baIdDump.size() == (size_t)nDumpLen) {
			std::string sAsText;
			sAsText.reserve(nDumpLen);
			for (int i = 0; i < nDumpLen; i++) {
				unsigned char c = (unsigned char)baIdDump[i];
				sAsText.push_back((c >= 32 && c < 127) ? (char)c : '.');
			}
			DbgLog("[InnoSetup]   setup0 @0x%llX first %d bytes as text: %s\n",
				(unsigned long long)nSetup0Offset, nDumpLen, sAsText.c_str());

			std::vector<char> hexBuf(3 * nDumpLen + 1, 0);
			for (int i = 0; i < nDumpLen; i++) {
				char tmp[4];
				snprintf(tmp, sizeof(tmp), "%02X ", (uint8_t)baIdDump[i]);
				strcat_s(hexBuf.data(), hexBuf.size(), tmp);
			}
			DbgLog("[InnoSetup]   setup0 @0x%llX first %d bytes hex: %s\n",
				(unsigned long long)nSetup0Offset, nDumpLen, hexBuf.data());

			for (int i = 0; i + 9 <= nDumpLen; i++) {
				uint32_t storedSize = (uint8_t)baIdDump[i + 4] | ((uint32_t)(uint8_t)baIdDump[i + 5] << 8)
					| ((uint32_t)(uint8_t)baIdDump[i + 6] << 16) | ((uint32_t)(uint8_t)baIdDump[i + 7] << 24);
				uint8_t flag = (uint8_t)baIdDump[i + 8];
				if (storedSize > 100 && storedSize < 10 * 1024 * 1024 && (flag == 0 || flag == 1)) {
					DbgLog("[InnoSetup]     candidate block header @ +%d (0x%X from setup0): storedSize=%u flag=%u\n",
						i, i, storedSize, flag);
				}
			}
		}
	}

	UInt64 nBlock1Offset = nSetup0Offset + 64;
	UInt64 nBlock1Consumed = 0;
	std::vector<char> baBlock1;
	{
		DbgLog("[InnoSetup]   --- probing candidate block1 offsets (byte-by-byte, real attempt) ---\n");

		const int64_t nSearchStart = 20;   
		const int64_t nSearchEnd = 65536;   

		int nLoggedCandidates = 0;
		const int nMaxLogCandidates = 60; 

		for (int64_t nDelta = nSearchStart; nDelta <= nSearchEnd; nDelta++) {
			UInt64 nCandidate = nSetup0Offset + (UInt64)nDelta;
			if (nCandidate + 9 > nFileSize) break;

			uint64_t nCandStoredSizeNew = ReadU64LE(nCandidate + 4);
			uint8_t nCandFlagNew = ReadU8(nCandidate + 12);
			bool bWorthTryingNew = (nCandStoredSizeNew > 0)
				&& (nCandidate + 13 + nCandStoredSizeNew <= nFileSize)
				&& (nCandFlagNew == 0 || nCandFlagNew == 1);

			uint32_t nCandStoredSizeOld = ReadU32LE(nCandidate + 4);
			uint8_t nCandFlagOld = ReadU8(nCandidate + 8);
			bool bWorthTryingOld = (nCandStoredSizeOld > 0)
				&& (nCandidate + 9 + (UInt64)nCandStoredSizeOld <= nFileSize)
				&& (nCandFlagOld == 0 || nCandFlagOld == 1);

			uint64_t nCandStoredSize = bWorthTryingNew ? nCandStoredSizeNew : nCandStoredSizeOld;
			uint8_t nCandFlag = bWorthTryingNew ? nCandFlagNew : nCandFlagOld;
			bool bWorthTrying = bWorthTryingNew || bWorthTryingOld;

			if (!bWorthTrying) continue;

			if (nLoggedCandidates < nMaxLogCandidates) {
				DbgLog("[InnoSetup]     raw candidate +%lld (0x%llX): storedSize=%u flag=%u\n",
					(long long)nDelta, (unsigned long long)nCandidate, nCandStoredSize, nCandFlag);
				nLoggedCandidates++;
			}

			UInt64 nTryConsumed = 0;
			std::vector<char> baTry = ReadBlockStream(nCandidate, &nTryConsumed);

			if (baTry.empty() && nCandStoredSize > 100000) {
				std::vector<char> baExtra;
				if (ReadArray(nCandidate + 9, 32, baExtra) && baExtra.size() == 32) {
					std::string hexBuf;
					char tmp[4];
					for (unsigned char c : baExtra) {
						snprintf(tmp, sizeof(tmp), "%02X ", c);
						hexBuf += tmp;
					}
					DbgLog("[InnoSetup]     FAILED candidate +%lld extra 32 raw bytes (post header, pre-strip): %s\n",
						(long long)nDelta, hexBuf.c_str());
				}
			}

			if (!baTry.empty()) {
				bool bLooksLikeHeader = false;
				if (baTry.size() >= 8) {
					uint32_t nFirstStrLen = (uint8_t)baTry[0] | ((uint32_t)(uint8_t)baTry[1] << 8)
						| ((uint32_t)(uint8_t)baTry[2] << 16) | ((uint32_t)(uint8_t)baTry[3] << 24);
					bLooksLikeHeader = (nFirstStrLen > 0) && (nFirstStrLen < 512)
						&& (4 + nFirstStrLen + 4 <= baTry.size());
				}

				bool bPlausibleSize = baTry.size() >= 512;

				DbgLog("[InnoSetup]     candidate +%lld (0x%llX): storedSize=%u flag=%u -> decompressed size=%zu looksLikeHeader=%d plausibleSize=%d\n",
					(long long)nDelta, (unsigned long long)nCandidate, nCandStoredSize, nCandFlag, baTry.size(),
					bLooksLikeHeader, bPlausibleSize);

				if (bLooksLikeHeader && bPlausibleSize && baBlock1.empty()) {
					nBlock1Offset = nCandidate;
					nBlock1Consumed = nTryConsumed;
					baBlock1 = std::move(baTry);
					DbgLog("[InnoSetup]     ^ ACCEPTED as real block1 (delta=%lld)\n", (long long)nDelta);
					break;
				}
			}
		}
		DbgLog("[InnoSetup]   --- end probe ---\n");
	}

	if (baBlock1.empty()) {
		DbgLog("[InnoSetup] Reading block stream 1 at default 0x%llX (probe found nothing)...\n", (unsigned long long)nBlock1Offset);
		baBlock1 = ReadBlockStream(nBlock1Offset, &nBlock1Consumed);
	}

	DbgLog("[InnoSetup] block1 size=%zu consumed=%llu (%.2fs elapsed)\n",
		baBlock1.size(), (unsigned long long)nBlock1Consumed,
		std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
	if (baBlock1.empty()) {
		std::fprintf(stderr, "[diag] block stream 1 (at 0x%llx) came back EMPTY\n", (unsigned long long)nBlock1Offset);
		return false;
	}

	UInt64 nBlock2Offset = nBlock1Offset + nBlock1Consumed;
	UInt64 nBlock2Consumed = 0;
	DbgLog("[InnoSetup] Reading block stream 2 at 0x%llX...\n", (unsigned long long)nBlock2Offset);
	std::vector<char> baBlock2 = ReadBlockStream(nBlock2Offset, &nBlock2Consumed);
	DbgLog("[InnoSetup] block2 size=%zu consumed=%llu (%.2fs elapsed)\n",
		baBlock2.size(), (unsigned long long)nBlock2Consumed,
		std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
	if (baBlock2.empty()) {
		std::fprintf(stderr, "[diag] block stream 2 (at 0x%llx) came back EMPTY\n", (unsigned long long)nBlock2Offset);
		return false;
	}

	{
		size_t nDumpLen = baBlock2.size() < 220 ? baBlock2.size() : 220;
		std::string hexBuf;
		hexBuf.reserve(nDumpLen * 3);
		char tmp[4];
		for (size_t i = 0; i < nDumpLen; i++) {
			snprintf(tmp, sizeof(tmp), "%02X ", (uint8_t)baBlock2[i]);
			hexBuf += tmp;
		}
		DbgLog("[InnoSetup]   block2 first %zu bytes hex: %s\n", nDumpLen, hexBuf.c_str());
	}

	DbgLog("[InnoSetup] Calling ParseDataEntries (block2 size=%zu)...\n", baBlock2.size());
	std::vector<DataEntry> listDataEntries = ParseDataEntries(baBlock2);
	DbgLog("[InnoSetup] ParseDataEntries done: %zu entries (%.2fs elapsed)\n",
		listDataEntries.size(),
		std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
	if (listDataEntries.empty()) {
		std::fprintf(stderr, "[diag] ParseDataEntries produced 0 entries (block2 size=%zu)\n", baBlock2.size());
		return false;
	}

	int32_t nNumDataEntries = (int32_t)listDataEntries.size();

	DbgLog("[InnoSetup] Calling ParseFileEntries (numDataEntries=%d, block1 size=%zu)...\n",
		nNumDataEntries, baBlock1.size());
	std::vector<FileEntry> listFileEntries = ParseFileEntries(baBlock1, nNumDataEntries);
	DbgLog("[InnoSetup] ParseFileEntries done: %zu entries (%.2fs elapsed)\n",
		listFileEntries.size(),
		std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
	if (listFileEntries.empty()) {
		std::fprintf(stderr, "[diag] ParseFileEntries produced 0 entries (no {app}/{tmp} pattern matched?)\n");
		return false;
	}

	std::vector<ChunkInfo> listChunks;
	UInt64 nCurrentChunkOffset = nDataStreamOffset;

	for (int32_t i = 0; i < nNumDataEntries; i++) {
		int64_t nCCS = listDataEntries.at(i).chunkCompressedSize;
		bool bFound = false;

		for (size_t j = 0; j < listChunks.size(); j++) {
			if (listChunks[j].chunkCompressedSize == nCCS) {
				listChunks[j].entryIndices.push_back(i);
				bFound = true;
				break;
			}
		}

		if (!bFound) {
			ChunkInfo chunk;
			chunk.chunkCompressedSize = nCCS;
			chunk.chunkFileOffset = nCurrentChunkOffset;
			chunk.entryIndices.push_back(i);
			listChunks.push_back(chunk);
			nCurrentChunkOffset += (UInt64)nCCS + 4;
		}
	}

	std::map<int32_t, UInt64> mapEntryChunkFileOffset;
	std::map<int32_t, int64_t> mapEntryChunkCompressedSize;

	for (size_t cIdx = 0; cIdx < listChunks.size(); cIdx++) {
		const ChunkInfo& chunk = listChunks[cIdx];
		for (size_t j = 0; j < chunk.entryIndices.size(); j++) {
			int32_t nEntryIdx = chunk.entryIndices[j];
			mapEntryChunkFileOffset[nEntryIdx] = chunk.chunkFileOffset;
			mapEntryChunkCompressedSize[nEntryIdx] = chunk.chunkCompressedSize;
		}
	}

	for (size_t i = 0; i < listFileEntries.size(); i++) {
		const FileEntry& fileEntry = listFileEntries[i];
		int32_t nLocIdx = fileEntry.locationEntry;

		if ((nLocIdx < 0) || (nLocIdx >= nNumDataEntries)) continue;

		const DataEntry& dataEntry = listDataEntries.at((size_t)nLocIdx);

		std::string sFileName = fileEntry.destName;
		std::replace(sFileName.begin(), sFileName.end(), '\\', '/');

		FileInfo info;
		info.path = sFileName;
		info.uncompressedSize = (uint64_t)dataEntry.originalSize;
		info.compressedSize = (uint64_t)dataEntry.chunkCompressedSize;

		{
			static const char* pszHex = "0123456789abcdef";
			std::string sHex;
			sHex.reserve(dataEntry.sha256.size() * 2);
			for (uint8_t b : dataEntry.sha256) {
				sHex.push_back(pszHex[b >> 4]);
				sHex.push_back(pszHex[b & 0x0F]);
			}
			info.sha256Hex = sHex;
		}

		if (dataEntry.originalSize == 0) {
			items.push_back(info);
			continue;
		}

		info.hasChunkData = true;
		info.chunkFileOffset = mapEntryChunkFileOffset.count(nLocIdx) ? mapEntryChunkFileOffset[nLocIdx] : 0;
		info.chunkStreamCompressedSize =
			(mapEntryChunkCompressedSize.count(nLocIdx) ? mapEntryChunkCompressedSize[nLocIdx] : 0) + 4;
		info.chunkSubOffset = dataEntry.chunkSubOffset;

		items.push_back(std::move(info));
	}

	return !items.empty();
}

bool InnoSetupInstallerHandler::ParseSyntheticFileEntries(UInt64 signatureOffset)
{
	UInt64 nFileSize = GetSize();

	UInt64 nOffset = signatureOffset;

	UInt64 nMaxScan = ((signatureOffset + 0x100) < nFileSize)
		? (signatureOffset + 0x100)
		: nFileSize;


	while (nOffset < nMaxScan) {
		uint8_t nByte = ReadU8(nOffset);
		if (nByte == 0) { nOffset++; break; }
		nOffset++;
	}

	if (nOffset + 4 > nFileSize) return false;

	std::vector<char> baMagic;
	if (!ReadArray(nOffset, 4, baMagic) || baMagic.size() != 4) return false;
	if (std::memcmp(baMagic.data(), "ISDF", 4) != 0) return false;

	nOffset += 4;

	if (nOffset + 4 > nFileSize) return false;
	uint32_t nNumberOfFiles = ReadU32LE(nOffset);
	nOffset += 4;

	if (nOffset + 8 > nFileSize) return false;
	nOffset += 8;

	for (uint32_t i = 0; i < nNumberOfFiles; i++) {
		if (nOffset + 2 > nFileSize) break;
		uint16_t nNameLen = ReadU16LE(nOffset);
		nOffset += 2;

		if (nOffset + nNameLen > nFileSize) break;
		std::vector<char> baName;
		ReadArray(nOffset, nNameLen, baName);
		std::string sFileName(baName.begin(), baName.end());
		nOffset += nNameLen;

		if (nOffset + 8 > nFileSize) break;
		uint64_t nDataOffset = ReadU64LE(nOffset);
		nOffset += 8;

		if (nOffset + 8 > nFileSize) break;
		uint64_t nDataSize = ReadU64LE(nOffset);
		nOffset += 8;

		if (nOffset + 4 > nFileSize) break;
		nOffset += 4;

		FileInfo info;
		info.path = sFileName;
		info.uncompressedSize = nDataSize;
		info.compressedSize = nDataSize;

		if (nDataSize > 0) {
			std::vector<char> baFileData;
			ReadArray(nDataOffset, nDataSize, baFileData);
			info.decompressedData.assign(baFileData.begin(), baFileData.end());
		}

		items.push_back(std::move(info));
	}

	return !items.empty();
}

const std::vector<uint8_t>* InnoSetupInstallerHandler::GetFileData(size_t index)
{
	if (index >= items.size()) return nullptr;

	FileInfo& info = items[index];

	if (!info.decompressedData.empty() || info.uncompressedSize == 0) {
		return &info.decompressedData;
	}

	if (!info.hasChunkData) return &info.decompressedData;

	auto cacheIt = m_chunkCache.find(info.chunkFileOffset);
	if (cacheIt == m_chunkCache.end()) {
		std::vector<char> baDecompressed = DecompressDataChunk(info.chunkFileOffset, info.chunkStreamCompressedSize);

		if (baDecompressed.empty()) {
			std::fprintf(stderr, "[InnoSetup] Failed to decompress data chunk at offset %llu\n",
				(unsigned long long)info.chunkFileOffset);
			return nullptr;
		}

		auto insertResult = m_chunkCache.emplace(info.chunkFileOffset, std::move(baDecompressed));
		cacheIt = insertResult.first;
	}

	const std::vector<char>& baChunk = cacheIt->second;
	int64_t nSubOffset = info.chunkSubOffset;
	int64_t nSize = (int64_t)info.uncompressedSize;

	if (nSubOffset < 0 || nSubOffset + nSize >(int64_t)baChunk.size()) {
		std::fprintf(stderr, "[InnoSetup] File data exceeds chunk boundary: offset %lld size %lld chunk size %zu\n",
			(long long)nSubOffset, (long long)nSize, baChunk.size());
		return nullptr;
	}

	info.decompressedData.assign(baChunk.begin() + nSubOffset, baChunk.begin() + nSubOffset + nSize);
	return &info.decompressedData;
}

HRESULT InnoSetupInstallerHandler::Open(IInStream* stream, const UInt64* /*maxCheckStartPosition*/, IArchiveOpenCallback* callback)
{
	Close();

	m_stream = stream;
	m_fileSize = 0;

	DbgLog("[InnoSetup] InnoSetupInstallerHandler::Open CALLED, calling Analyse()...\n");

	InternalInfo info = Analyse();

	DbgLog("[InnoSetup] Analyse() returned isValid=%d signatureOffset=0x%llX version='%s'\n",
		info.isValid, (unsigned long long)info.signatureOffset, info.version.c_str());

	if (!info.isValid) {
		DbgLog("[InnoSetup] Analyse() FAILED -- returning S_FALSE from Open()\n");
		Close();
		return S_FALSE;
	}

	version = info.version;

	if (callback) {
		UInt64 total = GetSize();
		callback->SetTotal(nullptr, &total);
	}

	bool parsedReal = ParseRealInnoSetup(info.signatureOffset);

	if (!parsedReal) {
		items.clear();
		if (!ParseSyntheticFileEntries(info.signatureOffset)) {
			Close();
			return S_FALSE;
		}
	}

	return S_OK;
}

void InnoSetupInstallerHandler::Close()
{
	version.clear();
	items.clear();
	m_chunkCache.clear();
	m_stream = nullptr;
	m_fileSize = 0;
}