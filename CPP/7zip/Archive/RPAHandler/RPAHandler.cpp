#include "stdafx.h"
#pragma warning (disable: 5043)
#include "../../../Common/ComTry.h"
#include "../../../Common/MyString.h"
#include "../../../Windows/PropVariant.h"
#include "../../Common/ProgressUtils.h"
#include "../../Common/RegisterArc.h"
#include "../../Common/StreamObjects.h"
#include "../../Archive/IArchive.h"
#include "RPAHandler.h"
#include <cstdint>
#include <chrono>
#ifdef _DEBUG
#include <fstream>
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif
using namespace NWindows;
namespace NArchive {
	namespace NRPA {
		static const Byte kSignatureRPA2[] = { 'R', 'P', 'A', '-', '2', '.', '0', ' ' };
		static const Byte kSignatureRPA3[] = { 'R', 'P', 'A', '-', '3', '.', '0', ' ' };
		static const Byte kSignatureRPA32[] = { 'R', 'P', 'A', '-', '3', '.', '2', ' ' };
		static const Byte kProps[] =
		{
			kpidPath,
			kpidSize,
			kpidPackSize,
		};
		static const Byte kArcProps[] =
		{
			kpidSubType
		};
#ifdef _DEBUG
		void DebugLog(const wchar_t* message) {
			std::wofstream logFile;
			logFile.open(L"C:\\rpa_debug.log", std::ios::app);
			if (logFile.is_open()) {
				logFile << message << std::endl;
				logFile.close();
			}
		}
		void DebugLog(const std::wstring& message) {
			DebugLog(message.c_str());
		}
#else
		inline void DebugLog(const wchar_t*) {}
		inline void DebugLog(const std::wstring&) {}
#endif
		class CHandler : public IInArchive, public IInArchiveGetStream, public CMyUnknownImp {
		public:
			MY_UNKNOWN_IMP2(IInArchive, IInArchiveGetStream)
				INTERFACE_IInArchive(;)
				STDMETHOD(GetStream)(UInt32 index, ISequentialInStream** stream);
			CHandler() : batchLoadEnabled(false), archiveVersion(0.0), hasArchiveCache(false) {
				DebugLog(L"CHandler constructed");
			}
			~CHandler() {
				DebugLog(L"CHandler destroyed");
				if (batchLoadEnabled) {
					rpaHandler.CloseBatchLoad();
				}
				archiveDataCache.clear();
			}
		private:
			RPAArchiveHandler rpaHandler;
			std::vector<std::pair<std::string, RPAArchiveHandler::ArchiveIndex>> itemsList;
			CMyComPtr<IInStream> _stream;
			double archiveVersion;
			bool batchLoadEnabled;
			std::wstring archiveFilePath;
			std::vector<uint8_t> archiveDataCache;
			bool hasArchiveCache;
			bool TryGetArchivePath(IArchiveOpenCallback* callback, IInStream* stream);
			bool CreateMemoryCache(IInStream* stream, UInt64 maxSize);
		};

		bool CHandler::CreateMemoryCache(IInStream* stream, UInt64 maxSize) {
			UInt64 streamSize = 0;
			if (FAILED(stream->Seek(0, STREAM_SEEK_END, &streamSize))) {
				return false;
			}
			if (streamSize > maxSize || streamSize == 0) {
				DebugLog(L"Stream too large for memory cache: " + std::to_wstring(streamSize) + L" bytes");
				return false;
			}
			DebugLog(L"Creating memory cache for archive: " + std::to_wstring(streamSize) + L" bytes");
			try {
				archiveDataCache.resize(static_cast<size_t>(streamSize));
			}
			catch (...) {
				DebugLog(L"Failed to allocate memory cache");
				return false;
			}
			if (FAILED(stream->Seek(0, STREAM_SEEK_SET, nullptr))) {
				archiveDataCache.clear();
				return false;
			}
			UInt32 bytesRead = 0;
			UInt64 totalRead = 0;
			const UInt32 chunkSize = 16 * 1024 * 1024;
			while (totalRead < streamSize) {
				UInt32 toRead = static_cast<UInt32>(std::min<UInt64>(chunkSize, streamSize - totalRead));
				HRESULT hr = stream->Read(&archiveDataCache[static_cast<size_t>(totalRead)], toRead, &bytesRead);
				if (FAILED(hr) || bytesRead == 0) {
					DebugLog(L"Failed to read archive data at offset " + std::to_wstring(totalRead));
					archiveDataCache.clear();
					return false;
				}
				totalRead += bytesRead;
			}
			DebugLog(L"Memory cache created successfully");
			hasArchiveCache = true;
			return true;
		}
		bool CHandler::TryGetArchivePath(IArchiveOpenCallback* callback, IInStream* stream) {
			CMyComPtr<IArchiveOpenVolumeCallback> volCallback;
			if (SUCCEEDED(callback->QueryInterface(IID_IArchiveOpenVolumeCallback, (void**)&volCallback)) && volCallback) {
				CMyComPtr<IInStream> volumeStream;
				HRESULT hr = volCallback->GetStream(L"", &volumeStream);
				if (SUCCEEDED(hr) && volumeStream) {
					DebugLog(L"Volume callback available but can't extract path directly");
				}
			}
			UInt64 originalPos = 0;
			if (SUCCEEDED(stream->Seek(0, STREAM_SEEK_CUR, &originalPos))) {
				UInt64 fileSize = 0;
				if (SUCCEEDED(stream->Seek(0, STREAM_SEEK_END, &fileSize))) {
					stream->Seek(originalPos, STREAM_SEEK_SET, nullptr);
					if (fileSize < 500 * 1024 * 1024) {
						DebugLog(L"Attempting to create memory cache for fast access");
						return CreateMemoryCache(stream, 500 * 1024 * 1024);
					}
					else {
						DebugLog(L"Archive too large for memory cache: " + std::to_wstring(fileSize) + L" bytes");
					}
				}
			}
			DebugLog(L"Could not create fast access cache - will use stream mode");
			return false;
		}
		STDMETHODIMP CHandler::GetNumberOfArchiveProperties(UInt32* numProps)
		{
			DebugLog(L"GetNumberOfArchiveProperties called");
			*numProps = ARRAY_SIZE(kArcProps);
			return S_OK;
		}
		STDMETHODIMP CHandler::GetArchivePropertyInfo(UInt32 index, BSTR* name, PROPID* propID, VARTYPE* varType)
		{
			DebugLog(L"GetArchivePropertyInfo called");
			if (index >= ARRAY_SIZE(kArcProps))
				return E_INVALIDARG;
			if (propID)
				*propID = kArcProps[index];
			if (varType)
				*varType = VT_BSTR;
			if (name)
				*name = nullptr;
			return S_OK;
		}
		STDMETHODIMP CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT* value)
		{
			DebugLog(L"GetArchiveProperty called, propID=" + std::to_wstring(propID));
			NCOM::CPropVariant prop;
			if (propID == kpidSubType) {
				std::wstring versionStr;
				double ver = rpaHandler.GetArchiveVersion();
				if (ver == 1.0)
					versionStr = L"RPA-1.0";
				else if (ver == 2.0)
					versionStr = L"RPA-2.0";
				else if (ver == 3.0)
					versionStr = L"RPA-3.0";
				else if (ver == 3.2)
					versionStr = L"RPA-3.2";
				else
					versionStr = L"Unknown";
				prop = versionStr.c_str();
			}
			prop.Detach(value);
			return S_OK;
		}
		STDMETHODIMP CHandler::Open(IInStream* stream, const UInt64*, IArchiveOpenCallback* callback) {
			COM_TRY_BEGIN
				DebugLog(L"=== OPEN CALLED ===");
			Close();
			if (!callback || !stream) {
				DebugLog(L"Open: Invalid parameters");
				return S_FALSE;
			}
			bool hasFilePath = TryGetArchivePath(callback, stream);
			const size_t maxHeaderSize = 256;
			char header[maxHeaderSize];
			UInt32 bytesRead = 0;
			HRESULT result = stream->Seek(0, STREAM_SEEK_SET, nullptr);
			if (FAILED(result)) {
				DebugLog(L"Open: Failed to seek");
				return result;
			}
			result = stream->Read(header, maxHeaderSize, &bytesRead);
			if (FAILED(result) || bytesRead < 8) {
				DebugLog(L"Open: Failed to read header");
				return S_FALSE;
			}
			if (memcmp(header, kSignatureRPA32, sizeof(kSignatureRPA32)) == 0) {
				DebugLog(L"Open: RPA-3.2 signature matched!");
			}
			else if (memcmp(header, kSignatureRPA3, sizeof(kSignatureRPA3)) == 0) {
				DebugLog(L"Open: RPA-3.0 signature matched!");
			}
			else if (memcmp(header, kSignatureRPA2, sizeof(kSignatureRPA2)) == 0) {
				DebugLog(L"Open: RPA-2.0 signature matched!");
			}
			result = stream->Seek(0, STREAM_SEEK_SET, nullptr);
			if (FAILED(result)) {
				DebugLog(L"Open: Failed to reset stream");
				return result;
			}
			if (hasFilePath || CreateMemoryCache(stream, 500 * 1024 * 1024)) {
				if (hasArchiveCache) {
					DebugLog(L"=== MEMORY CACHE CREATED FOR FAST ACCESS ===");
					DebugLog(L"Cache size: " + std::to_wstring(archiveDataCache.size()) + L" bytes");
					batchLoadEnabled = true;
				}
			}
			DebugLog(L"Using stream-based loading" + std::wstring(hasArchiveCache ? L" (with memory cache)" : L""));
			result = rpaHandler.Open(stream, nullptr, callback);
			if (FAILED(result)) {
				DebugLog(L"Open: RPAHandler.Open failed with HRESULT: " + std::to_wstring(result));
				return result;
			}
			_stream = stream;
			itemsList.clear();
			itemsList.reserve(rpaHandler.items.size());
			for (const auto& item : rpaHandler.items) {
				itemsList.push_back(item);
			}
			archiveVersion = rpaHandler.GetArchiveVersion();
			DebugLog(L"Open: Items loaded = " + std::to_wstring(itemsList.size()));
			DebugLog(L"Open: Archive version = " + std::to_wstring(archiveVersion));
			DebugLog(L"Open: Fast mode = " + std::wstring(hasArchiveCache ? L"ENABLED (MEMORY CACHE)" :
				batchLoadEnabled ? L"ENABLED (FILE MAPPING)" : L"DISABLED"));
#ifdef _DEBUG
			for (size_t i = 0; i < std::min(itemsList.size(), (size_t)10); i++) {
				std::wstring path(itemsList[i].first.begin(), itemsList[i].first.end());
				DebugLog(L" [" + std::to_wstring(i) + L"] " + path +
					L" (" + std::to_wstring(itemsList[i].second.length) + L" bytes)");
			}
			if (itemsList.size() > 10) {
				DebugLog(L" ... and " + std::to_wstring(itemsList.size() - 10) + L" more files");
			}
#endif
			DebugLog(L"Open: SUCCESS - Archive opened with " + std::to_wstring(itemsList.size()) + L" items");
			return S_OK;
			COM_TRY_END
		}
		STDMETHODIMP CHandler::Close() {
			DebugLog(L"Close called");
			itemsList.clear();
			rpaHandler.items.clear();
			_stream.Release();
			archiveDataCache.clear();
			archiveDataCache.shrink_to_fit();
			hasArchiveCache = false;
			if (batchLoadEnabled) {
				rpaHandler.CloseBatchLoad();
				batchLoadEnabled = false;
			}
			archiveFilePath.clear();
			return S_OK;
		}
		STDMETHODIMP CHandler::GetNumberOfItems(UInt32* numItems) {
			if (numItems == nullptr) {
				DebugLog(L"GetNumberOfItems: NULL pointer!");
				return E_POINTER;
			}
			*numItems = static_cast<UInt32>(itemsList.size());
			DebugLog(L"GetNumberOfItems: returning " + std::to_wstring(*numItems));
			return S_OK;
		}
		STDMETHODIMP CHandler::GetNumberOfProperties(UInt32* numProps)
		{
			if (numProps == nullptr) {
				DebugLog(L"GetNumberOfProperties: NULL pointer!");
				return E_POINTER;
			}
			*numProps = ARRAY_SIZE(kProps);
			DebugLog(L"GetNumberOfProperties: returning " + std::to_wstring(*numProps));
			return S_OK;
		}
		STDMETHODIMP CHandler::GetPropertyInfo(UInt32 index, BSTR* name, PROPID* propID, VARTYPE* varType)
		{
			DebugLog(L"GetPropertyInfo: index=" + std::to_wstring(index));
			if (index >= ARRAY_SIZE(kProps)) {
				DebugLog(L"GetPropertyInfo: index out of range!");
				return E_INVALIDARG;
			}
			if (propID) {
				*propID = kProps[index];
				DebugLog(L" propID=" + std::to_wstring(kProps[index]));
			}
			if (varType) {
				switch (kProps[index]) {
				case kpidPath:
					*varType = VT_BSTR;
					DebugLog(L" varType=VT_BSTR");
					break;
				case kpidSize:
				case kpidPackSize:
					*varType = VT_UI8;
					DebugLog(L" varType=VT_UI8");
					break;
				default:
					*varType = VT_EMPTY;
				}
			}
			if (name) {
				*name = nullptr;
			}
			return S_OK;
		}
		STDMETHODIMP CHandler::GetProperty(UInt32 index, PROPID propID, PROPVARIANT* value)
		{
			COM_TRY_BEGIN
				DebugLog(L">>> GetProperty CALLED <<<");
			DebugLog(L" index=" + std::to_wstring(index));
			DebugLog(L" propID=" + std::to_wstring(propID));
			if (value == nullptr) {
				DebugLog(L" ERROR: value is NULL!");
				return E_POINTER;
			}
			NCOM::CPropVariant prop;
			if (index >= itemsList.size()) {
				DebugLog(L" ERROR: index out of range! (size=" + std::to_wstring(itemsList.size()) + L")");
				prop.Detach(value);
				return S_OK;
			}
			const auto& item = itemsList[index];
			const std::string& fileName = item.first;
			const auto& fileInfo = item.second;
			switch (propID)
			{
			case kpidPath:
			{
				DebugLog(L" Getting PATH property");
				if (fileName.empty()) {
					DebugLog(L" Path is empty, using fallback");
					prop = L"unnamed.bin";
				}
				else {
					UString widePath;
					for (size_t i = 0; i < fileName.length(); i++) {
						widePath += (wchar_t)(unsigned char)fileName[i];
					}
#ifdef _DEBUG
					std::wstring pathLog = L" Returning path: ";
					for (int i = 0; i < widePath.Len(); i++) {
						pathLog += widePath[i];
					}
					DebugLog(pathLog.c_str());
#endif
					prop = widePath;
				}
			}
			break;
			case kpidSize:
				DebugLog(L" Getting SIZE property: " + std::to_wstring(fileInfo.length));
				prop = (UInt64)fileInfo.length;
				break;
			case kpidPackSize:
			{
				UInt64 packedSize = 0;
				for (const auto& tuple : fileInfo.tuples) {
					packedSize += tuple.second.length;
				}
				DebugLog(L" Getting PACKSIZE property: " + std::to_wstring(packedSize));
				prop = packedSize;
			}
			break;
			case kpidIsDir:
				DebugLog(L" Getting ISDIR property: false");
				prop = false;
				break;
			default:
				DebugLog(L" Unknown propID: " + std::to_wstring(propID));
				break;
			}
			prop.Detach(value);
			return S_OK;
			COM_TRY_END
		}
		STDMETHODIMP CHandler::Extract(const UInt32* indices, UInt32 numItems, Int32 testMode,
			IArchiveExtractCallback* extractCallback) {
			COM_TRY_BEGIN
				DebugLog(L"=== Extract called: numItems=" + std::to_wstring(numItems) + L" ===");
			bool allFilesMode = (numItems == (UInt32)(Int32)-1);
			if (allFilesMode) numItems = static_cast<UInt32>(itemsList.size());
			if (numItems == 0) return S_OK;
			UInt64 totalSize = 0;
			for (UInt32 i = 0; i < numItems; i++) {
				UInt32 index = allFilesMode ? i : indices[i];
				if (index < itemsList.size()) {
					totalSize += itemsList[index].second.length;
				}
			}
			extractCallback->SetTotal(totalSize);
			CLocalProgress* lps = new CLocalProgress;
			CMyComPtr<ICompressProgressInfo> progress = lps;
			lps->Init(extractCallback, false);
			if (hasArchiveCache && numItems > 5) {
				DebugLog(L"=== USING FAST MEMORY-CACHED EXTRACTION ===");
				DebugLog(L"Extracting " + std::to_wstring(numItems) + L" files from memory");
				auto startTime = std::chrono::high_resolution_clock::now();
				UInt64 currentSize = 0;
				for (UInt32 i = 0; i < numItems; i++) {
					UInt32 index = allFilesMode ? i : indices[i];
					if (index >= itemsList.size()) {
						DebugLog(L"Extract: Invalid index " + std::to_wstring(index));
						continue;
					}
					const auto& item = itemsList[index];
					const std::string& fileName = item.first;
					const auto& fileInfo = item.second;
					lps->InSize = currentSize;
					lps->OutSize = currentSize;
					RINOK(lps->SetCur());
					CMyComPtr<ISequentialOutStream> realOutStream;
					Int32 askMode = testMode ? NExtract::NAskMode::kTest : NExtract::NAskMode::kExtract;
					RINOK(extractCallback->GetStream(index, &realOutStream, askMode));
					currentSize += fileInfo.length;
					if (!testMode && !realOutStream) {
						continue;
					}
					RINOK(extractCallback->PrepareOperation(askMode));
					std::vector<uint8_t> fileData;
					fileData.reserve(fileInfo.length);
					for (const auto& tuplePair : fileInfo.tuples) {
						const auto& tuple = tuplePair.second;
						fileData.insert(fileData.end(), tuple.prefix.begin(), tuple.prefix.end());
						size_t dataLength = tuple.length - tuple.prefix.size();
						if (dataLength > 0 && tuple.offset + dataLength <= archiveDataCache.size()) {
							const uint8_t* srcData = &archiveDataCache[static_cast<size_t>(tuple.offset)];
							fileData.insert(fileData.end(), srcData, srcData + dataLength);
						}
					}
					if (!testMode && realOutStream) {
						UInt32 written = 0;
						HRESULT writeResult = realOutStream->Write(fileData.data(),
							static_cast<UInt32>(fileData.size()), &written);
						if (FAILED(writeResult) || written != fileData.size()) {
							DebugLog(L"Extract: Write failed for index " + std::to_wstring(index));
							RINOK(extractCallback->SetOperationResult(NExtract::NOperationResult::kDataError));
							continue;
						}
					}
					realOutStream.Release();
					RINOK(extractCallback->SetOperationResult(NExtract::NOperationResult::kOK));
				}
				auto endTime = std::chrono::high_resolution_clock::now();
				auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
				DebugLog(L"Memory-cached extraction completed in " + std::to_wstring(duration.count()) + L" ms");
				lps->InSize = totalSize;
				lps->OutSize = totalSize;
				DebugLog(L"=== FAST EXTRACTION COMPLETE ===");
				return lps->SetCur();
			}
			if (batchLoadEnabled && numItems > 5) {
				DebugLog(L"=== USING FAST BATCH EXTRACTION ===");
				DebugLog(L"Extracting " + std::to_wstring(numItems) + L" files in parallel");
				auto startTime = std::chrono::high_resolution_clock::now();
				std::vector<std::string> fileNames;
				std::vector<UInt32> validIndices;
				fileNames.reserve(numItems);
				validIndices.reserve(numItems);
				for (UInt32 i = 0; i < numItems; i++) {
					UInt32 index = allFilesMode ? i : indices[i];
					if (index < itemsList.size()) {
						fileNames.push_back(itemsList[index].first);
						validIndices.push_back(index);
					}
				}
				std::vector<std::vector<uint8_t>> outputs;
				HRESULT batchResult = rpaHandler.BatchExtractFiles(fileNames, outputs, 0);
				auto endTime = std::chrono::high_resolution_clock::now();
				auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
				DebugLog(L"Batch extraction completed in " + std::to_wstring(duration.count()) + L" ms");
				if (SUCCEEDED(batchResult)) {
					DebugLog(L"Processing extracted files...");
					UInt64 currentSize = 0;
					for (size_t i = 0; i < validIndices.size(); i++) {
						UInt32 index = validIndices[i];
						const auto& fileInfo = itemsList[index].second;
						lps->InSize = currentSize;
						lps->OutSize = currentSize;
						RINOK(lps->SetCur());
						CMyComPtr<ISequentialOutStream> realOutStream;
						Int32 askMode = testMode ? NExtract::NAskMode::kTest : NExtract::NAskMode::kExtract;
						RINOK(extractCallback->GetStream(index, &realOutStream, askMode));
						currentSize += fileInfo.length;
						if (!testMode && !realOutStream) {
							continue;
						}
						RINOK(extractCallback->PrepareOperation(askMode));
						if (!testMode && realOutStream && i < outputs.size()) {
							UInt32 written = 0;
							HRESULT writeResult = realOutStream->Write(outputs[i].data(),
								static_cast<UInt32>(outputs[i].size()), &written);
							if (FAILED(writeResult) || written != outputs[i].size()) {
								DebugLog(L"Extract: Write failed for index " + std::to_wstring(index));
								RINOK(extractCallback->SetOperationResult(NExtract::NOperationResult::kDataError));
								continue;
							}
						}
						realOutStream.Release();
						RINOK(extractCallback->SetOperationResult(NExtract::NOperationResult::kOK));
					}
					lps->InSize = totalSize;
					lps->OutSize = totalSize;
					DebugLog(L"=== FAST EXTRACTION COMPLETE ===");
					return lps->SetCur();
				}
				else {
					DebugLog(L"Batch extraction failed (HRESULT: " + std::to_wstring(batchResult) + L"), falling back to sequential");
				}
			}
			DebugLog(L"Using sequential extraction");
			if (!_stream && !hasArchiveCache) {
				DebugLog(L"Extract: No stream or cache available!");
				return E_FAIL;
			}
			UInt64 currentSize = 0;
			for (UInt32 i = 0; i < numItems; i++) {
				UInt32 index = allFilesMode ? i : indices[i];
				if (index >= itemsList.size()) {
					DebugLog(L"Extract: Invalid index " + std::to_wstring(index));
					continue;
				}
				const auto& item = itemsList[index];
				const std::string& fileName = item.first;
				const auto& fileInfo = item.second;
				lps->InSize = currentSize;
				lps->OutSize = currentSize;
				RINOK(lps->SetCur());
				CMyComPtr<ISequentialOutStream> realOutStream;
				Int32 askMode = testMode ? NExtract::NAskMode::kTest : NExtract::NAskMode::kExtract;
				RINOK(extractCallback->GetStream(index, &realOutStream, askMode));
				currentSize += fileInfo.length;
				if (!testMode && !realOutStream) {
					continue;
				}
				RINOK(extractCallback->PrepareOperation(askMode));
				std::vector<uint8_t> fileData;
				HRESULT extractResult = S_OK;
				if (hasArchiveCache) {
					fileData.reserve(fileInfo.length);
					for (const auto& tuplePair : fileInfo.tuples) {
						const auto& tuple = tuplePair.second;
						fileData.insert(fileData.end(), tuple.prefix.begin(), tuple.prefix.end());
						size_t dataLength = tuple.length - tuple.prefix.size();
						if (dataLength > 0 && tuple.offset + dataLength <= archiveDataCache.size()) {
							const uint8_t* srcData = &archiveDataCache[static_cast<size_t>(tuple.offset)];
							fileData.insert(fileData.end(), srcData, srcData + dataLength);
						}
					}
				}
				else if (batchLoadEnabled) {
					std::vector<std::string> singleFile = { fileName };
					std::vector<std::vector<uint8_t>> singleOutput;
					extractResult = rpaHandler.BatchExtractFiles(singleFile, singleOutput, 1);
					if (SUCCEEDED(extractResult) && !singleOutput.empty()) {
						fileData = std::move(singleOutput[0]);
					}
				}
				else {
					extractResult = rpaHandler.ExtractFile(_stream, fileName, fileData);
				}
				if (FAILED(extractResult)) {
					DebugLog(L"Extract: Failed to extract file " + std::to_wstring(index));
					RINOK(extractCallback->SetOperationResult(NExtract::NOperationResult::kDataError));
					continue;
				}
				if (!testMode && realOutStream) {
					UInt32 written = 0;
					HRESULT writeResult = realOutStream->Write(fileData.data(),
						static_cast<UInt32>(fileData.size()), &written);
					if (FAILED(writeResult) || written != fileData.size()) {
						DebugLog(L"Extract: Write failed for index " + std::to_wstring(index));
						RINOK(extractCallback->SetOperationResult(NExtract::NOperationResult::kDataError));
						continue;
					}
				}
				realOutStream.Release();
				RINOK(extractCallback->SetOperationResult(NExtract::NOperationResult::kOK));
			}
			lps->InSize = totalSize;
			lps->OutSize = totalSize;
			return lps->SetCur();
			COM_TRY_END
		}
		STDMETHODIMP CHandler::GetStream(UInt32 index, ISequentialInStream** stream) {
			COM_TRY_BEGIN
				DebugLog(L"GetStream called: index=" + std::to_wstring(index));

			if (index >= itemsList.size()) {
				return E_FAIL;
			}

			*stream = nullptr;

			const auto& item = itemsList[index];
			const std::string& fileName = item.first;
			std::vector<uint8_t> fileData;
			HRESULT result = S_OK;

			if (hasArchiveCache) {
				const auto& fileInfo = item.second;
				fileData.reserve(fileInfo.length);

				for (const auto& tuplePair : fileInfo.tuples) {
					const auto& tuple = tuplePair.second;
					fileData.insert(fileData.end(), tuple.prefix.begin(), tuple.prefix.end());

					size_t dataLength = tuple.length - tuple.prefix.size();
					if (dataLength > 0 && tuple.offset + dataLength <= archiveDataCache.size()) {
						const uint8_t* srcData = &archiveDataCache[static_cast<size_t>(tuple.offset)];
						fileData.insert(fileData.end(), srcData, srcData + dataLength);
					}
				}
			}
			else if (batchLoadEnabled) {
				std::vector<std::string> singleFile = { fileName };
				std::vector<std::vector<uint8_t>> singleOutput;
				result = rpaHandler.BatchExtractFiles(singleFile, singleOutput, 1);
				if (SUCCEEDED(result) && !singleOutput.empty()) {
					fileData = std::move(singleOutput[0]);
				}
			}
			else {
				if (!_stream) return E_FAIL;
				result = rpaHandler.ExtractFile(_stream, fileName, fileData);
			}

			if (FAILED(result)) {
				DebugLog(L"GetStream: Failed to extract file");
				return E_FAIL;
			}

			CBufInStream* streamSpec = new CBufInStream;
			CMyComPtr<ISequentialInStream> streamTemp = streamSpec;

			streamSpec->Init(reinterpret_cast<const Byte*>(fileData.data()),
				static_cast<UInt32>(fileData.size()));

			*stream = streamTemp.Detach();
			return S_OK;
			COM_TRY_END
		}
		static const Byte k_Signature[] = { 'R', 'P', 'A', '-', '3', '.', '0', ' ' };
		REGISTER_ARC_I(
			"RPA",
			"rpa rpi",
			0,
			0xC9,
			k_Signature,
			0,
			NArcInfoFlags::kFindSignature,
			NULL)
	}
}