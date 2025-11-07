#include "stdafx.h"
#pragma warning (disable: 5043)
#include "../../../Common/ComTry.h"
#include "../../../Common/MyString.h"
#include "../../../Windows/PropVariant.h"
#include "../../Common/ProgressUtils.h"
#include "../../Common/RegisterArc.h"
#include "../../Common/StreamObjects.h"
#include "../../Archive/IArchive.h"
#include "../../Common/LimitedStreams.h"
#include "../../Common/StreamUtils.h"
#include "Exfat.h"
#include <cstdint>

#ifdef _DEBUG
#include <fstream>
#endif

using namespace NWindows;
namespace NArchive {
	namespace NExFAT {

		// ExFAT signature at offset 3: "EXFAT   " (with spaces)
		static const Byte kSignature[] = { 0x45, 0x58, 0x46, 0x41, 0x54, 0x20, 0x20, 0x20 };

		static const Byte kProps[] =
		{
			kpidPath,
			kpidSize,
			kpidIsDir,
			kpidMTime,
			kpidCTime,
			kpidATime,
			kpidAttrib,
		};

#ifdef _DEBUG
		void DebugLog(const wchar_t* message) {
			std::wofstream logFile;
			logFile.open(L"C:\\exfat_debug.log", std::ios::app);
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

				STDMETHOD(Open)(IInStream* stream, const UInt64* maxCheckStartPosition, IArchiveOpenCallback* openCallback);
			STDMETHOD(Close)();
			STDMETHOD(GetNumberOfItems)(UInt32* numItems);
			STDMETHOD(GetProperty)(UInt32 index, PROPID propID, PROPVARIANT* value);
			STDMETHOD(Extract)(const UInt32* indices, UInt32 numItems, Int32 testMode, IArchiveExtractCallback* extractCallback);
			STDMETHOD(GetArchiveProperty)(PROPID propID, PROPVARIANT* value);
			STDMETHOD(GetNumberOfProperties)(UInt32* numProps);
			STDMETHOD(GetPropertyInfo)(UInt32 index, BSTR* name, PROPID* propID, VARTYPE* varType);
			STDMETHOD(GetNumberOfArchiveProperties)(UInt32* numProps);
			STDMETHOD(GetArchivePropertyInfo)(UInt32 index, BSTR* name, PROPID* propID, VARTYPE* varType);
			STDMETHOD(GetStream)(UInt32 index, ISequentialInStream** stream);

			CHandler() {
				DebugLog(L"CHandler constructed");
			}

			CHandler(ExFATHandler& handler) : exfatHandler(handler) {
				DebugLog(L"CHandler constructed with handler");
			}

		private:
			ExFATHandler exfatHandler;
			std::vector<ExFATHandler::FileInfo> items;
			CMyComPtr<IInStream> _stream;
		};

		/**
		 * @brief Retrieves the number of archive-level properties.
		 */
		STDMETHODIMP CHandler::GetNumberOfArchiveProperties(UInt32* numProps)
		{
			DebugLog(L"GetNumberOfArchiveProperties called");
			*numProps = 0;
			return S_OK;
		}

		/**
		 * @brief Retrieves archive-level property info.
		 */
		STDMETHODIMP CHandler::GetArchivePropertyInfo(UInt32 index, BSTR* name, PROPID* propID, VARTYPE* varType)
		{
			DebugLog(L"GetArchivePropertyInfo called");
			return E_NOTIMPL;
		}

		/**
		 * @brief Retrieves a value for a specific archive-level property.
		 */
		STDMETHODIMP CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT* value)
		{
			DebugLog(L"GetArchiveProperty called, propID=" + std::to_wstring(propID));
			NCOM::CPropVariant prop;
			prop.Detach(value);
			return S_OK;
		}

		/**
		 * @brief Opens the ExFAT image for reading.
		 */
		STDMETHODIMP CHandler::Open(IInStream* stream, const UInt64* maxCheckStartPosition, IArchiveOpenCallback* callback) {
			DebugLog(L"=== OPEN CALLED ===");
			Close();

			if (!stream) {
				DebugLog(L"Open: Invalid stream");
				return S_FALSE;
			}

			// Check ExFAT signature at offset 3
			const size_t magicOffset = 3;
			const size_t magicSize = sizeof(kSignature);
			char magic[magicSize];

			HRESULT result = stream->Seek(magicOffset, STREAM_SEEK_SET, nullptr);
			if (FAILED(result)) {
				DebugLog(L"Open: Failed to seek to magic offset");
				return result;
			}

			result = stream->Read(magic, magicSize, nullptr);
			if (FAILED(result)) {
				DebugLog(L"Open: Failed to read magic");
				return result;
			}

			if (memcmp(magic, kSignature, magicSize) != 0) {
				DebugLog(L"Open: Magic signature doesn't match");
				return S_FALSE;
			}

			DebugLog(L"Open: ExFAT signature matched!");

			// Reset stream position
			result = stream->Seek(0, STREAM_SEEK_SET, nullptr);
			if (FAILED(result)) {
				DebugLog(L"Open: Failed to reset stream");
				return result;
			}

			// Get file size
			UInt64 fileSize = 0;
			if (maxCheckStartPosition && *maxCheckStartPosition > 0) {
				fileSize = *maxCheckStartPosition;
			}
			else {
				result = stream->Seek(0, STREAM_SEEK_END, &fileSize);
				if (FAILED(result)) {
					DebugLog(L"Open: Failed to get file size");
					return result;
				}
				stream->Seek(0, STREAM_SEEK_SET, nullptr);
			}

			// Open ExFAT handler
			result = exfatHandler.Open(stream, &fileSize, callback);
			if (FAILED(result)) {
				DebugLog(L"Open: ExFATHandler.Open failed with code " + std::to_wstring(result));
				return result;
			}

			items = exfatHandler.items;
			_stream = stream;

			DebugLog(L"Open: Items loaded = " + std::to_wstring(items.size()));
#ifdef _DEBUG
			for (size_t i = 0; i < items.size(); i++) {
				std::wstring path(items[i].path.begin(), items[i].path.end());
				DebugLog(L"  [" + std::to_wstring(i) + L"] " + path +
					L" (size: " + std::to_wstring(items[i].size) +
					L", cluster: " + std::to_wstring(items[i].firstCluster) + L")");
			}
#endif

			DebugLog(L"Open: SUCCESS - ExFAT image opened with " + std::to_wstring(items.size()) + L" items");

			return S_OK;
		}

		/**
		 * @brief Closes the archive and releases all associated resources.
		 */
		STDMETHODIMP CHandler::Close() {
			DebugLog(L"Close called");
			items.clear();
			exfatHandler.items.clear();
			_stream.Release();
			return S_OK;
		}

		/**
		 * @brief Retrieves the total number of items in the archive.
		 */
		STDMETHODIMP CHandler::GetNumberOfItems(UInt32* numItems) {
			if (numItems == nullptr) {
				DebugLog(L"GetNumberOfItems: NULL pointer!");
				return E_POINTER;
			}

			*numItems = static_cast<UInt32>(items.size());
			DebugLog(L"GetNumberOfItems: returning " + std::to_wstring(*numItems));

			return S_OK;
		}

		/**
		 * @brief Retrieves the total number of properties available per item.
		 */
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

		/**
		 * @brief Retrieves property info for a given index.
		 */
		STDMETHODIMP CHandler::GetPropertyInfo(UInt32 index, BSTR* name, PROPID* propID, VARTYPE* varType)
		{
			DebugLog(L"GetPropertyInfo: index=" + std::to_wstring(index));

			if (index >= ARRAY_SIZE(kProps)) {
				DebugLog(L"GetPropertyInfo: index out of range!");
				return E_INVALIDARG;
			}

			if (propID) {
				*propID = kProps[index];
				DebugLog(L"  propID=" + std::to_wstring(kProps[index]));
			}

			if (varType) {
				switch (kProps[index]) {
				case kpidPath:
					*varType = VT_BSTR;
					DebugLog(L"  varType=VT_BSTR");
					break;
				case kpidSize:
					*varType = VT_UI8;
					DebugLog(L"  varType=VT_UI8");
					break;
				case kpidIsDir:
					*varType = VT_BOOL;
					DebugLog(L"  varType=VT_BOOL");
					break;
				case kpidMTime:
				case kpidCTime:
				case kpidATime:
					*varType = VT_FILETIME;
					DebugLog(L"  varType=VT_FILETIME");
					break;
				case kpidAttrib:
					*varType = VT_UI4;
					DebugLog(L"  varType=VT_UI4");
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

		/**
		 * @brief Converts ExFAT timestamp to Windows FILETIME.
		 * ExFAT timestamps are stored as seconds since 1980-01-01 00:00:00.
		 */
		static void ExFATTimeToFileTime(uint32_t exfatTime, FILETIME* ft) {
			if (exfatTime == 0) {
				ft->dwLowDateTime = 0;
				ft->dwHighDateTime = 0;
				return;
			}

			const uint64_t EPOCH_DIFF = 11644473600ULL;
			const uint64_t TICKS_PER_SECOND = 10000000ULL;

			uint64_t windowsTime = (exfatTime + EPOCH_DIFF) * TICKS_PER_SECOND;
			ft->dwLowDateTime = (DWORD)(windowsTime & 0xFFFFFFFF);
			ft->dwHighDateTime = (DWORD)(windowsTime >> 32);
		}

		/**
		 * @brief Retrieves a property value for a specific item.
		 */
		STDMETHODIMP CHandler::GetProperty(UInt32 index, PROPID propID, PROPVARIANT* value)
		{
			DebugLog(L">>> GetProperty CALLED <<<");
			DebugLog(L"  index=" + std::to_wstring(index));
			DebugLog(L"  propID=" + std::to_wstring(propID));

			if (value == nullptr) {
				DebugLog(L"  ERROR: value is NULL!");
				return E_POINTER;
			}

			NCOM::CPropVariant prop;

			if (index >= items.size()) {
				DebugLog(L"  ERROR: index out of range! (size=" + std::to_wstring(items.size()) + L")");
				prop.Detach(value);
				return S_OK;
			}

			const auto& item = items[index];

			switch (propID)
			{
			case kpidPath:
			{
				DebugLog(L"  Getting PATH property");
				if (item.path.empty()) {
					DebugLog(L"    Path is empty, using fallback");
					prop = L"unnamed";
				}
				else {
					UString widePath;
					const std::string& pathStr = item.path;

					for (size_t i = 0; i < pathStr.length(); i++) {
						widePath += (wchar_t)(unsigned char)pathStr[i];
					}

#ifdef _DEBUG
					std::wstring pathLog = L"    Returning path: ";
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
				DebugLog(L"  Getting SIZE property: " + std::to_wstring(item.size));
				prop = (UInt64)item.size;
				break;

			case kpidIsDir:
				DebugLog(L"  Getting ISDIR property: " + std::to_wstring(item.isDirectory));
				prop = item.isDirectory;
				break;

			case kpidMTime:
			{
				DebugLog(L"  Getting MTIME property");
				FILETIME ft;
				ExFATTimeToFileTime(item.modifyTime, &ft);
				prop = ft;
			}
			break;

			case kpidCTime:
			{
				DebugLog(L"  Getting CTIME property");
				FILETIME ft;
				ExFATTimeToFileTime(item.createTime, &ft);
				prop = ft;
			}
			break;

			case kpidATime:
			{
				DebugLog(L"  Getting ATIME property");
				FILETIME ft;
				ExFATTimeToFileTime(item.accessTime, &ft);
				prop = ft;
			}
			break;

			case kpidAttrib:
				DebugLog(L"  Getting ATTRIB property: " + std::to_wstring(item.attributes));
				prop = (UInt32)item.attributes;
				break;

			default:
				DebugLog(L"  Unknown propID: " + std::to_wstring(propID));
				break;
			}

			prop.Detach(value);
			return S_OK;
		}

		/**
		 * @brief Extracts one or more items from the ExFAT image.
		 */
		STDMETHODIMP CHandler::Extract(const UInt32* indices, UInt32 numItems, Int32 testMode, IArchiveExtractCallback* extractCallback) {
			DebugLog(L"Extract called: numItems=" + std::to_wstring(numItems));

			bool allFilesMode = (numItems == (UInt32)(Int32)-1);
			if (allFilesMode) numItems = static_cast<UInt32>(items.size());
			if (numItems == 0) return S_OK;

			// Calculate total size
			UInt64 totalSize = 0;
			for (UInt32 i = 0; i < numItems; i++) {
				UInt32 index = allFilesMode ? i : indices[i];
				if (!items[index].isDirectory) {
					totalSize += items[index].size;
				}
			}
			extractCallback->SetTotal(totalSize);

			CLocalProgress* lps = new CLocalProgress;
			CMyComPtr<ICompressProgressInfo> progress = lps;
			lps->Init(extractCallback, false);

			UInt64 currentTotalSize = 0;

			for (UInt32 i = 0; i < numItems; i++) {
				lps->InSize = currentTotalSize;
				lps->OutSize = currentTotalSize;
				RINOK(lps->SetCur());

				UInt32 index = allFilesMode ? i : indices[i];
				auto& item = items[index];

				CMyComPtr<ISequentialOutStream> realOutStream;
				Int32 askMode = testMode ? NExtract::NAskMode::kTest : NExtract::NAskMode::kExtract;

				RINOK(extractCallback->GetStream(index, &realOutStream, askMode));

				// Skip directories
				if (item.isDirectory) {
					RINOK(extractCallback->PrepareOperation(askMode));
					RINOK(extractCallback->SetOperationResult(NExtract::NOperationResult::kOK));
					continue;
				}

				if (!testMode && !realOutStream) {
					currentTotalSize += item.size;
					continue;
				}

				RINOK(extractCallback->PrepareOperation(askMode));

				// Extract file data
				std::vector<uint8_t> fileData;
				HRESULT hr = exfatHandler.ExtractFile(_stream, item, fileData);

				if (FAILED(hr)) {
					DebugLog(L"Extract: Failed to extract file at index " + std::to_wstring(index));
					RINOK(extractCallback->SetOperationResult(NExtract::NOperationResult::kDataError));
					continue;
				}

				// Write data
				if (!testMode && realOutStream) {
					UInt32 bytesWritten = 0;
					HRESULT writeResult = realOutStream->Write(fileData.data(), (UInt32)fileData.size(), &bytesWritten);
					if (FAILED(writeResult) || bytesWritten != fileData.size()) {
						DebugLog(L"Extract: Write failed for index " + std::to_wstring(index));
						RINOK(extractCallback->SetOperationResult(NExtract::NOperationResult::kDataError));
						continue;
					}
				}

				currentTotalSize += item.size;
				realOutStream.Release();
				RINOK(extractCallback->SetOperationResult(NExtract::NOperationResult::kOK));
			}

			lps->InSize = totalSize;
			lps->OutSize = totalSize;
			return lps->SetCur();
		}

		/**
		 * @brief Retrieves a stream corresponding to a specific item in the archive.
		 */
		STDMETHODIMP CHandler::GetStream(UInt32 index, ISequentialInStream** stream) {
			DebugLog(L"GetStream called: index=" + std::to_wstring(index));

			if (index >= items.size()) {
				return E_FAIL;
			}

			*stream = nullptr;

			auto& item = items[index];
			if (item.isDirectory) {
				return S_OK;
			}

			// Extract file data
			std::vector<uint8_t> fileData;
			HRESULT hr = exfatHandler.ExtractFile(_stream, item, fileData);
			if (FAILED(hr)) {
				DebugLog(L"GetStream: Failed to extract file at index " + std::to_wstring(index));
				return E_FAIL;
			}

			CBufInStream* streamSpec = new CBufInStream;
			CMyComPtr<ISequentialInStream> streamTemp = streamSpec;

			streamSpec->Init(fileData.data(), static_cast<UInt32>(fileData.size()));
			*stream = streamTemp.Detach();

			DebugLog(L"GetStream: Successfully created stream for index " + std::to_wstring(index));
			return S_OK;
		}

		REGISTER_ARC_I(
			"ExFAT",
			"img exfat",
			0,
			0xC5,
			kSignature,
			3,  // Signature offset
			NArcInfoFlags::kFindSignature,
			0,
			nullptr)

	}
}