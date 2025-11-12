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
#include "STKHandler.h"
#include <cstdint>

#ifdef _DEBUG
#include <fstream>
#endif

using namespace NWindows;
namespace NArchive {
	namespace NSTK {

		// STK format signatures
		static const char kSignatureSTK20[] = "STK2.0";
		static const char kSignatureSTK21[] = "STK2.1";

		static const Byte kProps[] =
		{
			kpidPath,
			kpidSize,
			kpidPackSize,
			kpidMTime,
			kpidCTime,
		};

#ifdef _DEBUG
		void DebugLog(const wchar_t* message) {
			std::wofstream logFile;
			logFile.open(L"C:\\stk_debug.log", std::ios::app);
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

			STKArchiveHandler STKHandler;
			std::vector<STKArchiveHandler::FileInfo> items;
			CMyComPtr<IInStream> _stream;
		};

		/**
		 * @brief Retrieves the number of archive-level properties.
		 */
		STDMETHODIMP CHandler::GetNumberOfArchiveProperties(UInt32* numProps)
		{
			DebugLog(L"GetNumberOfArchiveProperties called");
			*numProps = 1; // Just version
			return S_OK;
		}

		/**
		 * @brief Retrieves archive-level property info.
		 */
		STDMETHODIMP CHandler::GetArchivePropertyInfo(UInt32 index, BSTR* name, PROPID* propID, VARTYPE* varType)
		{
			DebugLog(L"GetArchivePropertyInfo called");
			if (index != 0)
				return E_INVALIDARG;

			if (propID)
				*propID = kpidComment;
			if (varType)
				*varType = VT_BSTR;
			if (name)
				*name = nullptr;

			return S_OK;
		}

		/**
		 * @brief Retrieves a value for a specific archive-level property.
		 */
		STDMETHODIMP CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT* value)
		{
			DebugLog(L"GetArchiveProperty called, propID=" + std::to_wstring(propID));
			NCOM::CPropVariant prop;

			if (propID == kpidComment) {
				wchar_t versionStr[32];
				swprintf_s(versionStr, L"STK Version %.1f", STKHandler.version);
				prop = versionStr;
			}

			prop.Detach(value);
			return S_OK;
		}

		/**
		 * @brief Opens the STK archive for reading.
		 */
		STDMETHODIMP CHandler::Open(IInStream* stream, const UInt64*, IArchiveOpenCallback* callback) {
			DebugLog(L"=== OPEN CALLED ===");
			Close();

			if (!stream) {
				DebugLog(L"Open: Invalid stream");
				return S_FALSE;
			}

			// Save stream for later extraction
			_stream = stream;

			// Try to detect STK format
			char header[6] = { 0 };
			UInt32 bytesRead = 0;
			HRESULT result = stream->Read(header, 6, &bytesRead);

			if (FAILED(result)) {
				DebugLog(L"Open: Failed to read header");
				return result;
			}

			// Reset to beginning
			RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));

			// Check if it's STK 2.0/2.1 or STK 1.0
			bool isSTK20 = (bytesRead == 6 && memcmp(header, kSignatureSTK20, 6) == 0);
			bool isSTK21 = (bytesRead == 6 && memcmp(header, kSignatureSTK21, 6) == 0);

			if (isSTK20) {
				DebugLog(L"Open: Detected STK 2.0 format");
			}
			else if (isSTK21) {
				DebugLog(L"Open: Detected STK 2.1 format");
			}
			else {
				// Try to parse as STK 1.0
				DebugLog(L"Open: Attempting STK 1.0 format");
			}

			// Open the archive
			result = STKHandler.Open(stream, nullptr, callback);
			if (FAILED(result)) {
				DebugLog(L"Open: STKHandler.Open failed");
				return result;
			}

			items = STKHandler.items;

			DebugLog(L"Open: Items loaded = " + std::to_wstring(items.size()));

#ifdef _DEBUG
			for (size_t i = 0; i < items.size(); i++) {
				std::wstring path(items[i].path.begin(), items[i].path.end());
				DebugLog(L"  [" + std::to_wstring(i) + L"] " + path +
					L" (size=" + std::to_wstring(items[i].uncompressed_size) +
					L", compressed=" + std::to_wstring(items[i].size) +
					L", compression=" + std::to_wstring(items[i].compression) + L")");
			}
#endif

			DebugLog(L"Open: SUCCESS - Archive opened with " + std::to_wstring(items.size()) + L" items");
			return S_OK;
		}

		/**
		 * @brief Closes the archive and releases resources.
		 */
		STDMETHODIMP CHandler::Close() {
			DebugLog(L"Close called");
			items.clear();
			STKHandler.items.clear();
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
		 * @brief Retrieves the total number of properties per item.
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
				case kpidPackSize:
					*varType = VT_UI8;
					DebugLog(L"  varType=VT_UI8");
					break;
				case kpidMTime:
				case kpidCTime:
					*varType = VT_FILETIME;
					DebugLog(L"  varType=VT_FILETIME");
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
		 * @brief Helper to parse STK 2.0/2.1 timestamp string to FILETIME
		 */
		static bool ParseSTKTimestamp(const std::string& timeStr, FILETIME* ft) {
			if (timeStr.length() != 14) return false;

			SYSTEMTIME st = { 0 };
			// Format: DDMMYYYYHHMMSS
			st.wDay = atoi(timeStr.substr(0, 2).c_str());
			st.wMonth = atoi(timeStr.substr(2, 2).c_str());
			st.wYear = atoi(timeStr.substr(4, 4).c_str());
			st.wHour = atoi(timeStr.substr(8, 2).c_str());
			st.wMinute = atoi(timeStr.substr(10, 2).c_str());
			st.wSecond = atoi(timeStr.substr(12, 2).c_str());

			return SystemTimeToFileTime(&st, ft) != 0;
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
					prop = L"unnamed.bin";
				}
				else {
					UString widePath;
					for (size_t i = 0; i < item.path.length(); i++) {
						widePath += (wchar_t)(unsigned char)item.path[i];
					}

#ifdef _DEBUG
					std::wstring pathLog = L"    Returning path: " + std::wstring(widePath);
					DebugLog(pathLog.c_str());
#endif

					prop = widePath;
				}
			}
			break;

			case kpidSize:
				DebugLog(L"  Getting SIZE property: " + std::to_wstring(item.uncompressed_size));
				prop = (UInt64)item.uncompressed_size;
				break;

			case kpidPackSize:
				DebugLog(L"  Getting PACKSIZE property: " + std::to_wstring(item.size));
				prop = (UInt64)item.size;
				break;

			case kpidMTime:
			{
				DebugLog(L"  Getting MTIME property");
				if (!item.modified.empty()) {
					FILETIME ft;
					if (ParseSTKTimestamp(item.modified, &ft)) {
						prop = ft;
					}
				}
			}
			break;

			case kpidCTime:
			{
				DebugLog(L"  Getting CTIME property");
				if (!item.created.empty()) {
					FILETIME ft;
					if (ParseSTKTimestamp(item.created, &ft)) {
						prop = ft;
					}
				}
			}
			break;

			case kpidIsDir:
				DebugLog(L"  Getting ISDIR property: false");
				prop = false;
				break;

			default:
				DebugLog(L"  Unknown propID: " + std::to_wstring(propID));
				break;
			}

			prop.Detach(value);
			return S_OK;
		}

		/**
		 * @brief Extracts one or more items from the archive.
		 */
		STDMETHODIMP CHandler::Extract(const UInt32* indices, UInt32 numItems, Int32 testMode, IArchiveExtractCallback* extractCallback) {
			DebugLog(L"Extract called: numItems=" + std::to_wstring(numItems));

			if (!_stream) {
				DebugLog(L"Extract: No stream available");
				return E_FAIL;
			}

			bool allFilesMode = (numItems == (UInt32)(Int32)-1);
			if (allFilesMode) numItems = static_cast<UInt32>(items.size());
			if (numItems == 0) return S_OK;

			// Calculate total size
			UInt64 totalSize = 0, currentSize = 0;
			for (size_t i = 0; i < numItems; i++) {
				UInt32 index = allFilesMode ? i : indices[i];
				totalSize += items[index].uncompressed_size > 0 ?
					items[index].uncompressed_size : items[index].size;
			}
			extractCallback->SetTotal(totalSize);

			CLocalProgress* lps = new CLocalProgress;
			CMyComPtr<ICompressProgressInfo> progress = lps;
			lps->Init(extractCallback, false);

			for (UInt32 i = 0; i < numItems; i++) {
				lps->InSize = currentSize;
				lps->OutSize = currentSize;
				RINOK(lps->SetCur());

				CMyComPtr<ISequentialOutStream> realOutStream;
				Int32 askMode = testMode ? NExtract::NAskMode::kTest : NExtract::NAskMode::kExtract;
				UInt32 index = allFilesMode ? i : indices[i];
				auto& item = items[index];

				RINOK(extractCallback->GetStream(index, &realOutStream, askMode));
				if (!testMode && !realOutStream) {
					continue;
				}

				RINOK(extractCallback->PrepareOperation(askMode));

				// Extract the file if not already decompressed
				if (item.decompressedData.empty()) {
					DebugLog(L"Extract: Decompressing item " + std::to_wstring(index));
					HRESULT hr = STKHandler.ExtractFile(_stream, item);
					if (FAILED(hr)) {
						DebugLog(L"Extract: Failed to decompress item " + std::to_wstring(index));
						return hr;
					}
				}

				// Write decompressed data
				if (!item.decompressedData.empty()) {
					HRESULT writeResult = realOutStream->Write(
						item.decompressedData.data(),
						(UInt32)item.decompressedData.size(),
						NULL
					);
					if (FAILED(writeResult)) {
						DebugLog(L"Extract: Write failed for index " + std::to_wstring(index));
						return writeResult;
					}
				}

				currentSize += item.decompressedData.size();
				realOutStream.Release();
				RINOK(extractCallback->SetOperationResult(NExtract::NOperationResult::kOK));
			}

			lps->InSize = totalSize;
			lps->OutSize = totalSize;
			return lps->SetCur();
		}

		/**
		 * @brief Retrieves a stream for a specific item.
		 */
		STDMETHODIMP CHandler::GetStream(UInt32 index, ISequentialInStream** stream) {
			DebugLog(L"GetStream called: index=" + std::to_wstring(index));

			if (index >= items.size()) {
				return E_FAIL;
			}

			*stream = nullptr;

			auto& item = items[index];

			// Extract if not already done
			if (item.decompressedData.empty() && _stream) {
				HRESULT hr = STKHandler.ExtractFile(_stream, item);
				if (FAILED(hr)) {
					DebugLog(L"GetStream: Failed to extract item " + std::to_wstring(index));
					return hr;
				}
			}

			if (item.decompressedData.empty()) {
				return E_FAIL;
			}

			CBufInStream* streamSpec = new CBufInStream;
			CMyComPtr<ISequentialInStream> streamTemp = streamSpec;

			streamSpec->Init(
				reinterpret_cast<const Byte*>(item.decompressedData.data()),
				static_cast<UInt32>(item.decompressedData.size())
			);

			*stream = streamTemp.Detach();
			return S_OK;
		}

		static const Byte k_Signature[] = { 'S', 'T', 'K', '2', '.', '0' };

		static UInt32 __stdcall  IsArc_STK(const Byte* p, size_t size)
		{
			if (size < 6) return k_IsArc_Res_NEED_MORE;
			if (memcmp(p, kSignatureSTK20, 6) == 0) return k_IsArc_Res_YES;
			if (memcmp(p, kSignatureSTK21, 6) == 0) return k_IsArc_Res_YES;

			return k_IsArc_Res_NO;
		}

		// Register the STK archive handler
		REGISTER_ARC_I(
			"STK",           
			"stk itk ltk jtk", 
			0,              
			0xE1,            
			k_Signature,              
			0,              
			NArcInfoFlags::kStartOpen,
			IsArc_STK)      


	}
}