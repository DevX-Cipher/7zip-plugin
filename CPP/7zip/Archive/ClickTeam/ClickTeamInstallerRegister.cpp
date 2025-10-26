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
#include "ClickTeamInstallerHandler.h"
#include <cstdint>

#ifdef _DEBUG
#include <fstream>
#endif

using namespace NWindows;
namespace NArchive {
	namespace NZzz {

		const unsigned char kSignature[] = { 0x77, 0x77, 0x67, 0x54, 0x29, 0x48 };

		static const Byte kProps[] =
		{
				kpidPath,
				kpidSize,
				kpidPackSize,
		};

#ifdef _DEBUG
		void DebugLog(const wchar_t* message) {
			std::wofstream logFile;
			logFile.open(L"C:\\clickteam_debug.log", std::ios::app);
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

			CHandler(ClickTeamInstallerHandler& handler) : ClickHandler(handler) {
				DebugLog(L"CHandler constructed with handler");
			}

			ClickTeamInstallerHandler ClickHandler;
			std::vector<ClickTeamInstallerHandler::FileInfo> items;
		};

		/**
		 * @brief Retrieves the number of archive-level properties.
		 *
		 * @param numProps Output parameter that receives the number of archive properties.
		 * @return HRESULT Always returns S_OK.
		 */
		STDMETHODIMP CHandler::GetNumberOfArchiveProperties(UInt32* numProps)
		{
			DebugLog(L"GetNumberOfArchiveProperties called");
			*numProps = 0;
			return S_OK;
		}

		/**
		 * @brief Retrieves archive-level property info.
		 *
		 * @param index Index of the archive property (0-based).
		 * @param name Optional output parameter for the property name (BSTR).
		 * @param propID Output parameter that receives the property ID.
		 * @param varType Output parameter that receives the VARIANT type of the property.
		 * @return HRESULT Always returns E_NOTIMPL.
		 */
		STDMETHODIMP CHandler::GetArchivePropertyInfo(UInt32 index, BSTR* name, PROPID* propID, VARTYPE* varType)
		{
			DebugLog(L"GetArchivePropertyInfo called");
			return E_NOTIMPL;
		}

		/**
		 * @brief Retrieves a value for a specific archive-level property.
		 *
		 * @param propID Archive property ID.
		 * @param value Output parameter that receives the property value.
		 * @return HRESULT Always returns S_OK (property is empty).
		 */
		STDMETHODIMP CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT* value)
		{
			DebugLog(L"GetArchiveProperty called, propID=" + std::to_wstring(propID));
			NCOM::CPropVariant prop;
			prop.Detach(value);
			return S_OK;
		}
		/**
		 * @brief Opens the archive for reading.
		 *
		 * Verifies the archive's signature and initializes internal structures.
		 *
		 * @param stream Input stream representing the archive file.
		 * @param maxCheckStartPosition Not used (pass nullptr).
		 * @param callback Callback interface for progress and extraction info.
		 * @return HRESULT S_OK if successful, S_FALSE if the signature does not match, or appropriate HRESULT on error.
		 */
		STDMETHODIMP CHandler::Open(IInStream* stream, const UInt64*, IArchiveOpenCallback* callback) {
			DebugLog(L"=== OPEN CALLED ===");
			Close();

			if (!callback || !stream) {
				DebugLog(L"Open: Invalid parameters");
				return S_FALSE;
			}

			const size_t magicSize = sizeof(kSignature);
			char magic[magicSize];
			HRESULT result = stream->Read(magic, magicSize, nullptr);
			if (FAILED(result)) {
				DebugLog(L"Open: Failed to read magic");
				return result;
			}

			if (memcmp(magic, kSignature, magicSize) != 0) {
				DebugLog(L"Open: Magic signature doesn't match");
				return S_FALSE;
			}

			DebugLog(L"Open: Magic signature matched!");

			result = ClickHandler.Open(stream, nullptr, callback);
			if (FAILED(result)) {
				DebugLog(L"Open: ClickHandler.Open failed");
				return result;
			}

			items = ClickHandler.items;

			DebugLog(L"Open: Items loaded = " + std::to_wstring(items.size()));
#ifdef _DEBUG
			for (size_t i = 0; i < items.size(); i++) {
				std::wstring path(items[i].path.begin(), items[i].path.end());
				DebugLog(L"  [" + std::to_wstring(i) + L"] " + path);
			}
#endif

			DebugLog(L"Open: SUCCESS - Archive opened with " + std::to_wstring(items.size()) + L" items");

			return S_OK;
		}

		/**
		 * @brief Closes the archive and releases all associated resources.
		 *
		 * Clears internal item lists and resets the ClickHandler.
		 *
		 * @return HRESULT Always returns S_OK.
		 */
		STDMETHODIMP CHandler::Close() {
			DebugLog(L"Close called");
			items.clear();
			ClickHandler.items.clear();
			return S_OK;
		}

		/**
		 * @brief Retrieves the total number of items in the archive.
		 *
		 * @param numItems Output parameter that receives the number of items.
		 * @return HRESULT S_OK if successful, E_POINTER if numItems is nullptr.
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
		 *
		 * @param numProps Output parameter that receives the number of properties.
		 * @return HRESULT S_OK if successful, E_POINTER if numProps is nullptr.
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
		 *
		 * @param index Index of the property (0-based).
		 * @param name Optional output parameter for the property name (BSTR). May be nullptr.
		 * @param propID Output parameter that receives the property ID.
		 * @param varType Output parameter that receives the VARIANT type of the property.
		 * @return HRESULT S_OK if successful, E_INVALIDARG if index is out of range.
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
		 * @brief Retrieves a property value for a specific item.
		 *
		 * @param index Index of the item (0-based).
		 * @param propID The property ID to retrieve (e.g., kpidPath, kpidSize).
		 * @param value Output parameter that receives the property value.
		 * @return HRESULT S_OK if successful, E_POINTER if value is nullptr.
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

			switch (propID)
			{
			case kpidPath:
			{
				DebugLog(L"  Getting PATH property");
				if (items[index].path.empty()) {
					DebugLog(L"    Path is empty, using fallback");
					prop = L"unnamed.bin";
				}
				else {
					UString widePath;
					const std::string& pathStr = items[index].path;

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
				DebugLog(L"  Getting SIZE property: " + std::to_wstring(items[index].uncompressedSize));
				prop = (UInt64)items[index].uncompressedSize;
				break;

			case kpidPackSize:
				DebugLog(L"  Getting PACKSIZE property: " + std::to_wstring(items[index].compressedSize));
				prop = (UInt64)items[index].compressedSize;
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
		 *
		 * Handles both test (verification) mode and actual extraction mode.
		 *
		 * @param indices Array of item indices to extract. Ignored if numItems == -1.
		 * @param numItems Number of items to extract, or -1 for all items.
		 * @param testMode Non-zero to test items without writing output.
		 * @param extractCallback Callback interface to receive extracted streams.
		 * @return HRESULT indicating success or failure of the extraction operation.
		 */
		STDMETHODIMP CHandler::Extract(const UInt32* indices, UInt32 numItems, Int32 testMode, IArchiveExtractCallback* extractCallback) {
			DebugLog(L"Extract called: numItems=" + std::to_wstring(numItems));

			bool allFilesMode = (numItems == (UInt32)(Int32)-1);
			if (allFilesMode) numItems = static_cast<UInt32>(items.size());
			if (numItems == 0) return S_OK;

			UInt64 totalSize = 0, currentSize = 0;
			for (size_t i = 0; i < numItems; i++) {
				totalSize += items[allFilesMode ? i : indices[i]].uncompressedSize;
			}
			extractCallback->SetTotal(totalSize);

			CLocalProgress* lps = new CLocalProgress;
			CMyComPtr<ICompressProgressInfo> progress = lps;
			lps->Init(extractCallback, false);

			for (UINT i = 0; i < numItems; i++) {
				lps->InSize = currentSize;
				lps->OutSize = currentSize;
				RINOK(lps->SetCur());

				CMyComPtr<ISequentialOutStream> realOutStream;
				Int32 askMode = testMode ? NExtract::NAskMode::kTest : NExtract::NAskMode::kExtract;
				UINT32 index = allFilesMode ? i : indices[i];
				auto& item = items[index];
				currentSize += item.uncompressedSize;

				RINOK(extractCallback->GetStream(index, &realOutStream, askMode));
				if (!testMode && !realOutStream) {
					continue;
				}

				RINOK(extractCallback->PrepareOperation(askMode));

				HRESULT writeResult = realOutStream->Write(item.decompressedData.data(), (UINT32)item.decompressedData.size(), NULL);
				if (writeResult != S_OK) {
					DebugLog(L"Extract: Write failed for index " + std::to_wstring(index));
					return writeResult;
				}

				realOutStream.Release();
				RINOK(extractCallback->SetOperationResult(NExtract::NOperationResult::kOK));
			}

			lps->InSize = totalSize;
			lps->OutSize = totalSize;
			return lps->SetCur();
		}
		
		/**
		 * @brief Retrieves a stream corresponding to a specific item in the archive.
		 *
		 * Returns a sequential input stream for reading the contents of the item.
		 *
		 * @param index Index of the item (0-based).
		 * @param stream Output parameter that receives the stream interface.
		 * @return HRESULT S_OK if successful, E_FAIL if index is out of range.
		 */
		STDMETHODIMP CHandler::GetStream(UInt32 index, ISequentialInStream** stream) {
			DebugLog(L"GetStream called: index=" + std::to_wstring(index));

			if (index >= items.size()) {
				return E_FAIL;
			}
			*stream = 0;

			CBufInStream* streamSpec = new CBufInStream;
			CMyComPtr<ISequentialInStream> streamTemp = streamSpec;

			streamSpec->Init(reinterpret_cast<const Byte*>(items[index].decompressedData.data()),
				static_cast<UInt32>(items[index].decompressedData.size()));
			*stream = streamTemp.Detach();
			return S_OK;
		}

		REGISTER_ARC_I(
			"clickteam_exe",
			"exe",
			0,
			0xAB,
			kSignature,
			0,
			NArcInfoFlags::kFindSignature)

	}
}