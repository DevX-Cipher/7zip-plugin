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
#include "PSX.h"
#include <cstdint>

#ifdef _DEBUG
#include <fstream>
#endif

using namespace NWindows;
namespace NArchive {
	namespace NPKG {

		// Both PS3 and PS4 PKG magic signatures
		// PS3: 0x7F504B47 ("\x7FPKG")
		// PS4: 0x7F434E54 ("\x7FCNT")
		static const Byte kSignaturePS3[] = { 0x7F, 0x50, 0x4B, 0x47 };
		static const Byte kSignaturePS4[] = { 0x7F, 0x43, 0x4E, 0x54 };

		static const Byte kProps[] =
		{
			kpidPath,
			kpidSize,
			kpidPackSize,
			kpidMTime,
			kpidCTime,
			kpidATime,
			kpidIsDir
		};

#ifdef _DEBUG
		void DebugLog(const wchar_t* message) {
			std::wofstream logFile;
			logFile.open(L"C:\\ps3_ps4_pkg_debug.log", std::ios::app);
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
				DebugLog(L"PS3/PS4 PKG CHandler constructed");
			}

			UnifiedPKGHandler PKGHandler;  // Changed to UnifiedPKGHandler
			std::vector<UnifiedPKGHandler::FileInfo> items;
			std::wstring contentID;
			std::wstring formatName;  // "PS3" or "PS4"
			UInt16 pkgType;
			UInt64 totalSize;
		};

		/**
		 * @brief Retrieves the number of archive-level properties.
		 */
		STDMETHODIMP CHandler::GetNumberOfArchiveProperties(UInt32* numProps)
		{
			DebugLog(L"GetNumberOfArchiveProperties called");
			*numProps = 4; // Format, Content ID, Package Type, Total Size
			return S_OK;
		}

		/**
		 * @brief Retrieves archive-level property info.
		 */
		STDMETHODIMP CHandler::GetArchivePropertyInfo(UInt32 index, BSTR* name, PROPID* propID, VARTYPE* varType)
		{
			DebugLog(L"GetArchivePropertyInfo called, index=" + std::to_wstring(index));

			if (index >= 4) {
				return E_INVALIDARG;
			}

			if (propID) {
				switch (index) {
				case 0: *propID = kpidHostOS; break;       // Format (PS3/PS4)
				case 1: *propID = kpidComment; break;      // Content ID
				case 2: *propID = kpidMethod; break;       // Package Type
				case 3: *propID = kpidPhySize; break;      // Total Size
				default: return E_INVALIDARG;
				}
			}

			if (varType) {
				switch (index) {
				case 0: *varType = VT_BSTR; break;         // Format (string)
				case 1: *varType = VT_BSTR; break;         // Content ID (string)
				case 2: *varType = VT_BSTR; break;         // Package Type (string)
				case 3: *varType = VT_UI8; break;          // Total Size (uint64)
				default: return E_INVALIDARG;
				}
			}

			if (name) {
				*name = nullptr;
			}

			return S_OK;
		}

		/**
		 * @brief Retrieves a value for a specific archive-level property.
		 */
		STDMETHODIMP CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT* value)
		{
			DebugLog(L"GetArchiveProperty called, propID=" + std::to_wstring(propID));
			NCOM::CPropVariant prop;

			switch (propID) {
			case kpidHostOS:  // Format (PS3/PS4)
				if (!formatName.empty()) {
					prop = formatName.c_str();
				}
				break;

			case kpidComment:  // Content ID
				if (!contentID.empty()) {
					prop = contentID.c_str();
				}
				break;

			case kpidMethod:  // Package Type
			{
				std::wstring typeStr;

				// Check format first
				if (PKGHandler.GetFormat() == PKG_FORMAT_PS3) {
					switch (pkgType) {
					case 0x0001: typeStr = L"PS3 Retail"; break;
					case 0x0002: typeStr = L"PSP"; break;
					case 0x0003: typeStr = L"PSVita"; break;
					case 0x0004: typeStr = L"PSM"; break;
					case 0x8001: typeStr = L"PS3 Debug"; break;
					case 0x8002: typeStr = L"PSP Minis"; break;
					default: typeStr = L"Unknown (0x" + std::to_wstring(pkgType) + L")"; break;
					}
				}
				else if (PKGHandler.GetFormat() == PKG_FORMAT_PS4) {
					// PS4 type determination
					switch (pkgType) {
					case 0x0000: typeStr = L"PS4 Debug"; break;
					case 0x0001: typeStr = L"PS4 Retail"; break;
					default: typeStr = L"PS4 (0x" + std::to_wstring(pkgType) + L")"; break;
					}
				}

				prop = typeStr.c_str();
			}
			break;

			case kpidPhySize:  // Total Size
				prop = totalSize;
				break;
			}

			prop.Detach(value);
			return S_OK;
		}

		/**
		 * @brief Opens the PKG archive (PS3 or PS4) for reading.
		 *
		 * Automatically detects format and initializes appropriate handler.
		 */
		STDMETHODIMP CHandler::Open(IInStream* stream, const UInt64* maxCheckStartPosition, IArchiveOpenCallback* callback) {
			DebugLog(L"=== PKG OPEN CALLED (PS3/PS4 UNIFIED) ===");
			Close();

			if (!callback || !stream) {
				DebugLog(L"Open: Invalid parameters");
				return S_FALSE;
			}

			// Read magic signature to determine format
			const size_t magicSize = 4;
			char magic[magicSize];
			HRESULT result = stream->Read(magic, magicSize, nullptr);
			if (FAILED(result)) {
				DebugLog(L"Open: Failed to read magic");
				return result;
			}

			// Check for PS3 or PS4 signature
			bool isPS3 = (memcmp(magic, kSignaturePS3, magicSize) == 0);
			bool isPS4 = (memcmp(magic, kSignaturePS4, magicSize) == 0);

			if (!isPS3 && !isPS4) {
				DebugLog(L"Open: Not a valid PS3 or PS4 PKG file");
				return S_FALSE;
			}

			if (isPS3) {
				DebugLog(L"Open: Detected PS3 PKG format");
				formatName = L"PS3";
			}
			else {
				DebugLog(L"Open: Detected PS4 PKG format");
				formatName = L"PS4";
			}

			// Reset stream to beginning for handler
			stream->Seek(0, STREAM_SEEK_SET, nullptr);

			// Open PKG with unified handler
			result = PKGHandler.Open(stream, nullptr, callback);
			if (FAILED(result)) {
				DebugLog(L"Open: PKGHandler.Open failed with HRESULT: " + std::to_wstring(result));
				return result;
			}

			// Copy items from handler
			items = PKGHandler.items;

			// Store archive properties based on format
			if (PKGHandler.GetFormat() == PKG_FORMAT_PS3) {
				const auto& header = PKGHandler.GetPS3Header();

				// Convert Content ID to wide string
				contentID.clear();
				for (int i = 0; i < 0x30 && header.content_id[i] != '\0'; i++) {
					contentID += (wchar_t)(unsigned char)header.content_id[i];
				}

				pkgType = header.pkg_type;
				totalSize = header.total_size;
			}
			else if (PKGHandler.GetFormat() == PKG_FORMAT_PS4) {
				const auto& header = PKGHandler.GetPS4Header();

				// Convert Content ID to wide string
				contentID.clear();
				for (int i = 0; i < 0x30 && header.content_id[i] != '\0'; i++) {
					contentID += (wchar_t)(unsigned char)header.content_id[i];
				}

				pkgType = header.type;
				totalSize = 0; // PS4 doesn't have total_size in same location

				// Calculate total size from items
				for (const auto& item : items) {
					if (!item.isFolder) {
						totalSize += item.size;
					}
				}
			}

			DebugLog(L"Open: Items loaded = " + std::to_wstring(items.size()));
			DebugLog(L"Open: Format = " + formatName);
			DebugLog(L"Open: Content ID = " + contentID);
			DebugLog(L"Open: Package Type = 0x" + std::to_wstring(pkgType));
			DebugLog(L"Open: Total Size = " + std::to_wstring(totalSize));

#ifdef _DEBUG
			for (size_t i = 0; i < items.size(); i++) {
				std::wstring path(items[i].path.begin(), items[i].path.end());
				std::wstring isDir = items[i].isFolder ? L" [DIR]" : L"";
				DebugLog(L"  [" + std::to_wstring(i) + L"] " + path + isDir +
					L" (" + std::to_wstring(items[i].size) + L" bytes)");
			}
#endif

			DebugLog(L"Open: SUCCESS - Archive opened with " + std::to_wstring(items.size()) + L" items");

			return S_OK;
		}

		/**
		 * @brief Closes the archive and releases all associated resources.
		 */
		STDMETHODIMP CHandler::Close() {
			DebugLog(L"Close called");
			items.clear();
			PKGHandler.items.clear();
			contentID.clear();
			formatName.clear();
			pkgType = 0;
			totalSize = 0;
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
				case kpidPackSize:
					*varType = VT_UI8;
					DebugLog(L"  varType=VT_UI8");
					break;
				case kpidMTime:
				case kpidCTime:
				case kpidATime:
					*varType = VT_FILETIME;
					DebugLog(L"  varType=VT_FILETIME");
					break;
				case kpidIsDir:
					*varType = VT_BOOL;
					DebugLog(L"  varType=VT_BOOL");
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
		 * @brief Converts Unix time to Windows FILETIME
		 */
		static void UnixTimeToFileTime(int64_t unixTime, FILETIME* ft) {
			if (unixTime <= 0) {
				ft->dwLowDateTime = 0;
				ft->dwHighDateTime = 0;
				return;
			}

			const UInt64 UNIX_EPOCH_OFFSET = 116444736000000000ULL;
			UInt64 windowsTime = ((UInt64)unixTime * 10000000ULL) + UNIX_EPOCH_OFFSET;

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
					prop = L"unnamed.bin";
				}
				else {
					UString widePath;
					const std::string& pathStr = item.path;

					// Convert path to wide string
					for (size_t i = 0; i < pathStr.length(); i++) {
						widePath += (wchar_t)(unsigned char)pathStr[i];
					}

					// Replace backslashes with forward slashes
					for (int i = 0; i < widePath.Len(); i++) {
						if (widePath[i] == L'\\') {
							widePath.ReplaceOneCharAtPos(i, L'/');
						}
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

			case kpidPackSize:
				DebugLog(L"  Getting PACKSIZE property: " + std::to_wstring(item.size));
				prop = (UInt64)item.size;
				break;

			case kpidIsDir:
				DebugLog(L"  Getting ISDIR property: " + std::to_wstring(item.isFolder));
				prop = item.isFolder;
				break;

			case kpidMTime:  // Modified time
			{
				DebugLog(L"  Getting MTIME property");
				FILETIME ft;
				UnixTimeToFileTime(item.fileTime3, &ft);
				if (ft.dwLowDateTime != 0 || ft.dwHighDateTime != 0) {
					prop = ft;
				}
			}
			break;

			case kpidCTime:  // Created time
			{
				DebugLog(L"  Getting CTIME property");
				FILETIME ft;
				UnixTimeToFileTime(item.fileTime1, &ft);
				if (ft.dwLowDateTime != 0 || ft.dwHighDateTime != 0) {
					prop = ft;
				}
			}
			break;

			case kpidATime:  // Accessed time
			{
				DebugLog(L"  Getting ATIME property");
				FILETIME ft;
				UnixTimeToFileTime(item.fileTime2, &ft);
				if (ft.dwLowDateTime != 0 || ft.dwHighDateTime != 0) {
					prop = ft;
				}
			}
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

			bool allFilesMode = (numItems == (UInt32)(Int32)-1);
			if (allFilesMode) numItems = static_cast<UInt32>(items.size());
			if (numItems == 0) return S_OK;

			UInt64 totalSize = 0, currentSize = 0;
			for (size_t i = 0; i < numItems; i++) {
				UInt32 index = allFilesMode ? i : indices[i];
				if (index < items.size() && !items[index].isFolder) {
					totalSize += items[index].size;
				}
			}
			extractCallback->SetTotal(totalSize);

			CLocalProgress* lps = new CLocalProgress;
			CMyComPtr<ICompressProgressInfo> progress = lps;
			lps->Init(extractCallback, false);

			for (UINT i = 0; i < numItems; i++) {
				lps->InSize = currentSize;
				lps->OutSize = currentSize;
				RINOK(lps->SetCur());

				Int32 askMode = testMode ? NExtract::NAskMode::kTest : NExtract::NAskMode::kExtract;
				UINT32 index = allFilesMode ? i : indices[i];

				if (index >= items.size()) {
					DebugLog(L"Extract: Invalid index " + std::to_wstring(index));
					continue;
				}

				auto& item = items[index];

				CMyComPtr<ISequentialOutStream> realOutStream;
				RINOK(extractCallback->GetStream(index, &realOutStream, askMode));

				// Skip folders
				if (item.isFolder) {
					DebugLog(L"Extract: Skipping folder: " + std::wstring(item.path.begin(), item.path.end()));
					extractCallback->SetOperationResult(NExtract::NOperationResult::kOK);
					continue;
				}

				if (!testMode && !realOutStream) {
					DebugLog(L"Extract: No output stream for index " + std::to_wstring(index));
					continue;
				}

				RINOK(extractCallback->PrepareOperation(askMode));

				// Write file data
				if (item.fileData.empty()) {
					DebugLog(L"Extract: WARNING - No data for file: " + std::wstring(item.path.begin(), item.path.end()));
					extractCallback->SetOperationResult(NExtract::NOperationResult::kDataError);
					continue;
				}

				if (!testMode) {
					HRESULT writeResult = realOutStream->Write(
						item.fileData.data(),
						(UINT32)item.fileData.size(),
						NULL
					);

					if (writeResult != S_OK) {
						DebugLog(L"Extract: Write failed for index " + std::to_wstring(index));
						extractCallback->SetOperationResult(NExtract::NOperationResult::kDataError);
						continue;
					}
				}

				currentSize += item.size;
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
				DebugLog(L"GetStream: Invalid index");
				return E_FAIL;
			}

			if (items[index].isFolder) {
				DebugLog(L"GetStream: Item is a folder");
				return E_FAIL;
			}

			*stream = 0;

			CBufInStream* streamSpec = new CBufInStream;
			CMyComPtr<ISequentialInStream> streamTemp = streamSpec;

			streamSpec->Init(
				reinterpret_cast<const Byte*>(items[index].fileData.data()),
				static_cast<UInt32>(items[index].fileData.size())
			);

			*stream = streamTemp.Detach();
			return S_OK;
		}

		// Register the PKG archive format with 7-Zip
		// This now handles BOTH PS3 and PS4 PKG files
		REGISTER_ARC_I(
			"PKG",              // Format name
			"pkg",              // File extension
			0,                  // Add extension (flags)
			0xE0,               // Signature ID
			kSignaturePS3,      // Magic signature (PS3 - will check both in Open)
			0,                  // Signature offset
			NArcInfoFlags::kFindSignature,  // Find signature flag
			NULL                // IsArc function (optional)
		)

	}
}