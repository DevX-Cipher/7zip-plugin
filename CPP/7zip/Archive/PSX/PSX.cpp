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
#include "log.h"

#include <cstdint>


using namespace NWindows;
namespace NArchive {
	namespace NPKG {

		
		static const Byte kSignaturePS3[] = { 0x7F, 0x50, 0x4B, 0x47 };
		static const Byte kSignaturePS4[] = { 0x7F, 0x43, 0x4E, 0x54 };
		static const Byte kSignaturePS3PUP[] = { 0x53, 0x43, 0x45, 0x55 };

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
		enum {
			kpidVersion = kpidUserDefined + 1 
		};

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
			static HRESULT IsArc_PKG_PUP(const Byte* p, size_t size);
			CHandler() {
				logDebug(L"PS3/PS4 PKG + PUP CHandler constructed");
			}

			PSXHandler PKGHandler;  // Unified handler for PKG and PUP
			std::vector<PSXHandler::FileInfo> items;
			std::wstring contentID;
			std::wstring formatName;  // "PS3 PKG", "PS4 PKG", "PS3 PUP", "PS4 PUP"
			UInt16 pkgType;
			UInt64 totalSize;
			UInt32 imageVersion;  // For PUP files
		};

		/**
		 * @brief Retrieves the number of archive-level properties.
		 */
		STDMETHODIMP CHandler::GetNumberOfArchiveProperties(UInt32* numProps)
		{
			logDebug(L"GetNumberOfArchiveProperties called");
			*numProps = 5; // Format, Content ID, Package Type, Total Size, Image Version (PUP)
			return S_OK;
		}

		/**
		 * @brief Retrieves archive-level property info.
		 */
		STDMETHODIMP CHandler::GetArchivePropertyInfo(UInt32 index, BSTR* name, PROPID* propID, VARTYPE* varType)
		{
			logDebug(L"GetArchivePropertyInfo called, index=" + std::to_wstring(index));

			if (index >= 5) {
				return E_INVALIDARG;
			}

			if (propID) {
				switch (index) {
				case 0: *propID = kpidHostOS; break;       // Format (PS3/PS4 PKG/PUP)
				case 1: *propID = kpidComment; break;      // Content ID
				case 2: *propID = kpidMethod; break;       // Package Type
				case 3: *propID = kpidPhySize; break;      // Total Size
				case 4: *propID = kpidVersion; break;      // Image Version (PUP only)
				default: return E_INVALIDARG;
				}
			}

			if (varType) {
				switch (index) {
				case 0: *varType = VT_BSTR; break;         // Format (string)
				case 1: *varType = VT_BSTR; break;         // Content ID (string)
				case 2: *varType = VT_BSTR; break;         // Package Type (string)
				case 3: *varType = VT_UI8; break;          // Total Size (uint64)
				case 4: *varType = VT_BSTR; break;         // Image Version (string)
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
			logDebug(L"GetArchiveProperty called, propID=" + std::to_wstring(propID));
			NCOM::CPropVariant prop;

			switch (propID) {
			case kpidHostOS:  // Format (PS3/PS4 PKG/PUP)
				if (!formatName.empty()) {
					prop = formatName.c_str();
				}
				break;

			case kpidComment:  // Content ID (or file count for PUP)
				if (PKGHandler.GetFormat() == PKG_FORMAT_PS3_PUP ||
					PKGHandler.GetFormat() == PKG_FORMAT_PS4_PUP) {
					// For PUP, show file count
					std::wstring pupInfo = L"Files: " + std::to_wstring(items.size());
					if (PKGHandler.GetFormat() == PKG_FORMAT_PS4_PUP) {
						pupInfo += L" (PS4 Update)";
					}
					else {
						pupInfo += L" (PS3 Update)";
					}
					prop = pupInfo.c_str();
				}
				else if (!contentID.empty()) {
					prop = contentID.c_str();
				}
				break;

			case kpidMethod:  // Package Type
			{
				std::wstring typeStr;

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
					switch (pkgType) {
					case 0x0000: typeStr = L"PS4 Debug"; break;
					case 0x0001: typeStr = L"PS4 Retail"; break;
					default: typeStr = L"PS4 (0x" + std::to_wstring(pkgType) + L")"; break;
					}
				}
				else if (PKGHandler.GetFormat() == PKG_FORMAT_PS3_PUP) {
					typeStr = L"PS3 System Update";
				}
				else if (PKGHandler.GetFormat() == PKG_FORMAT_PS4_PUP) {
					typeStr = L"PS4 System Update";
				}

				prop = typeStr.c_str();
			}
			break;

			case kpidPhySize:  // Total Size
				prop = totalSize;
				break;

			case kpidVersion:  // Image Version (PUP only)
				if (PKGHandler.GetFormat() == PKG_FORMAT_PS3_PUP ||
					PKGHandler.GetFormat() == PKG_FORMAT_PS4_PUP) {
					wchar_t versionStr[32];
					swprintf_s(versionStr, L"0x%08X", imageVersion);
					prop = versionStr;
				}
				break;
			}

			prop.Detach(value);
			return S_OK;
		}

		/**
		 * @brief Opens the archive (PS3 PKG, PS4 PKG, PS3 PUP, or PS4 PUP) for reading.
		 *
		 * Automatically detects format and initializes appropriate handler.
		 */
		STDMETHODIMP CHandler::Open(IInStream* stream, const UInt64* maxCheckStartPosition, IArchiveOpenCallback* callback) {
			logDebug(L"=== ARCHIVE OPEN CALLED (PS3/PS4 PKG + PUP UNIFIED) ===");
			Close();

			if (!callback || !stream) {
				logDebug(L"Open: Invalid parameters");
				return S_FALSE;
			}

			// Get actual file size
			UInt64 actualFileSize = 0;
			stream->Seek(0, STREAM_SEEK_END, &actualFileSize);
			stream->Seek(0, STREAM_SEEK_SET, nullptr);
			logDebug(L"Open: Actual file size = " + std::to_wstring(actualFileSize));

			// Read header to determine format (need more than just 4 bytes for PS4 PUP)
			const size_t headerSize = 0x20; // Read 32 bytes for full header
			char headerBuf[headerSize];
			HRESULT result = stream->Read(headerBuf, headerSize, nullptr);
			if (FAILED(result)) {
				logDebug(L"Open: Failed to read header");
				return result;
			}

			// Check for PS3 PKG, PS4 PKG, or PS3 PUP signature (first 4 bytes)
			bool isPS3PKG = (memcmp(headerBuf, kSignaturePS3, 4) == 0);
			bool isPS4PKG = (memcmp(headerBuf, kSignaturePS4, 4) == 0);
			bool isPS3PUP = (memcmp(headerBuf, kSignaturePS3PUP, 4) == 0);

			// PS4 PUP detection - decrypted PS4 PUP files have NO reliable magic signature
			bool isPS4PUP = false;

			if (!isPS3PKG && !isPS4PKG && !isPS3PUP) {
				logDebug(L"No known magic signature found, attempting PS4 PUP detection...");

				// Read fields in little-endian (PS4 PUP uses LE)
				uint32_t magic = (uint8_t)headerBuf[0] | ((uint8_t)headerBuf[1] << 8) |
					((uint8_t)headerBuf[2] << 16) | ((uint8_t)headerBuf[3] << 24);

				uint16_t header_size = (uint8_t)headerBuf[0x0C] | ((uint8_t)headerBuf[0x0D] << 8);
				uint16_t entry_count = (uint8_t)headerBuf[0x18] | ((uint8_t)headerBuf[0x19] << 8);
				uint16_t hash_count = (uint8_t)headerBuf[0x1A] | ((uint8_t)headerBuf[0x1B] << 8);

				uint64_t file_size = 0;
				for (int i = 0; i < 8; i++) {
					file_size |= ((uint64_t)(uint8_t)headerBuf[0x10 + i]) << (i * 8);
				}

				logDebug(L"PS4 PUP Detection:");
				logDebug(L"  Header Size: 0x" + std::to_wstring(header_size));
				logDebug(L"  Entry Count: " + std::to_wstring(entry_count));
				logDebug(L"  Hash Count: " + std::to_wstring(hash_count));
				logDebug(L"  File Size (header): " + std::to_wstring(file_size));
				logDebug(L"  Actual File Size: " + std::to_wstring(actualFileSize));

				bool headerSizeOK = (header_size >= 0x20 && header_size <= 0x100000);  // Increased max
				bool entryCountOK = (entry_count > 0 && entry_count <= 5000);  // Increased max
				bool hashCountOK = (hash_count <= 5000);  // Increased max

				bool fileSizeOK = true;  // DISABLE FILE SIZE CHECK for now
				if (file_size > 0) {
					// Only check if file_size seems reasonable
					fileSizeOK = (file_size <= actualFileSize * 10);  // Very lenient
				}

				logDebug(L"  Validation Results:");
				logDebug(L"    Header Size OK: " + std::to_wstring(headerSizeOK));
				logDebug(L"    Entry Count OK: " + std::to_wstring(entryCountOK));
				logDebug(L"    Hash Count OK: " + std::to_wstring(hashCountOK));
				logDebug(L"    File Size OK: " + std::to_wstring(fileSizeOK));

				// Accept if basic structure looks valid
				if (headerSizeOK && entryCountOK && hashCountOK && fileSizeOK) {
					isPS4PUP = true;
					logDebug(L"Open: Detected PS4 PUP format (VALIDATION PASSED)");
				}
				else {
					logDebug(L"Open: PS4 PUP validation FAILED");

					if (!headerSizeOK) logDebug(L"  FAILED: Header size check");
					if (!entryCountOK) logDebug(L"  FAILED: Entry count check");
					if (!hashCountOK) logDebug(L"  FAILED: Hash count check");
					if (!fileSizeOK) logDebug(L"  FAILED: File size check");
				}
			}

			if (!isPS3PKG && !isPS4PKG && !isPS3PUP && !isPS4PUP) {
				logDebug(L"Open: Not a valid PS3/PS4 PKG or PUP file");
				return S_FALSE;
			}

			// Set format name
			if (isPS3PKG) {
				logDebug(L"Open: Detected PS3 PKG format");
				formatName = L"PS3 PKG";
			}
			else if (isPS4PKG) {
				logDebug(L"Open: Detected PS4 PKG format");
				formatName = L"PS4 PKG";
			}
			else if (isPS3PUP) {
				logDebug(L"Open: Detected PS3 PUP format");
				formatName = L"PS3 PUP";
			}
			else if (isPS4PUP) {
				logDebug(L"Open: Detected PS4 PUP format");
				formatName = L"PS4 PUP";
			}

			// Reset stream to beginning for handler
			stream->Seek(0, STREAM_SEEK_SET, nullptr);

			// Open archive with unified handler
			result = PKGHandler.Open(stream, nullptr, callback);
			if (FAILED(result)) {
				logDebug(L"Open: PKGHandler.Open failed with HRESULT: 0x" + std::to_wstring(result));
				return result;
			}

			// Copy items from handler
			items = PKGHandler.items;
			logDebug(L"Open: Copied " + std::to_wstring(items.size()) + L" items from handler");

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
				totalSize = 0;

				// Calculate total size from items
				for (const auto& item : items) {
					if (!item.isFolder) {
						totalSize += item.size;
					}
				}
			}
			else if (PKGHandler.GetFormat() == PKG_FORMAT_PS3_PUP) {
				const auto& header = PKGHandler.GetPS3PUPHeader();

				contentID = L"PS3 System Update Package";
				pkgType = 0; 
				imageVersion = header.image_version;

				// Calculate total size from header
				totalSize = header.header_length + header.data_length;
			}
			else if (PKGHandler.GetFormat() == PKG_FORMAT_PS4_PUP) {
				const auto& header = PKGHandler.GetPS4PUPHeader();

				contentID = L"PS4 System Update Package";
				pkgType = 0;  
				imageVersion = 0;  

				totalSize = header.file_size;
			}

			logDebug(L"Open: Items loaded = " + std::to_wstring(items.size()));
			logDebug(L"Open: Format = " + formatName);

			if (PKGHandler.GetFormat() != PKG_FORMAT_PS3_PUP &&
				PKGHandler.GetFormat() != PKG_FORMAT_PS4_PUP) {
				logDebug(L"Open: Content ID = " + contentID);
				logDebug(L"Open: Package Type = 0x" + std::to_wstring(pkgType));
			}
			else {
				if (imageVersion != 0) {
					logDebug(L"Open: Image Version = 0x" + std::to_wstring(imageVersion));
				}
			}

			logDebug(L"Open: Total Size = ", totalSize);

			for (size_t i = 0; i < items.size(); i++) {
				const auto& item = items[i];
				std::wstring path(item.path.begin(), item.path.end());

				logDebug(
					L"  [", i, L"] ",
					path,
					item.isFolder ? L" [DIR]" : L"",
					item.isCompressed ? L" [COMPRESSED]" : L"",
					item.isBlocked ? L" [BLOCKED]" : L"",
					L" (", item.size, L" bytes)"
				);
			}

			logDebug(L"Open: SUCCESS - Archive opened with " + std::to_wstring(items.size()) + L" items");

			return S_OK;
		}
		/**
		 * @brief Closes the archive and releases all associated resources.
		 */
		STDMETHODIMP CHandler::Close() {
			logDebug(L"Close called");
			items.clear();
			PKGHandler.items.clear();
			contentID.clear();
			formatName.clear();
			pkgType = 0;
			totalSize = 0;
			imageVersion = 0;
			return S_OK;
		}

		/**
		 * @brief Retrieves the total number of items in the archive.
		 */
		STDMETHODIMP CHandler::GetNumberOfItems(UInt32* numItems) {
			if (numItems == nullptr) {
				logDebug(L"GetNumberOfItems: NULL pointer!");
				return E_POINTER;
			}

			*numItems = static_cast<UInt32>(items.size());
			logDebug(L"GetNumberOfItems: returning " + std::to_wstring(*numItems));

			return S_OK;
		}

		/**
		 * @brief Retrieves the total number of properties available per item.
		 */
		STDMETHODIMP CHandler::GetNumberOfProperties(UInt32* numProps)
		{
			if (numProps == nullptr) {
				logDebug(L"GetNumberOfProperties: NULL pointer!");
				return E_POINTER;
			}

			*numProps = ARRAY_SIZE(kProps);
			logDebug(L"GetNumberOfProperties: returning " + std::to_wstring(*numProps));

			return S_OK;
		}

		/**
		 * @brief Retrieves property info for a given index.
		 */
		STDMETHODIMP CHandler::GetPropertyInfo(UInt32 index, BSTR* name, PROPID* propID, VARTYPE* varType)
		{
			logDebug(L"GetPropertyInfo: index=" + std::to_wstring(index));

			if (index >= ARRAY_SIZE(kProps)) {
				logDebug(L"GetPropertyInfo: index out of range!");
				return E_INVALIDARG;
			}

			if (propID) {
				*propID = kProps[index];
				logDebug(L"  propID=" + std::to_wstring(kProps[index]));
			}

			if (varType) {
				switch (kProps[index]) {
				case kpidPath:
					*varType = VT_BSTR;
					logDebug(L"  varType=VT_BSTR");
					break;
				case kpidSize:
				case kpidPackSize:
					*varType = VT_UI8;
					logDebug(L"  varType=VT_UI8");
					break;
				case kpidMTime:
				case kpidCTime:
				case kpidATime:
					*varType = VT_FILETIME;
					logDebug(L"  varType=VT_FILETIME");
					break;
				case kpidIsDir:
					*varType = VT_BOOL;
					logDebug(L"  varType=VT_BOOL");
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
			logDebug(L">>> GetProperty CALLED <<<");
			logDebug(L"  index=" + std::to_wstring(index));
			logDebug(L"  propID=" + std::to_wstring(propID));

			if (value == nullptr) {
				logDebug(L"  ERROR: value is NULL!");
				return E_POINTER;
			}

			NCOM::CPropVariant prop;

			if (index >= items.size()) {
				logDebug(L"  ERROR: index out of range! (size=" + std::to_wstring(items.size()) + L")");
				prop.Detach(value);
				return S_OK;
			}

			const auto& item = items[index];

			switch (propID)
			{
			case kpidPath:
			{
				logDebug(L"  Getting PATH property");
				if (item.path.empty()) {
					logDebug(L"    Path is empty, using fallback");
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

					std::wstring pathLog = L"    Returning path: ";
					for (int i = 0; i < widePath.Len(); i++) {
						pathLog += widePath[i];
					}
					logDebug(pathLog.c_str());

					prop = widePath;
				}
			}
			break;

			case kpidSize:
				if (item.uncompressed_size > 0) {
					logDebug(L"  Getting SIZE property (uncompressed): " + std::to_wstring(item.uncompressed_size));
					prop = (UInt64)item.uncompressed_size;
				}
				else {
					logDebug(L"  Getting SIZE property: " + std::to_wstring(item.size));
					prop = (UInt64)item.size;
				}
				break;

			case kpidPackSize:
				logDebug(L"  Getting PACKSIZE property: " + std::to_wstring(item.size));
				prop = (UInt64)item.size;
				break;

			case kpidIsDir:
				logDebug(L"  Getting ISDIR property: " + std::to_wstring(item.isFolder));
				prop = item.isFolder;
				break;

			case kpidMTime:  // Modified time
			{
				logDebug(L"  Getting MTIME property");
				FILETIME ft;
				UnixTimeToFileTime(item.fileTime3, &ft);
				if (ft.dwLowDateTime != 0 || ft.dwHighDateTime != 0) {
					prop = ft;
				}
			}
			break;

			case kpidCTime:  // Created time
			{
				logDebug(L"  Getting CTIME property");
				FILETIME ft;
				UnixTimeToFileTime(item.fileTime1, &ft);
				if (ft.dwLowDateTime != 0 || ft.dwHighDateTime != 0) {
					prop = ft;
				}
			}
			break;

			case kpidATime:  // Accessed time
			{
				logDebug(L"  Getting ATIME property");
				FILETIME ft;
				UnixTimeToFileTime(item.fileTime2, &ft);
				if (ft.dwLowDateTime != 0 || ft.dwHighDateTime != 0) {
					prop = ft;
				}
			}
			break;

			default:
				logDebug(L"  Unknown propID: " + std::to_wstring(propID));
				break;
			}

			prop.Detach(value);
			return S_OK;
		}

		/**
		 * @brief Extracts one or more items from the archive.
		 */
		STDMETHODIMP CHandler::Extract(const UInt32* indices, UInt32 numItems, Int32 testMode, IArchiveExtractCallback* extractCallback) {
			logDebug(L"Extract called: numItems=" + std::to_wstring(numItems));

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
					logDebug(L"Extract: Invalid index " + std::to_wstring(index));
					continue;
				}

				auto& item = items[index];

				CMyComPtr<ISequentialOutStream> realOutStream;
				RINOK(extractCallback->GetStream(index, &realOutStream, askMode));

				// Skip folders
				if (item.isFolder) {
					logDebug(L"Extract: Skipping folder: " + std::wstring(item.path.begin(), item.path.end()));
					extractCallback->SetOperationResult(NExtract::NOperationResult::kOK);
					continue;
				}

				if (!testMode && !realOutStream) {
					logDebug(L"Extract: No output stream for index " + std::to_wstring(index));
					continue;
				}

				RINOK(extractCallback->PrepareOperation(askMode));

				if (item.fileData.empty()) {
					if (item.isCompressed) {
						logDebug(L"Extract: WARNING - Compressed file not extracted: " +
							std::wstring(item.path.begin(), item.path.end()));
						extractCallback->SetOperationResult(NExtract::NOperationResult::kUnsupportedMethod);
					}
					else {
						logDebug(L"Extract: WARNING - No data for file: " +
							std::wstring(item.path.begin(), item.path.end()));
						extractCallback->SetOperationResult(NExtract::NOperationResult::kDataError);
					}
					continue;
				}

				if (!testMode) {
					HRESULT writeResult = realOutStream->Write(
						item.fileData.data(),
						(UINT32)item.fileData.size(),
						NULL
					);

					if (writeResult != S_OK) {
						logDebug(L"Extract: Write failed for index " + std::to_wstring(index));
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
			logDebug(L"GetStream called: index=" + std::to_wstring(index));

			if (index >= items.size()) {
				logDebug(L"GetStream: Invalid index");
				return E_FAIL;
			}

			if (items[index].isFolder) {
				logDebug(L"GetStream: Item is a folder");
				return E_FAIL;
			}

			if (items[index].fileData.empty()) {
				logDebug(L"GetStream: No data available for item");
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

		/**
		 * @brief Custom archive detection function for PS3/PS4 PKG and PUP files
		 */
		static inline UInt32 IsArc_PKG_PUP(const Byte* p, size_t size)
		{
			if (size < 0x20) {
				return k_IsArc_Res_NO;  // Need at least 32 bytes
			}

			// Check PS3 PKG signature (big-endian): 0x7F504B47
			if (p[0] == 0x7F && p[1] == 0x50 && p[2] == 0x4B && p[3] == 0x47) {
				return k_IsArc_Res_YES;
			}

			// Check PS4 PKG signature (big-endian): 0x7F434E54
			if (p[0] == 0x7F && p[1] == 0x43 && p[2] == 0x4E && p[3] == 0x54) {
				return k_IsArc_Res_YES;
			}

			// Check PS3 PUP signature (big-endian): 0x53434555
			if (p[0] == 0x53 && p[1] == 0x43 && p[2] == 0x45 && p[3] == 0x55) {
				return k_IsArc_Res_YES;
			}

			uint16_t header_size = p[0x0C] | (p[0x0D] << 8);
			uint16_t entry_count = p[0x18] | (p[0x19] << 8);
			uint16_t hash_count = p[0x1A] | (p[0x1B] << 8);

			// PS4 PUP validation
			bool headerSizeOK = (header_size >= 0x20 && header_size <= 0x100000);
			bool entryCountOK = (entry_count > 0 && entry_count <= 5000);
			bool hashCountOK = (hash_count <= 5000);

			if (headerSizeOK && entryCountOK && hashCountOK) {
				return k_IsArc_Res_YES;  
			}

			return k_IsArc_Res_NO;  
		}

		REGISTER_ARC_I(
			"PKG",                          // Format name
			"pkg pup",                      // File extensions
			0,                              // Add extension
			0xE0,                           // Format ID
			kSignaturePS3,                  // Signature bytes
			0,                              // Signature offset
			NArcInfoFlags::kFindSignature,  // Flags
			IsArc_PKG_PUP                   // IsArc function
		)
	}
}