#define INITGUID
#include "Alloc.h"
#include "ComTry.h"
#include "MyCom.h"
#include "IArchive.h"
#include "MyVector.h"
#include "CopyCoder.h"
#include "LimitedStreams.h"
#include "PropVariant.h"
#include "ProgressUtils.h"
#include "RegisterArc.h"
#include "StringConvert.h"
#include <cwchar>
#include "PSX.h"
#include <StreamUtils.h>



using namespace NWindows;
namespace NArchive {
	namespace NPKG {

		static constexpr const Byte kSignaturePS3[] =			{ 0x7F, 0x50, 0x4B, 0x47 };
		static constexpr const Byte kSignaturePS4[] =			{ 0x7F, 0x43, 0x4E, 0x54 };
		static constexpr const Byte kSignaturePS3PUP[] =  { 0x53, 0x43, 0x45, 0x55 };
		static constexpr const Byte kSignaturePS5[] =			{ 0x7F, 0x46, 0x49, 0x48 };

		enum {
			kpidVersion = kpidUserDefined + 1
		};

		static constexpr const PROPID kProps[] =
		{
				kpidPath,
				kpidSize,
				kpidPackSize,
				kpidMTime,
				kpidCTime,
				kpidATime,
				kpidIsDir
		};

		static constexpr const PROPID kArcProps[] =
		{
				kpidHostOS,
				kpidComment,
				kpidMethod,
				kpidPhySize,
				kpidVersion
		};



		class CHandler :
			public IInArchive, public IInArchiveGetStream, // reading
			public IOutArchive, public ISetProperties, public IMultiVolumeOutArchive, // writing
			public CMyUnknownImp
		{
		public:
			MY_UNKNOWN_IMP5(IInArchive, IInArchiveGetStream, IOutArchive, ISetProperties, IMultiVolumeOutArchive)

				INTERFACE_IInArchive(override)
				INTERFACE_IOutArchive(override)

				STDMETHOD(GetStream)(UInt32 index, ISequentialInStream** stream);
				STDMETHOD(SetProperties)(const wchar_t* const* names, const PROPVARIANT* values, UInt32 numProps) override;
				STDMETHOD(GetMultiArchiveNameFmt)(PROPVARIANT* nameMod, PROPVARIANT* prefix, PROPVARIANT* postfix, BOOL* numberAfterExt, UInt32* digitCount) override;

				CHandler(PKG_FORMAT defaultFormat = PKG_FORMAT_PS3)
					: m_defaultFormat(defaultFormat), PKGHandler() {
					logDebug(L"CHandler constructed with default format: " + std::to_wstring((int)defaultFormat));
				}

			PSXHandler PKGHandler;
			PKG_FORMAT m_defaultFormat;
			std::vector<PSXHandler::FileInfo> items;
			std::wstring contentID;
			std::wstring formatName;
			UInt16 pkgType;
			UInt64 totalSize;
			UInt32 imageVersion;
		};

		// PS3-specific handler
		class CHandlerPS3 : public CHandler {
		public:
			CHandlerPS3() : CHandler(PKG_FORMAT_PS3) {
				logDebug(L"PS3 PKG Handler constructed");
			}
		};

		// PS4-specific handler
		class CHandlerPS4 : public CHandler {
		public:
			CHandlerPS4() : CHandler(PKG_FORMAT_PS4) {
				logDebug(L"PS4 PKG Handler constructed");
			}
		};

		// PS5-specific handler (read-only for now)
		class CHandlerPS5 : public CHandler {
		public:
			CHandlerPS5() : CHandler(PKG_FORMAT_PS5) {
				logDebug(L"PS5 PKG Handler constructed");
			}
		};

		// Implement IInArchive property methods
		IMP_IInArchive_Props
			IMP_IInArchive_ArcProps


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
		 */
		STDMETHODIMP CHandler::Open(IInStream* stream, const UInt64* maxCheckStartPosition, IArchiveOpenCallback* callback) {
			logDebug(L"=== ARCHIVE OPEN CALLED (PS3/PS4 PKG + PUP UNIFIED) ===");
			Close();

			if (!stream) {
				logDebug(L"Open: Invalid parameters");
				return S_FALSE;
			}

			// Get actual file size
			UInt64 actualFileSize = 0;
			stream->Seek(0, STREAM_SEEK_END, &actualFileSize);
			stream->Seek(0, STREAM_SEEK_SET, nullptr);
			logDebug(L"Open: Actual file size = " + std::to_wstring(actualFileSize));

			// Read header to determine format
			const size_t headerSize = 0x20;
			char headerBuf[headerSize];
			HRESULT result = stream->Read(headerBuf, headerSize, nullptr);
			if (FAILED(result)) {
				logDebug(L"Open: Failed to read header");
				return result;
			}

			// Check for PS3 PKG, PS4 PKG, or PS3 PUP signature
			bool isPS3PKG = (memcmp(headerBuf, kSignaturePS3, 4) == 0);
			bool isPS4PKG = (memcmp(headerBuf, kSignaturePS4, 4) == 0);
			bool isPS5PKG = (memcmp(headerBuf, kSignaturePS5, 4) == 0); 
			bool isPS3PUP = (memcmp(headerBuf, kSignaturePS3PUP, 4) == 0);

			// PS4 PUP detection
			bool isPS4PUP = false;

			if (!isPS3PKG && !isPS4PKG && !isPS5PKG && !isPS3PUP) {
				logDebug(L"No known magic signature found, attempting PS4 PUP detection...");

				uint32_t magic = (uint8_t)headerBuf[0] | ((uint8_t)headerBuf[1] << 8) |
					((uint8_t)headerBuf[2] << 16) | ((uint8_t)headerBuf[3] << 24);

				uint16_t header_size = (uint8_t)headerBuf[0x0C] | ((uint8_t)headerBuf[0x0D] << 8);
				uint16_t entry_count = (uint8_t)headerBuf[0x18] | ((uint8_t)headerBuf[0x19] << 8);
				uint16_t hash_count = (uint8_t)headerBuf[0x1A] | ((uint8_t)headerBuf[0x1B] << 8);

				uint64_t file_size = 0;
				for (int i = 0; i < 8; i++) {
					file_size |= ((uint64_t)(uint8_t)headerBuf[0x10 + i]) << (i * 8);
				}

				bool headerSizeOK = (header_size >= 0x20 && header_size <= 0x100000);
				bool entryCountOK = (entry_count > 0 && entry_count <= 5000);
				bool hashCountOK = (hash_count <= 5000);
				bool fileSizeOK = true;

				if (file_size > 0) {
					fileSizeOK = (file_size <= actualFileSize * 10);
				}

				if (headerSizeOK && entryCountOK && hashCountOK && fileSizeOK) {
					isPS4PUP = true;
					logDebug(L"Open: Detected PS4 PUP format");
				}
			}

			if (!isPS3PKG && !isPS4PKG && !isPS5PKG && !isPS3PUP && !isPS4PUP) {
				logDebug(L"Open: Not a valid PS3/PS4 PKG or PUP file");
				return S_FALSE;
			}

			// Set format name
			if (isPS3PKG) {
				formatName = L"PS3 PKG";
			}
			else if (isPS4PKG) {
				formatName = L"PS4 PKG";
			}
			else if (isPS5PKG) { 
				formatName = L"PS5 PKG";
			}
			else if (isPS3PUP) {
				formatName = L"PS3 PUP";
			}
			else if (isPS4PUP) {
				formatName = L"PS4 PUP";
			}

			// Reset stream to beginning
			stream->Seek(0, STREAM_SEEK_SET, nullptr);

			// Open archive with unified handler
			result = PKGHandler.Open(stream, nullptr, callback);
			if (FAILED(result)) {
				logDebug(L"Open: PKGHandler.Open failed");
				return result;
			}

			// Copy items from handler
			items = PKGHandler.items;
			logDebug(L"Open: Copied " + std::to_wstring(items.size()) + L" items");

			// Store archive properties
			if (PKGHandler.GetFormat() == PKG_FORMAT_PS3) {
				const auto& header = PKGHandler.GetPS3Header();

				contentID.clear();
				for (int i = 0; i < 0x30 && header.content_id[i] != '\0'; i++) {
					contentID += (wchar_t)(unsigned char)header.content_id[i];
				}

				pkgType = header.pkg_type;
				totalSize = header.total_size;
			}
			else if (PKGHandler.GetFormat() == PKG_FORMAT_PS4) {
				const auto& header = PKGHandler.GetPS4Header();

				contentID.clear();
				for (int i = 0; i < 0x30 && header.content_id[i] != '\0'; i++) {
					contentID += (wchar_t)(unsigned char)header.content_id[i];
				}

				pkgType = header.type;
				totalSize = 0;

				for (const auto& item : items) {
					if (!item.isFolder) {
						totalSize += item.size;
					}
				}
			}
			else if (PKGHandler.GetFormat() == PKG_FORMAT_PS5) {
				const auto& header = PKGHandler.GetPS5Header();

				contentID.clear();
				for (int i = 0; i < 0x30 && header.content_id[i] != '\0'; i++) {
					contentID += (wchar_t)(unsigned char)header.content_id[i];
				}

				pkgType = header.type;
				totalSize = 0;

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
				totalSize = header.header_length + header.data_length;
			}
			else if (PKGHandler.GetFormat() == PKG_FORMAT_PS4_PUP) {
				const auto& header = PKGHandler.GetPS4PUPHeader();

				contentID = L"PS4 System Update Package";
				pkgType = 0;
				imageVersion = 0;
				totalSize = header.file_size;
			}

			logDebug(L"Open: SUCCESS - Archive opened with " + std::to_wstring(items.size()) + L" items");
			return S_OK;
		}

		/**
		 * @brief Closes the archive and releases all resources.
		 */
		STDMETHODIMP CHandler::Close() {
			logDebug(L"CHandler::Close called");

		

			// Clear local data structures
			items.clear();
			contentID.clear();
			formatName.clear();
			pkgType = 0;
			totalSize = 0;
			imageVersion = 0;

			logDebug(L"CHandler::Close completed - all resources released");
			return S_OK;
		}

		/**
		 * @brief Retrieves the total number of items.
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
			if (value == nullptr) {
				return E_POINTER;
			}

			NCOM::CPropVariant prop;

			if (index >= items.size()) {
				prop.Detach(value);
				return S_OK;
			}

			const auto& item = items[index];

			switch (propID)
			{
			case kpidPath:
			{
				if (item.path.empty()) {
					prop = L"unnamed.bin";
				}
				else {
					UString widePath;
					const std::string& pathStr = item.path;

					for (size_t i = 0; i < pathStr.length(); i++) {
						widePath += (wchar_t)(unsigned char)pathStr[i];
					}

					for (int i = 0; i < widePath.Len(); i++) {
						if (widePath[i] == L'\\') {
							widePath.ReplaceOneCharAtPos(i, L'/');
						}
					}

					prop = widePath;
				}
			}
			break;

			case kpidSize:
				if (PKGHandler.GetFormat() == PKG_FORMAT_PS3_PUP ||
					PKGHandler.GetFormat() == PKG_FORMAT_PS4_PUP ||
					PKGHandler.GetFormat() == PKG_FORMAT_PS5_PUP) {
					if (item.uncompressed_size > 0) {
						prop = (UInt64)item.uncompressed_size;
					}
					else {
						prop = (UInt64)item.size;
					}
				}
				else {
					prop = (UInt64)item.size;
				}
				break;

			case kpidPackSize:
				if ((PKGHandler.GetFormat() == PKG_FORMAT_PS3_PUP ||
					PKGHandler.GetFormat() == PKG_FORMAT_PS4_PUP ||
					PKGHandler.GetFormat() == PKG_FORMAT_PS5_PUP) &&
					item.isCompressed) {
					prop = (UInt64)item.size;
				}
				break;

			case kpidIsDir:
				prop = item.isFolder;
				break;

			case kpidMTime:
			{
				FILETIME ft;
				UnixTimeToFileTime(item.fileTime3, &ft);
				if (ft.dwLowDateTime != 0 || ft.dwHighDateTime != 0) {
					prop = ft;
				}
			}
			break;

			case kpidCTime:
			{
				FILETIME ft;
				UnixTimeToFileTime(item.fileTime1, &ft);
				if (ft.dwLowDateTime != 0 || ft.dwHighDateTime != 0) {
					prop = ft;
				}
			}
			break;

			case kpidATime:
			{
				FILETIME ft;
				UnixTimeToFileTime(item.fileTime2, &ft);
				if (ft.dwLowDateTime != 0 || ft.dwHighDateTime != 0) {
					prop = ft;
				}
			}
			break;

			case kpidAttrib:
				prop = (UInt32)(item.isFolder ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL);
				break;

			case kpidMethod:
				if ((PKGHandler.GetFormat() == PKG_FORMAT_PS3_PUP ||
					PKGHandler.GetFormat() == PKG_FORMAT_PS4_PUP ||
					PKGHandler.GetFormat() == PKG_FORMAT_PS5_PUP) &&
					item.isCompressed) {
					prop = L"Zlib";
				}
				break;
			}

			prop.Detach(value);
			return S_OK;
		}

		/**
		 * @brief Extracts items from the archive.
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
					continue;
				}

				auto& item = items[index];

				CMyComPtr<ISequentialOutStream> realOutStream;
				RINOK(extractCallback->GetStream(index, &realOutStream, askMode));

				if (item.isFolder) {
					extractCallback->SetOperationResult(NExtract::NOperationResult::kOK);
					continue;
				}

				if (!testMode && !realOutStream) {
					continue;
				}

				RINOK(extractCallback->PrepareOperation(askMode));

				if (!testMode && realOutStream) {
					HRESULT extractResult = PKGHandler.ExtractFile(index, realOutStream, nullptr);

					if (extractResult == E_NOTIMPL) {
						extractCallback->SetOperationResult(NExtract::NOperationResult::kUnsupportedMethod);
						continue;
					}
					else if (FAILED(extractResult)) {
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
			*stream = nullptr;
			return S_FALSE;
		}

		STDMETHODIMP CHandler::GetFileTimeType(UInt32* type)
		{
			if (!type)
				return E_POINTER;
			*type = NFileTimeType::kUnix;
			return S_OK;
		}

	/**
	 * @brief Detects if a path structure contains PS3 content at root and should skip the container folder
	 * @param items List of all items being added
	 * @return The common root folder to strip, or empty string if no stripping needed
	 */
		static std::string DetectPS3RootFolder(const std::vector<std::string>& paths, const std::vector<bool>& isFolder)
		{
			if (paths.empty() || paths.size() != isFolder.size())
				return "";

			logDebug(L"DetectPS3RootFolder: Analyzing " + std::to_wstring(paths.size()) + L" paths");

			// Common PS3 required directories/files
			static const std::vector<std::string> ps3Markers = {
					"PS3_GAME",
					"USRDIR",
					"PARAM.SFO",
					"ICON0.PNG",
					"TROPDIR",
					"PS3_DISC.SFB",
					"EBOOT.BIN",
					"PIC1.PNG",
					"PS3LOGO.DAT"
			};

			// Find the common root folder (if any)
			std::string commonRoot;
			bool hasCommonRoot = false;
			int rootFolderIndex = -1;

			for (size_t idx = 0; idx < paths.size(); idx++) {
				const auto& path = paths[idx];

				size_t firstSlash = path.find('/');
				if (firstSlash == std::string::npos)
					firstSlash = path.find('\\');

				if (firstSlash != std::string::npos) {
					// Path has a slash - extract root folder
					std::string rootFolder = path.substr(0, firstSlash);

					if (commonRoot.empty()) {
						commonRoot = rootFolder;
						hasCommonRoot = true;
						logDebug(L"  Common root candidate: " + std::wstring(commonRoot.begin(), commonRoot.end()));
					}
					else if (rootFolder != commonRoot) {
						// Multiple root folders - don't strip anything
						logDebug(L"  Multiple root folders detected, no stripping");
						return "";
					}
				}
				else {
					// No slash in path - could be the root folder itself or a file at root
					if (isFolder[idx]) {
						// This is likely the root folder entry itself
						if (commonRoot.empty()) {
							commonRoot = path;
							rootFolderIndex = (int)idx;
							hasCommonRoot = true;
							logDebug(L"  Found root folder entry: " + std::wstring(commonRoot.begin(), commonRoot.end()));
						}
						else if (path != commonRoot) {
							// Multiple root folders
							logDebug(L"  Multiple root folders detected, no stripping");
							return "";
						}
					}
					else {
						// File at root level (not in any folder) - don't strip
						logDebug(L"  File at root level detected: " + std::wstring(path.begin(), path.end()));
						return "";
					}
				}
			}

			if (!hasCommonRoot || commonRoot.empty()) {
				logDebug(L"  No common root found");
				return "";
			}

			// Check if any PS3 content markers exist directly under the common root
			int markerCount = 0;
			for (size_t idx = 0; idx < paths.size(); idx++) {
				const auto& path = paths[idx];

				// Skip the root folder entry itself
				if ((int)idx == rootFolderIndex) {
					continue;
				}

				// Remove the common root prefix to get relative path
				std::string relativePath = path;
				if (relativePath.length() > commonRoot.length() + 1) {
					relativePath = relativePath.substr(commonRoot.length() + 1);
				}
				else if (relativePath.length() == commonRoot.length() && relativePath == commonRoot) {
					// This is the root folder itself
					continue;
				}

				// Check if this path starts with a PS3 marker
				for (const auto& marker : ps3Markers) {
					if (relativePath == marker ||
						relativePath.find(marker + "/") == 0 ||
						relativePath.find(marker + "\\") == 0) {
						markerCount++;
						logDebug(L"  Found PS3 marker: " + std::wstring(marker.begin(), marker.end()) +
							L" in path: " + std::wstring(relativePath.begin(), relativePath.end()));
						break; // Found marker for this path, move to next path
					}
				}
			}

			// If we found at least 2 PS3 markers, it's likely PS3 content - strip the root
			if (markerCount >= 2) {
				logDebug(L"   STRIPPING ROOT: " + std::wstring(commonRoot.begin(), commonRoot.end()) +
					L" (found " + std::to_wstring(markerCount) + L" PS3 markers)");
				return commonRoot;
			}

			// No PS3 markers found - keep the structure as-is
			logDebug(L"  Not enough PS3 markers found (" + std::to_wstring(markerCount) + L"), keeping structure");
			return "";
		}


		STDMETHODIMP CHandler::UpdateItems(ISequentialOutStream* outStream, UInt32 numItems, IArchiveUpdateCallback* callback)
		{
			COM_TRY_BEGIN

				logDebug(L"UpdateItems called: numItems=" + std::to_wstring(numItems));

			if (!callback)
				return E_FAIL;

			CMyComPtr<IArchiveUpdateCallback2> callback2;
			RINOK(callback->QueryInterface(IID_IArchiveUpdateCallback2, (void**)&callback2));

			// Determine which format we're writing
			PKG_FORMAT targetFormat = PKGHandler.GetFormat();

			// If no format detected (new archive), default to PS3
			if (targetFormat == PKG_FORMAT_UNKNOWN) {
				targetFormat = PKG_FORMAT_PS3;
				logDebug(L"UpdateItems: No format detected, defaulting to PS3 PKG");
			}

			logDebug(L"UpdateItems: Target format = " + std::to_wstring((int)targetFormat));

			std::string contentIDStr;

			// Get existing Content ID
			if (!items.empty() && !contentID.empty()) {
				for (size_t i = 0; i < contentID.length() && i < 0x2F; i++) {
					contentIDStr += (char)contentID[i];
				}
				logDebug(L"UpdateItems: Using existing Content ID: " + contentID);
			}

			// Pre-cache files from archive
			logDebug(L"UpdateItems: Pre-caching files from archive...");
			std::map<UInt32, std::vector<Byte>> cachedFiles;

			for (UInt32 i = 0; i < numItems; i++) {
				Int32 newData = 0;
				Int32 newProps = 0;
				UInt32 indexInArchive = (UInt32)-1;
				RINOK(callback->GetUpdateItemInfo(i, &newData, &newProps, &indexInArchive));

				bool isFromArchive = (indexInArchive != (UInt32)-1 && newData == 0);

				if (isFromArchive && indexInArchive < items.size()) {
					auto& item = items[indexInArchive];

					if (!item.isFolder && item.size > 0) {
						CMyComPtr<ISequentialInStream> itemStream;
						HRESULT hr = GetStream(indexInArchive, &itemStream);

						if (SUCCEEDED(hr) && itemStream) {
							std::vector<Byte> buffer(item.size);
							UInt32 bytesRead = 0;

							hr = ReadStream_FALSE(itemStream, buffer.data(), (UInt32)item.size);
							if (FAILED(hr)) {
								logDebug(L"UpdateItems: Failed to read stream for index " + std::to_wstring(indexInArchive));
								return hr;
							}

							cachedFiles[indexInArchive] = std::move(buffer);
						}
					}
				}
			}

			logDebug(L"UpdateItems: Cached " + std::to_wstring(cachedFiles.size()) + L" files");

			logDebug(L"UpdateItems: Releasing input stream...");
			PKGHandler.ReleaseStream();
			logDebug(L"UpdateItems: Stream released");

			logDebug(L"UpdateItems: Building item list...");

			struct ItemInfo {
				std::string path;
				UInt64 size;
				bool isFolder;
				UInt32 flags;
				UInt32 type;
				bool isFromArchive;
				UInt32 archiveIndex;
				CMyComPtr<IInStream> newStream;
			};

			std::vector<ItemInfo> itemList;
			itemList.reserve(numItems);

			std::vector<std::string> allPaths;
			std::vector<bool> allIsFolder;
			allPaths.reserve(numItems);
			allIsFolder.reserve(numItems);

			for (UInt32 i = 0; i < numItems; i++) {
				NWindows::NCOM::CPropVariant prop;

				RINOK(callback->GetProperty(i, kpidPath, &prop));
				if (prop.vt != VT_BSTR)
					return E_INVALIDARG;

				UString widePath = prop.bstrVal;
				std::string path;
				for (int j = 0; j < widePath.Len(); j++) {
					path += (char)widePath[j];
				}
				std::replace(path.begin(), path.end(), '\\', '/');
				allPaths.push_back(path);
				prop.Clear();

				RINOK(callback->GetProperty(i, kpidIsDir, &prop));
				if (prop.vt != VT_BOOL)
					return E_INVALIDARG;
				bool isFolder = (prop.boolVal != VARIANT_FALSE);
				allIsFolder.push_back(isFolder);
				prop.Clear();
			}

			std::string rootToStrip = DetectPS3RootFolder(allPaths, allIsFolder);

			if (!rootToStrip.empty()) {
				logDebug(L"Stripping root folder: " + std::wstring(rootToStrip.begin(), rootToStrip.end()));
			}
			else {
				// If no root detected from DetectPS3RootFolder, try to find a common prefix for new files
				// This handles the case where we're adding files from a folder on disk
				std::string commonPrefix;
				bool hasNewFiles = false;

				for (UInt32 i = 0; i < numItems; i++) {
					Int32 newData = 0;
					Int32 newProps = 0;
					UInt32 indexInArchive = (UInt32)-1;
					callback->GetUpdateItemInfo(i, &newData, &newProps, &indexInArchive);

					bool isFromArchive = (indexInArchive != (UInt32)-1 && newData == 0);
					if (!isFromArchive && !allIsFolder[i]) {
						hasNewFiles = true;
						const std::string& path = allPaths[i];
						size_t slashPos = path.find('/');
						if (slashPos != std::string::npos) {
							std::string firstSegment = path.substr(0, slashPos);
							if (commonPrefix.empty()) {
								commonPrefix = firstSegment;
							}
							else if (commonPrefix != firstSegment) {
								commonPrefix.clear();
								break;
							}
						}
					}
				}

				// Only strip if we found a common prefix and it's not a system path
				if (hasNewFiles && !commonPrefix.empty() &&
					commonPrefix.find("..") == std::string::npos &&
					commonPrefix != "PARAM.SFO" && commonPrefix != "ICON0.PNG" &&
					commonPrefix != "PIC1.PNG" && commonPrefix != "USRDIR") {
					rootToStrip = commonPrefix;
					logDebug(L"Detected common prefix for new files: " + std::wstring(commonPrefix.begin(), commonPrefix.end()));
				}
			}

			for (UInt32 i = 0; i < numItems; i++) {
				NWindows::NCOM::CPropVariant prop;
				Int32 newData = 0;
				Int32 newProps = 0;
				UInt32 indexInArchive = (UInt32)-1;
				RINOK(callback->GetUpdateItemInfo(i, &newData, &newProps, &indexInArchive));

				bool isFromArchive = (indexInArchive != (UInt32)-1 && newData == 0);

				std::string path = allPaths[i];
				bool isFolder = allIsFolder[i];

				if (!rootToStrip.empty()) {
					if (path == rootToStrip) {
						logDebug(L"Skipping root folder entry: " + std::wstring(path.begin(), path.end()));
						continue;
					}

					if (path.length() > rootToStrip.length() + 1 &&
						path.substr(0, rootToStrip.length()) == rootToStrip &&
						(path[rootToStrip.length()] == '/' || path[rootToStrip.length()] == '\\')) {

						path = path.substr(rootToStrip.length() + 1);
						logDebug(L"Stripped path: " + std::wstring(path.begin(), path.end()));
					}
				}

				if (path.empty()) {
					logDebug(L"Skipping empty path after stripping");
					continue;
				}

				// Get size
				UInt64 size = 0;
				if (!isFolder) {
					RINOK(callback->GetProperty(i, kpidSize, &prop));
					if (prop.vt != VT_UI8)
						return E_INVALIDARG;
					size = prop.uhVal.QuadPart;
					prop.Clear();
				}

				UInt32 flags = 0;
				UInt32 type = 0;

				if (targetFormat == PKG_FORMAT_PS3) {
					flags = 0;
				}
				else if (targetFormat == PKG_FORMAT_PS4) {
					type = isFolder ? 0 : 0x1000;
					flags = 0;
				}

				ItemInfo info;
				info.path = path;
				info.size = size;
				info.isFolder = isFolder;
				info.flags = flags;
				info.type = type;
				info.isFromArchive = isFromArchive;
				info.archiveIndex = indexInArchive;

				// Get stream for new files
				if (!isFromArchive && !isFolder && size > 0) {
					CMyComPtr<ISequentialInStream> fileInStream;
					RINOK(callback->GetStream(i, &fileInStream));
					if (!fileInStream) {
						logDebug(L"UpdateItems: GetStream returned null for new file");
						return E_FAIL;
					}

					RINOK(fileInStream->QueryInterface(IID_IInStream, (void**)&info.newStream));
					if (!info.newStream) {
						logDebug(L"UpdateItems: New file does not support IInStream");
						return E_FAIL;
					}
				}

				itemList.push_back(info);

				// Content ID derivation (if not already set)
				if (contentIDStr.empty() && !path.empty()) {
					size_t dashPos = path.find('-');
					size_t underscorePos = path.find('_');

					if (dashPos != std::string::npos && underscorePos != std::string::npos &&
						dashPos < underscorePos && underscorePos < 40) {

						size_t slashPos = path.find('/');
						size_t endPos = (slashPos != std::string::npos && slashPos < 40) ?
							slashPos : std::min(path.length(), (size_t)36);

						std::string potentialID = path.substr(0, endPos);

						if (potentialID.length() >= 16 && potentialID.length() <= 36) {
							bool validFormat = true;
							for (char c : potentialID) {
								if (!isalnum(c) && c != '-' && c != '_') {
									validFormat = false;
									break;
								}
							}

							if (validFormat) {
								contentIDStr = potentialID;
								logDebug(L"UpdateItems: Derived Content ID from path");
							}
						}
					}
				}
			}

			logDebug(L"UpdateItems: Item list built with " + std::to_wstring(itemList.size()) + L" items");

			// Write PKG based on format
			if (targetFormat == PKG_FORMAT_PS3) {
				logDebug(L"UpdateItems: Creating PS3 PKG...");

				PS3PKGWriter writer;

				for (const auto& item : itemList) {
					if (item.isFolder) {
						RINOK(writer.addDirectory(item.path));
					}
					else if (item.size > 0) {
						if (item.isFromArchive) {
							auto it = cachedFiles.find(item.archiveIndex);
							if (it == cachedFiles.end()) {
								logDebug(L"UpdateItems: Cached file not found for archive index " + std::to_wstring(item.archiveIndex));
								return E_FAIL;
							}

							RINOK(writer.addItemWithBuffer(item.path, item.size, std::move(it->second), false, 0));
						}
						else {
							RINOK(writer.addFile(item.path, item.size, item.newStream));
						}
					}
					else {
						RINOK(writer.addFile(item.path, 0, item.newStream));
					}
				}

				// ========================================================================
				// ADDED: Find PARAM.SFO and read Content ID from memory
				// ========================================================================
				std::vector<uint8_t> sfoBuffer;
				UInt32 sfoIndex = (UInt32)-1;

				for (UInt32 i = 0; i < itemList.size(); i++) {
					const auto& item = itemList[i];
					std::string upperPath = item.path;
					std::transform(upperPath.begin(), upperPath.end(), upperPath.begin(), ::toupper);

					if (upperPath.find("PARAM.SFO") != std::string::npos) {
						sfoIndex = i;
						logDebug(L"UpdateItems: Found PARAM.SFO at: " + std::wstring(item.path.begin(), item.path.end()));

						if (item.isFromArchive) {
							// It's from the archive, use cached file
							auto it = cachedFiles.find(item.archiveIndex);
							if (it != cachedFiles.end()) {
								sfoBuffer = it->second;
								logDebug(L"UpdateItems: Using cached PARAM.SFO from archive (" +
									std::to_wstring(sfoBuffer.size()) + L" bytes)");
							}
						}
						else if (item.newStream && item.size > 0) {
							// It's a new file being added
							sfoBuffer.resize(item.size);
							RINOK(item.newStream->Seek(0, STREAM_SEEK_SET, nullptr));

							UInt32 read = 0;
							HRESULT hr = item.newStream->Read(sfoBuffer.data(), (UInt32)item.size, &read);
							if (SUCCEEDED(hr) && read == item.size) {
								logDebug(L"UpdateItems: Read new PARAM.SFO into memory (" +
									std::to_wstring(sfoBuffer.size()) + L" bytes)");
							}
							else {
								logDebug(L"UpdateItems: Failed to read new PARAM.SFO");
								sfoBuffer.clear();
							}

							// Reset stream position
							RINOK(item.newStream->Seek(0, STREAM_SEEK_SET, nullptr));
						}
						break;
					}
				}

				// Try to read Content ID from SFO buffer
				if (!sfoBuffer.empty() && contentIDStr.empty()) {
					std::string sfoContentID = SFOReader::getContentIDFromMemory(sfoBuffer.data(), sfoBuffer.size());
					if (!sfoContentID.empty()) {
						contentIDStr = sfoContentID;
						logDebug(L"UpdateItems: Using Content ID from PARAM.SFO: " +
							std::wstring(sfoContentID.begin(), sfoContentID.end()));
					}
					else {
						logDebug(L"UpdateItems: Could not read Content ID from PARAM.SFO buffer");
					}
				}
				else if (sfoBuffer.empty()) {
					logDebug(L"UpdateItems: PARAM.SFO not found in item list");
				}
				// ========================================================================

				logDebug(L"UpdateItems: Writing PS3 PKG to output stream...");
				RINOK(writer.writePKG(outStream, callback, contentIDStr, "", true));
				logDebug(L"UpdateItems: PS3 PKG written successfully!");
			}
			else if (targetFormat == PKG_FORMAT_PS4) {
				logDebug(L"UpdateItems: Creating PS4 PKG (FPKG)...");

				PS4PKGWriter writer;

				for (const auto& item : itemList) {
					if (item.isFolder) {
						RINOK(writer.addItem(item.path, 0, nullptr, true, item.flags, 0));
					}
					else if (item.size > 0) {
						if (item.isFromArchive) {
							auto it = cachedFiles.find(item.archiveIndex);
							if (it == cachedFiles.end()) {
								logDebug(L"UpdateItems: Cached file not found for archive index " + std::to_wstring(item.archiveIndex));
								return E_FAIL;
							}

							RINOK(writer.addItemWithBuffer(item.path, item.size, std::move(it->second), false, item.flags, item.type));
						}
						else {
							RINOK(writer.addItem(item.path, item.size, item.newStream, false, item.flags, item.type));
						}
					}
					else {
						RINOK(writer.addItem(item.path, 0, nullptr, false, item.flags, item.type));
					}
				}

				logDebug(L"UpdateItems: Writing PS4 PKG (FPKG) to output stream...");
			//	RINOK(writer.writeFPKG(outStream, callback, contentIDStr));
				logDebug(L"UpdateItems: PS4 PKG (FPKG) written successfully!");
			}
			else if (targetFormat == PKG_FORMAT_PS5) {
				logDebug(L"UpdateItems: PS5 PKG writing not supported");
				return E_NOTIMPL;
			}
			else {
				logDebug(L"UpdateItems: Unsupported format for writing: " + std::to_wstring((int)targetFormat));
				return E_NOTIMPL;
			}

			RINOK(callback->SetOperationResult(NArchive::NExtract::NOperationResult::kOK));
			return S_OK;

			COM_TRY_END
		}

		STDMETHODIMP CHandler::SetProperties(const wchar_t* const* names, const PROPVARIANT* values, UInt32 numProps)
		{
			return S_OK;
		}

		STDMETHODIMP CHandler::GetMultiArchiveNameFmt(PROPVARIANT* nameMod, PROPVARIANT* prefix, PROPVARIANT* postfix, BOOL* numberAfterExt, UInt32* digitCount)
		{
			NWindows::NCOM::CPropVariant prop;
			prop = "_";
			prop.Detach(prefix);
			UString name = nameMod->bstrVal;
			auto end = name.Len();
			if (end > 4 && name[end - 1] == L'r' && name[end - 2] == L'i' && name[end - 3] == L'd' && name[end - 4] == L'_')
				name.DeleteFrom(end - 4);
			prop = name;
			prop.Detach(nameMod);
			*numberAfterExt = FALSE;
			*digitCount = 3;
			return S_OK;
		}

		API_FUNC_IsArc IsArc_PKG_PUP(const Byte* p, size_t size)
		{
			if (size < 0x20)
				return k_IsArc_Res_NEED_MORE;

			// Check all known signatures
			if (memcmp(p, "\x7F\x50\x4B\x47", 4) == 0 ||  // PS3 PKG
				memcmp(p, "\x7F\x43\x4E\x54", 4) == 0 ||  // PS4 PKG
				memcmp(p, "\x53\x43\x45\x55", 4) == 0 ||  // PS3 PUP
				memcmp(p, "\x7F\x46\x49\x48", 4) == 0)   // PS5 PKG
			{
				return k_IsArc_Res_YES;
			}

			// PS4 PUP detection (no magic signature)
			UInt16 hs = p[0x0C] | (p[0x0D] << 8);
			UInt16 ec = p[0x18] | (p[0x19] << 8);
			if (hs >= 0x20 && hs <= 0x100000 && ec > 0 && ec <= 5000)
				return k_IsArc_Res_YES;

			return k_IsArc_Res_NO;
		}


		static IInArchive* CreateArcIn_PS3() { return new CHandlerPS3(); }
		static IOutArchive* CreateArcOut_PS3() { return new CHandlerPS3(); }
		static const CArcInfo g_ArcInfo_PS3 = {
				NArcInfoFlags::kStartOpen | NArcInfoFlags::kPureStartOpen,
				0xE1,
				sizeof(kSignaturePS3),
				0,
				0,
				kSignaturePS3,
				"PlayStation 3 PKG",
				"pkg",
				nullptr,
				CreateArcIn_PS3,
				CreateArcOut_PS3,
				IsArc_PKG_PUP
		};
		struct CRegisterArc_PS3 { CRegisterArc_PS3() { RegisterArc(&g_ArcInfo_PS3); } };
		static CRegisterArc_PS3 g_RegisterArc_PS3;

		// PS4 PKG
		static IInArchive* CreateArcIn_PS4() { return new CHandlerPS4(); }
		static IOutArchive* CreateArcOut_PS4() { return new CHandlerPS4(); }
		static const CArcInfo g_ArcInfo_PS4 = {
				NArcInfoFlags::kStartOpen | NArcInfoFlags::kPureStartOpen,
				0xE2,
				sizeof(kSignaturePS4),
				0,
				0,
				kSignaturePS4,
				"PlayStation 4 PKG",
				"pkg",
				nullptr,
				CreateArcIn_PS4,
				CreateArcOut_PS4,
				IsArc_PKG_PUP
		};
		struct CRegisterArc_PS4 { CRegisterArc_PS4() { RegisterArc(&g_ArcInfo_PS4); } };
		static CRegisterArc_PS4 g_RegisterArc_PS4;

		// PS5 PKG
		static IInArchive* CreateArcIn_PS5() { return new CHandlerPS5(); }
		static IOutArchive* CreateArcOut_PS5() { return new CHandlerPS5(); }
		static const CArcInfo g_ArcInfo_PS5 = {
				NArcInfoFlags::kStartOpen | NArcInfoFlags::kPureStartOpen,
				0xE3,
				sizeof(kSignaturePS5),
				0,
				0,
				kSignaturePS5,
				"PlayStation 5 PKG",
				"pkg",
				nullptr,
				CreateArcIn_PS5,
				CreateArcOut_PS5,
				IsArc_PKG_PUP
		};
		struct CRegisterArc_PS5 { CRegisterArc_PS5() { RegisterArc(&g_ArcInfo_PS5); } };
		static CRegisterArc_PS5 g_RegisterArc_PS5;
		} // namespace NPKG
} // namespace NArchive