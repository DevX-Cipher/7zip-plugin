#include "stdafx.h"

#pragma warning (disable: 5043)

#include "../../../Common/ComTry.h"
#include "../../../Common/MyString.h"

#include "../../../Windows/PropVariant.h"

#include "../../Common/ProgressUtils.h"
#include "../../Common/RegisterArc.h"
#include "../../Common/StreamObjects.h"

#include <sstream>
#include <iostream>
#include <Windows.h>
#include <string>
#include <vector>
#include <iomanip>

#pragma comment(lib, "Ws2_32.lib")


using namespace NWindows;

namespace NArchive {
    namespace NZzz {

        struct CTOCEntry {
            uint32_t position;
            uint32_t cmprsdDataSize;
            uint32_t uncmprsdDataSize;
            uint8_t cmprsFlag;
            char typeCmprsData;
            std::wstring name;

            CTOCEntry(uint32_t pos, uint32_t cmprsdSize, uint32_t uncmprsdSize, uint8_t flag, char type, const std::wstring& n)
                : position(pos), cmprsdDataSize(cmprsdSize), uncmprsdDataSize(uncmprsdSize), cmprsFlag(flag), typeCmprsData(type), name(n) {}
        };

        class CHandler : public IInArchive, public IInArchiveGetStream, public CMyUnknownImp {
        public:
            MY_UNKNOWN_IMP2(IInArchive, IInArchiveGetStream)
                INTERFACE_IInArchive(;)
                STDMETHOD(GetStream)(UInt32 index, ISequentialInStream** stream);
            STDMETHODIMP ParseArchive(IInStream* stream, UInt64 fileSize);

            // Constructor and other methods...

        private:
            const size_t PYINST20_COOKIE_SIZE = 32;
            static const uint8_t PYINST21_COOKIE_SIZE = 24 + 64;
            uint64_t tableOfContentsPos;
            uint64_t tableOfContentsSize;
            uint32_t lengthofPackage;
            uint32_t toc;
            uint32_t tocLen;
            uint32_t pyver;
            uint64_t cookiePos;
            std::vector<CTOCEntry> items;

            
        };

IMP_IInArchive_ArcProps_NO_Table

void HandleError(const std::wstring& errorMessage);

// Function to convert std::string to std::wstring
std::wstring stringToWString(const std::string& str) {
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), NULL, 0);
    std::wstring wstr(size_needed, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), &wstr[0], size_needed);
    return wstr;
}

std::wstring UStringToWString(const UString& ustr) {
    return std::wstring(ustr.Ptr(), ustr.Len());
}

std::string wstringToString(const std::wstring& wstr) {
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), NULL, 0, NULL, NULL);
    std::string str(size_needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), &str[0], size_needed, NULL, NULL);
    return str;
}

STDMETHODIMP CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT* value)
{
	std::wstringstream ss;
	ss << L"[FormatZzz] GetArchiveProperty: " << propID << std::endl;
	OutputDebugString(ss.str().c_str());

	NCOM::CPropVariant prop;
	switch (propID)
	{
	case kpidPhySize:
		prop = (UInt64)1;
		break;
	}
	prop.Detach(value);
	return S_OK;
}

HRESULT SafeRead(IInStream* stream, void* buffer, size_t size, UInt32* bytesRead) {
    HRESULT result = stream->Read(buffer, size, bytesRead);
    if (result != S_OK || *bytesRead != size) {
        HandleError(L"Failed to read from stream");
        return S_FALSE;
    }
    return S_OK;
}

// Centralized error handling function
void HandleError(const std::wstring& errorMessage) {
    MessageBox(NULL, errorMessage.c_str(), L"Error", MB_ICONERROR);
}



const std::string MAGIC = "MEI\014\013\012\013\016";

HRESULT CHandler::Open(IInStream* stream, const UInt64*, IArchiveOpenCallback* callback) {
    if (!callback || !stream) {
        return S_FALSE;
    }

    // Get file size
    UInt64 fileSize;
    HRESULT result = stream->Seek(0, STREAM_SEEK_END, &fileSize);
    if (result != S_OK) {
        HandleError(L"Failed to seek to the end of the stream");
        return result;
    }

    // Log file size
    std::wstringstream fileSizeMsg;
    fileSizeMsg << L"File Size: " << fileSize;
    MessageBox(NULL, fileSizeMsg.str().c_str(), L"Debug Info", MB_OK);

    const size_t searchChunkSize = 8192;
    uint64_t endPos = fileSize;
    cookiePos = -1;
    UInt32 bytesRead = 0;

    // Check for the cookie position
    while (true) {
        uint64_t startPos = endPos >= searchChunkSize ? endPos - searchChunkSize : 0;
        size_t chunkSize = endPos - startPos;
        if (chunkSize < MAGIC.size()) {
            break;
        }

        // Read the chunk
        stream->Seek(startPos, STREAM_SEEK_SET, nullptr);
        std::wstringstream seekMsg;
        seekMsg << L"Seeking to: " << startPos;
        MessageBox(NULL, seekMsg.str().c_str(), L"Debug Info", MB_OK);

        std::vector<char> data(chunkSize);
        result = stream->Read(data.data(), static_cast<UInt32>(chunkSize), &bytesRead);
        if (result != S_OK || bytesRead != chunkSize) {
            HandleError(L"Failed to read the stream correctly");
            return result;
        }

        // Log read data
        std::wstringstream readMsg;
        readMsg << L"Read " << bytesRead << L" bytes from stream";
        MessageBox(NULL, readMsg.str().c_str(), L"Debug Info", MB_OK);

        auto offs = std::string(data.data(), chunkSize).rfind(MAGIC);
        if (offs != std::string::npos) {
            cookiePos = startPos + offs;
            break;
        }
        endPos = startPos + MAGIC.size() - 1;
        if (startPos == 0) {
            break;
        }
    }

    if (cookiePos == -1) {
        HandleError(L"[!] Error: Missing cookie, unsupported pyinstaller version or not a pyinstaller archive");
        return S_FALSE;
    }

    // Log the cookie position
    std::wstringstream cookiePosMsg;
    cookiePosMsg << L"Cookie Position: " << cookiePos;
    MessageBox(NULL, cookiePosMsg.str().c_str(), L"Debug Info", MB_OK);

    // Determine PyInstaller version
    stream->Seek(cookiePos + 8, STREAM_SEEK_SET, nullptr);
    char versionBuffer[64];
    result = stream->Read(versionBuffer, sizeof(versionBuffer), &bytesRead);
    if (result != S_OK || bytesRead < sizeof(uint32_t)) {
        HandleError(L"Failed to read the PyInstaller version");
        return S_FALSE;
    }
    uint32_t pyinstVer = (std::string(versionBuffer, 64).find("python") != std::string::npos) ? 21 : 20;

    // Log the PyInstaller version
    std::wstringstream versionMsg;
    versionMsg << L"PyInstaller Version: " << pyinstVer;
    MessageBox(NULL, versionMsg.str().c_str(), L"Debug Info", MB_OK);

    // Read the appropriate buffer based on version
    stream->Seek(cookiePos, STREAM_SEEK_SET, nullptr);
    if (pyinstVer == 20) {
        const size_t PYINST20_COOKIE_SIZE = 32;
        char buffer[PYINST20_COOKIE_SIZE];
        result = stream->Read(buffer, PYINST20_COOKIE_SIZE, &bytesRead);
        if (result != S_OK || bytesRead != PYINST20_COOKIE_SIZE) {
            HandleError(L"Failed to read the PyInstaller 2.0 buffer");
            return S_FALSE;
        }
        memcpy(&lengthofPackage, buffer + 8, 4);
        memcpy(&toc, buffer + 12, 4);
        memcpy(&tocLen, buffer + 16, 4);
        memcpy(&pyver, buffer + 20, 4);
    }
    else if (pyinstVer == 21) {
        const size_t PYINST21_COOKIE_SIZE = 24 + 64;
        char buffer[PYINST21_COOKIE_SIZE];
        result = stream->Read(buffer, PYINST21_COOKIE_SIZE, &bytesRead);
        if (result != S_OK || bytesRead != PYINST21_COOKIE_SIZE) {
            HandleError(L"Failed to read the PyInstaller 2.1 buffer");
            return S_FALSE;
        }
        memcpy(&lengthofPackage, buffer + 8, 4);
        memcpy(&toc, buffer + 12, 4);
        memcpy(&tocLen, buffer + 16, 4);
        memcpy(&pyver, buffer + 20, 4);
    }
    else {
        HandleError(L"Unsupported PyInstaller version");
        return S_FALSE;
    }

    // Log extracted raw values before conversion
    std::wstringstream rawValuesMsg;
    rawValuesMsg << L"Raw Values - Length of Package: "
        << std::hex << std::setw(8) << std::setfill(L'0') << lengthofPackage
        << L", TOC: " << std::hex << std::setw(8) << std::setfill(L'0') << toc
        << L", TOC Length: " << std::hex << std::setw(8) << std::setfill(L'0') << tocLen
        << L", Python Version: " << std::hex << std::setw(8) << std::setfill(L'0') << pyver;
    MessageBox(NULL, rawValuesMsg.str().c_str(), L"Debug Info", MB_OK);

    // Handle endianness
    lengthofPackage = ntohl(lengthofPackage);
    toc = ntohl(toc);
    tocLen = ntohl(tocLen);
    pyver = ntohl(pyver);

    // Calculate overlay positions
    uint64_t tailBytes = fileSize - cookiePos - (pyinstVer == 20 ? PYINST20_COOKIE_SIZE : PYINST21_COOKIE_SIZE);
    uint64_t overlaySize = static_cast<uint64_t>(lengthofPackage) + tailBytes;
    uint64_t overlayPos = fileSize - overlaySize;

    // Log overlay details
    std::wstringstream overlayMsg;
    overlayMsg << L"Overlay Size: " << overlaySize << L", Overlay Pos: " << overlayPos;
    MessageBox(NULL, overlayMsg.str().c_str(), L"Debug Info", MB_OK);

    // Correct the TOC position
    tableOfContentsPos = overlayPos + toc;
    tableOfContentsSize = tocLen;

    // Log corrected TOC position
    std::wstringstream tocPosMsg;
    tocPosMsg << L"Calculated TOC Position: " << tableOfContentsPos << L", TOC Length: " << tableOfContentsSize;
    MessageBox(NULL, tocPosMsg.str().c_str(), L"Debug Info", MB_OK);

    // Now parse the archive
    return ParseArchive(stream, fileSize);
}



HRESULT CHandler::ParseArchive(IInStream* stream, UInt64 fileSize) {
    HRESULT result;

    // Attempt to seek to the TOC position
    result = stream->Seek(tableOfContentsPos, STREAM_SEEK_SET, nullptr);
    if (result != S_OK) {
        HandleError(L"[!] Error: Failed to seek to the TOC position");
        return result;
    }

    items.clear(); // Clear the existing items before parsing
    uint32_t parsedLen = 0; // Initialize parsed length

    // Log initial TOC position and size
    std::wstringstream initialMsg;
    initialMsg << L"Seeking TOC Position: " << tableOfContentsPos << L", Size: " << tableOfContentsSize;
    MessageBox(NULL, initialMsg.str().c_str(), L"Debug Info", MB_OK);

    // Loop to parse the TOC entries
    while (parsedLen < tableOfContentsSize) {
        uint32_t entrySize;
        UInt32 bytesRead = 0;

        // Read the entry size
        result = SafeRead(stream, &entrySize, sizeof(entrySize), &bytesRead);
        if (result != S_OK) return result;
        if (bytesRead != sizeof(entrySize)) {
            HandleError(L"[!] Error: Failed to read the entire entry size");
            return S_FALSE;
        }
        entrySize = ntohl(entrySize); // Convert to host byte order

        // Log entry size
        std::wstringstream entrySizeMsg;
        entrySizeMsg << L"Entry Size: " << entrySize << ", Parsed Length: " << parsedLen << ", Remaining Size: " << (tableOfContentsSize - parsedLen);
        MessageBox(NULL, entrySizeMsg.str().c_str(), L"Debug Info", MB_OK);

        // Ensure we have enough data to read the entire entry
        if (parsedLen + entrySize > tableOfContentsSize) {
            HandleError(L"[!] Error: Entry size exceeds remaining TOC size");
            return S_FALSE;
        }

        uint32_t entryPos, cmprsdDataSize, uncmprsdDataSize;
        uint8_t cmprsFlag;
        char typeCmprsData;
        std::vector<char> nameBuffer(entrySize - (sizeof(entryPos) + sizeof(cmprsdDataSize) + sizeof(uncmprsdDataSize) + sizeof(cmprsFlag) + sizeof(typeCmprsData)));

        // Read and log entry fields
        result = SafeRead(stream, &entryPos, sizeof(entryPos), &bytesRead);
        if (result != S_OK) return result;
        if (bytesRead != sizeof(entryPos)) {
            HandleError(L"[!] Error: Failed to read the entire entry position");
            return S_FALSE;
        }

        result = SafeRead(stream, &cmprsdDataSize, sizeof(cmprsdDataSize), &bytesRead);
        if (result != S_OK) return result;
        if (bytesRead != sizeof(cmprsdDataSize)) {
            HandleError(L"[!] Error: Failed to read the entire compressed data size");
            return S_FALSE;
        }

        result = SafeRead(stream, &uncmprsdDataSize, sizeof(uncmprsdDataSize), &bytesRead);
        if (result != S_OK) return result;
        if (bytesRead != sizeof(uncmprsdDataSize)) {
            HandleError(L"[!] Error: Failed to read the entire uncompressed data size");
            return S_FALSE;
        }

        result = SafeRead(stream, &cmprsFlag, sizeof(cmprsFlag), &bytesRead);
        if (result != S_OK) return result;
        if (bytesRead != sizeof(cmprsFlag)) {
            HandleError(L"[!] Error: Failed to read the entire compression flag");
            return S_FALSE;
        }

        result = SafeRead(stream, &typeCmprsData, sizeof(typeCmprsData), &bytesRead);
        if (result != S_OK) return result;
        if (bytesRead != sizeof(typeCmprsData)) {
            HandleError(L"[!] Error: Failed to read the entire type of compressed data");
            return S_FALSE;
        }

        result = SafeRead(stream, nameBuffer.data(), nameBuffer.size(), &bytesRead);
        if (result != S_OK) return result;
        if (bytesRead != nameBuffer.size()) {
            HandleError(L"[!] Error: Failed to read the entire name buffer");
            return S_FALSE;
        }

        // Decode the name from the buffer and remove null characters
        std::wstring name(reinterpret_cast<wchar_t*>(nameBuffer.data()), nameBuffer.size() / sizeof(wchar_t));
        name.erase(std::remove(name.begin(), name.end(), L'\0'), name.end());

        // Log entry details
        std::wstringstream entryDetailsMsg;
        entryDetailsMsg << L"Entry Pos: " << ntohl(entryPos)
            << L", Compressed Size: " << ntohl(cmprsdDataSize)
            << L", Uncompressed Size: " << ntohl(uncmprsdDataSize)
            << L", Compression Flag: " << static_cast<int>(cmprsFlag)
            << L", Type: " << typeCmprsData
            << L", Name: " << name;
        MessageBox(NULL, entryDetailsMsg.str().c_str(), L"Debug Info", MB_OK);

        if (name.empty() || name[0] == L'/') {
            name = L"unnamed_" + std::to_wstring(parsedLen);
        }

        // Add the entry to the TOC list
        items.emplace_back(
            ntohl(entryPos),
            ntohl(cmprsdDataSize),
            ntohl(uncmprsdDataSize),
            cmprsFlag,
            typeCmprsData,
            name
        );

        // Update parsed length
        parsedLen += entrySize;
    }

    // Log the total number of items found
    std::wstringstream resultMsg;
    resultMsg << L"[+] Found " << items.size() << L" files in CArchive";
    MessageBox(NULL, resultMsg.str().c_str(), L"Success", MB_OK);

    return S_OK; // Success
}




STDMETHODIMP CHandler::Close() {
    return S_OK;
}

STDMETHODIMP CHandler::GetNumberOfItems(UInt32* numItems) {
    *numItems = static_cast<UInt32>(items.size());
    return S_OK;
}

STDMETHODIMP CHandler::GetPropertyInfo(UInt32 index, wchar_t** name, PROPID* propID, VARTYPE* varType) {
    if (index >= items.size()) {
        return E_INVALIDARG;
    }

    const CTOCEntry& item = items[index];  // Using CTOCEntry instead of MyVirtualItem

    // Allocate memory for the name
    size_t nameLength = item.name.length() + 1;
    *name = (wchar_t*)::CoTaskMemAlloc(nameLength * sizeof(wchar_t));
    if (*name == nullptr) {
        return E_OUTOFMEMORY;
    }
    wcscpy_s(*name, nameLength, item.name.c_str());

    // Set property ID and type
    *propID = kpidPath; // Example, set as path
    *varType = VT_BSTR; // Assuming you are using a BSTR type for the name

    return S_OK;
}


STDMETHODIMP CHandler::GetProperty(UInt32 index, PROPID propID, PROPVARIANT* value) {
    if (index >= items.size()) {
        return E_INVALIDARG;
    }
    const CTOCEntry& item = items[index];  // Using CTOCEntry instead of MyVirtualItem
    PropVariantInit(value);

    switch (propID) {
    case kpidPath:
        value->vt = VT_BSTR;
        value->bstrVal = ::SysAllocString(item.name.c_str());
        break;
    case kpidSize:
        value->vt = VT_UI8;
        value->uhVal.QuadPart = item.uncmprsdDataSize;  // Using uncmprsdDataSize for size
        break;
    case kpidIsDir:
        value->vt = VT_BOOL;
        value->boolVal = VARIANT_FALSE;  // Assuming the items are files, not directories
        break;
    default:
        return S_OK;
    }
    return S_OK;
}



STDMETHODIMP CHandler::GetNumberOfProperties(UInt32* numProps) {
    *numProps = static_cast<UInt32>(items.size());
    return S_OK;
}

STDMETHODIMP CHandler::Extract(const UInt32* indices, UInt32 numItems, Int32 testMode, IArchiveExtractCallback* extractCallback) {
    try {
        for (UInt32 i = 0; i < numItems; i++) {
            UInt32 index = indices[i];

            // Get the file information from the archive
            const CTOCEntry& fileItem = items[index];  // Using CTOCEntry instead of MyVirtualItem

            // Create a stream for the file
            CMyComPtr<ISequentialOutStream> outStream;
            HRESULT result = extractCallback->GetStream(index, &outStream, NExtract::NOperationResult::kOK);
            if (result != S_OK) {
                HandleError(L"Failed to get output stream for file.");
                return result;
            }

            // Write the file data to the output stream
            result = outStream->Write(fileItem.name.data(), static_cast<UInt32>(fileItem.uncmprsdDataSize), nullptr);
            if (result != S_OK) {
                HandleError(L"Failed to write file data to output stream.");
                return result;
            }

            // Notify the callback that the extraction is complete
            extractCallback->SetOperationResult(NExtract::NOperationResult::kOK);
        }
        return S_OK; // Successfully extracted files
    }
    catch (const std::exception& ex) {
        std::wstring errMsg = L"[!] C++ Exception in Extract: " + stringToWString(ex.what());
        MessageBox(NULL, errMsg.c_str(), L"Error", MB_ICONERROR);
        return E_FAIL; // Indicate failure
    }
    catch (...) {
        MessageBox(NULL, L"[!] Unexpected Exception occurred in Extract.", L"Error", MB_ICONERROR);
        return E_FAIL; // Indicate failure
    }
}

STDMETHODIMP CHandler::GetStream(UInt32 index, ISequentialInStream** stream) {
    if (index >= items.size()) {
        return E_INVALIDARG;
    }

    const CTOCEntry& item = items[index];  // Using CTOCEntry instead of MyVirtualItem
    CBufInStream* streamSpec = new CBufInStream;
    CMyComPtr<ISequentialInStream> streamTemp = streamSpec;

    // Initialize the stream with entry data
    // Assuming item.data contains the actual file data to be extracted
    streamSpec->Init(reinterpret_cast<const Byte*>(item.name.c_str()), static_cast<UInt32>(item.uncmprsdDataSize));
    *stream = streamTemp.Detach();

    return S_OK;
}




REGISTER_ARC_I_NO_SIG(
	"Zzz", "zzz", 0, 0xAA,
	0,
	0,
	NULL)

}}