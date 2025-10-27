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
#include "InstallShieldInstallerHandler.h"
#include <cstdint>

#ifdef _DEBUG
#include <fstream>
#endif

using namespace NWindows;
namespace NArchive {
  namespace NInstallShield {

    // InstallShield signatures
    static const Byte kSignature[] = { 'I', 'n', 's', 't', 'a', 'l', 'l', 'S', 'h', 'i', 'e', 'l', 'd', 0x00 };
    static const Byte kSignatureStream[] = { 'I', 'S', 'S', 'e', 't', 'u', 'p', 'S', 't', 'r', 'e', 'a', 'm', 0x00 };

    static const Byte kProps[] =
    {
        kpidPath,
        kpidSize,
        kpidPackSize,
    };

#ifdef _DEBUG
    void DebugLog(const wchar_t* message) {
      std::wofstream logFile;
      logFile.open(L"C:\\installshield_debug.log", std::ios::app);
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

    private:
      InstallShieldHandler handler;
      std::vector<InstallShieldHandler::FileInfo> items;
    };

    STDMETHODIMP CHandler::GetNumberOfArchiveProperties(UInt32* numProps)
    {
      DebugLog(L"GetNumberOfArchiveProperties called");
      *numProps = 0;
      return S_OK;
    }

    STDMETHODIMP CHandler::GetArchivePropertyInfo(UInt32 index, BSTR* name, PROPID* propID, VARTYPE* varType)
    {
      DebugLog(L"GetArchivePropertyInfo called");
      return E_NOTIMPL;
    }

    STDMETHODIMP CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT* value)
    {
      DebugLog(L"GetArchiveProperty called, propID=" + std::to_wstring(propID));
      NCOM::CPropVariant prop;
      prop.Detach(value);
      return S_OK;
    }

    STDMETHODIMP CHandler::Open(IInStream* stream, const UInt64* maxCheckStartPosition, IArchiveOpenCallback* callback) {
      DebugLog(L"=== OPEN CALLED ===");
      Close();

      if (!callback || !stream) {
        DebugLog(L"Open: Invalid parameters");
        return S_FALSE;
      }

      // Try to open the InstallShield archive
      HRESULT result = handler.Open(stream, nullptr, callback);
      if (FAILED(result)) {
        DebugLog(L"Open: InstallShieldHandler.Open failed with error " + std::to_wstring(result));
        return result;
      }

      // Copy items from handler
      items = handler.items;

      if (items.empty()) {
        DebugLog(L"Open: No items found in archive");
        return S_FALSE;
      }

      DebugLog(L"Open: Items loaded = " + std::to_wstring(items.size()));
#ifdef _DEBUG
      for (size_t i = 0; i < items.size(); i++) {
        std::wstring path(items[i].path.begin(), items[i].path.end());
        DebugLog(L"  [" + std::to_wstring(i) + L"] " + path +
          L" (size: " + std::to_wstring(items[i].uncompressedSize) + L")");
      }
#endif

      DebugLog(L"Open: SUCCESS - Archive opened with " + std::to_wstring(items.size()) + L" items");

      return S_OK;
    }

    STDMETHODIMP CHandler::Close() {
      DebugLog(L"Close called");
      items.clear();
      handler.items.clear();
      return S_OK;
    }

    STDMETHODIMP CHandler::GetNumberOfItems(UInt32* numItems) {
      if (numItems == nullptr) {
        DebugLog(L"GetNumberOfItems: NULL pointer!");
        return E_POINTER;
      }

      *numItems = static_cast<UInt32>(items.size());
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
          // Convert UTF-8 std::string to UString
          const std::string& pathStr = items[index].path;

          // Convert UTF-8 to wide string properly
          int size_needed = MultiByteToWideChar(CP_UTF8, 0, pathStr.c_str(), -1, nullptr, 0);
          if (size_needed > 0) {
            std::wstring wpath(size_needed - 1, 0);
            MultiByteToWideChar(CP_UTF8, 0, pathStr.c_str(), -1, &wpath[0], size_needed - 1);

            UString widePath;
            for (wchar_t ch : wpath) {
              widePath += ch;
            }

            prop = widePath;

#ifdef _DEBUG
            DebugLog(L"    Returning path: " + wpath);
#endif
          }
          else {
            // Fallback to simple conversion
            UString widePath;
            for (size_t i = 0; i < pathStr.length(); i++) {
              widePath += (wchar_t)(unsigned char)pathStr[i];
            }
            prop = widePath;
          }
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

    STDMETHODIMP CHandler::Extract(const UInt32* indices, UInt32 numItems, Int32 testMode, IArchiveExtractCallback* extractCallback) {
      DebugLog(L"Extract called: numItems=" + std::to_wstring(numItems));

      bool allFilesMode = (numItems == (UInt32)(Int32)-1);
      if (allFilesMode) {
        numItems = static_cast<UInt32>(items.size());
        DebugLog(L"Extract: All files mode, extracting " + std::to_wstring(numItems) + L" items");
      }

      if (numItems == 0) {
        DebugLog(L"Extract: No items to extract");
        return S_OK;
      }

      // Calculate total size
      UInt64 totalSize = 0;
      for (UInt32 i = 0; i < numItems; i++) {
        UInt32 index = allFilesMode ? i : indices[i];
        if (index < items.size()) {
          totalSize += items[index].uncompressedSize;
        }
      }

      DebugLog(L"Extract: Total size = " + std::to_wstring(totalSize));
      RINOK(extractCallback->SetTotal(totalSize));

      CLocalProgress* lps = new CLocalProgress;
      CMyComPtr<ICompressProgressInfo> progress = lps;
      lps->Init(extractCallback, false);

      UInt64 currentSize = 0;

      for (UInt32 i = 0; i < numItems; i++) {
        lps->InSize = currentSize;
        lps->OutSize = currentSize;
        RINOK(lps->SetCur());

        UInt32 index = allFilesMode ? i : indices[i];

        if (index >= items.size()) {
          DebugLog(L"Extract: Index out of range: " + std::to_wstring(index));
          continue;
        }

        auto& item = items[index];

        DebugLog(L"Extract: Processing item " + std::to_wstring(index) +
          L": " + std::wstring(item.path.begin(), item.path.end()));

        CMyComPtr<ISequentialOutStream> realOutStream;
        Int32 askMode = testMode ? NExtract::NAskMode::kTest : NExtract::NAskMode::kExtract;

        RINOK(extractCallback->GetStream(index, &realOutStream, askMode));

        if (!testMode && !realOutStream) {
          DebugLog(L"Extract: No output stream for item " + std::to_wstring(index));
          currentSize += item.uncompressedSize;
          continue;
        }

        RINOK(extractCallback->PrepareOperation(askMode));

        // Write decompressed data
        if (realOutStream && !item.decompressedData.empty()) {
          UInt32 processedSize = 0;
          HRESULT writeResult = realOutStream->Write(
            item.decompressedData.data(),
            static_cast<UInt32>(item.decompressedData.size()),
            &processedSize
          );

          if (FAILED(writeResult)) {
            DebugLog(L"Extract: Write failed for index " + std::to_wstring(index));
            return writeResult;
          }

          DebugLog(L"Extract: Wrote " + std::to_wstring(processedSize) + L" bytes");
        }

        currentSize += item.uncompressedSize;
        realOutStream.Release();

        RINOK(extractCallback->SetOperationResult(NExtract::NOperationResult::kOK));
      }

      lps->InSize = totalSize;
      lps->OutSize = totalSize;
      return lps->SetCur();
    }

    STDMETHODIMP CHandler::GetStream(UInt32 index, ISequentialInStream** stream) {
      DebugLog(L"GetStream called: index=" + std::to_wstring(index));

      if (index >= items.size()) {
        DebugLog(L"GetStream: Index out of range");
        return E_FAIL;
      }

      *stream = nullptr;

      if (items[index].decompressedData.empty()) {
        DebugLog(L"GetStream: No data for item " + std::to_wstring(index));
        return S_FALSE;
      }

      CBufInStream* streamSpec = new CBufInStream;
      CMyComPtr<ISequentialInStream> streamTemp = streamSpec;

      streamSpec->Init(
        reinterpret_cast<const Byte*>(items[index].decompressedData.data()),
        static_cast<size_t>(items[index].decompressedData.size())
      );

      *stream = streamTemp.Detach();

      DebugLog(L"GetStream: Stream created successfully");
      return S_OK;
    }

    // Register the archive format
    REGISTER_ARC_I(
      "InstallShield", 
      "exe",         
      0,               
      0xAC,            
      kSignature,      
      0,               
      NArcInfoFlags::kFindSignature, 
      NULL,           
      NULL 
    )

  }
}