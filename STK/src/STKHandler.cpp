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
#include "STKHandler.h"
#include <cwchar>

class CHandler :
	public IInArchive,
	public IInArchiveGetStream,
	public CMyUnknownImp
{
public:
	CHandler() {}

	MY_UNKNOWN_IMP2(IInArchive, IInArchiveGetStream)
		INTERFACE_IInArchive(override)

		STDMETHOD(GetStream)(UInt32 index, ISequentialInStream** stream) override;

private:
	STKArchiveHandler stkHandler;
	std::vector<STKArchiveHandler::FileInfo> items;
	CMyComPtr<IInStream> mainStream;
	UInt64 totalSize = 0;
};

STDMETHODIMP CHandler::Open(IInStream* inStream, const UInt64* maxCheckStartPosition, IArchiveOpenCallback* callback) MY_NO_THROW_DECL_ONLY
{
	try
	{
		Close();

		// Check STK signature
		char header[6] = { 0 };
		UInt32 bytesRead = 0;

		RINOK(inStream->Read(header, 6, &bytesRead));

		if (bytesRead < 6)
			return S_FALSE;

		// Reset to beginning
		RINOK(inStream->Seek(0, STREAM_SEEK_SET, nullptr));

		// Check for STK 2.0/2.1 or STK 1.0
		const char kSignatureSTK20[] = "STK2.0";
		const char kSignatureSTK21[] = "STK2.1";

		bool isSTK = (memcmp(header, kSignatureSTK20, 6) == 0 ||
			memcmp(header, kSignatureSTK21, 6) == 0);

		// If not STK 2.x, might be STK 1.0 (try to parse anyway)
		if (!isSTK)
		{
			// STK 1.0 has different format, let the handler validate it
		}

		// Open with STK handler
		RINOK(stkHandler.Open(inStream, nullptr, callback));

		items = stkHandler.items;
		mainStream = inStream;

		// Calculate total size
		UInt64 s = 0;
		for (size_t i = 0; i < items.size(); i++)
		{
			s += items[i].uncompressed_size > 0 ? items[i].uncompressed_size : items[i].size;
		}
		totalSize = s;

		return S_OK;
	}
	catch (...)
	{
		Close();
		return E_OUTOFMEMORY;
	}
}

STDMETHODIMP CHandler::Close() MY_NO_THROW_DECL_ONLY
{
	mainStream.Release();
	items.clear();
	stkHandler.items.clear();
	totalSize = 0;
	return S_OK;
}

STDMETHODIMP CHandler::GetNumberOfItems(UInt32* numItems) MY_NO_THROW_DECL_ONLY
{
	*numItems = static_cast<UInt32>(items.size());
	return S_OK;
}

static constexpr const PROPID kProps[] =
{
	kpidPath,
	kpidSize,
	kpidPackSize,
	kpidMTime,
	kpidCTime
};

static constexpr const PROPID kArcProps[] =
{
	kpidComment,
	kpidTotalPhySize
};

IMP_IInArchive_Props
IMP_IInArchive_ArcProps

STDMETHODIMP CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT* value) MY_NO_THROW_DECL_ONLY
{
	COM_TRY_BEGIN
		NWindows::NCOM::CPropVariant prop;
	switch (propID)
	{
	case kpidComment:
	{
		wchar_t versionStr[32];
		swprintf_s(versionStr, L"STK Version %.1f", stkHandler.version);
		prop = versionStr;
	}
	break;

	case kpidTotalPhySize:
		prop = totalSize;
		break;
	}
	prop.Detach(value);
	return S_OK;
	COM_TRY_END
}

// Helper to parse STK 2.0/2.1 timestamp string to FILETIME
static bool ParseSTKTimestamp(const std::string& timeStr, FILETIME* ft)
{
	if (timeStr.length() != 14)
		return false;

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

STDMETHODIMP CHandler::GetProperty(UInt32 index, PROPID propID, PROPVARIANT* value) MY_NO_THROW_DECL_ONLY
{
	COM_TRY_BEGIN
		if (index >= items.size())
			return E_INVALIDARG;

	const auto& item = items[index];
	NWindows::NCOM::CPropVariant prop;

	switch (propID)
	{
	case kpidPath:
	{
		if (item.path.empty())
		{
			prop = L"unnamed.bin";
		}
		else
		{
			UString widePath;
			for (size_t i = 0; i < item.path.length(); i++)
			{
				widePath += (wchar_t)(unsigned char)item.path[i];
			}
			prop = widePath;
		}
	}
	break;

	case kpidSize:
		prop = static_cast<UInt64>(item.uncompressed_size);
		break;

	case kpidPackSize:
		prop = static_cast<UInt64>(item.size);
		break;

	case kpidMTime:
	{
		if (!item.modified.empty())
		{
			FILETIME ft;
			if (ParseSTKTimestamp(item.modified, &ft))
			{
				prop = ft;
			}
		}
	}
	break;

	case kpidCTime:
	{
		if (!item.created.empty())
		{
			FILETIME ft;
			if (ParseSTKTimestamp(item.created, &ft))
			{
				prop = ft;
			}
		}
	}
	break;

	default:
		break;
	}

	prop.Detach(value);
	return S_OK;
	COM_TRY_END
}

STDMETHODIMP CHandler::Extract(const UInt32* indices, UInt32 numItems, Int32 testMode, IArchiveExtractCallback* extractCallback) MY_NO_THROW_DECL_ONLY
{
	COM_TRY_BEGIN
		const bool allFilesMode = numItems == (UInt32)(Int32)-1;
	if (allFilesMode)
		numItems = static_cast<UInt32>(items.size());

	if (numItems == 0)
		return S_OK;

	if (!mainStream)
		return E_FAIL;

	// Calculate total size
	UInt64 totalExtractSize = 0;
	for (UInt32 i = 0; i < numItems; i++)
	{
		UInt32 index = allFilesMode ? i : indices[i];
		if (index < items.size())
		{
			totalExtractSize += items[index].uncompressed_size > 0 ?
				items[index].uncompressed_size : items[index].size;
		}
	}

	RINOK(extractCallback->SetTotal(totalExtractSize));

	CMyComPtr<CLocalProgress> progress = new CLocalProgress;
	progress->Init(extractCallback, false);

	const Int32 askMode = testMode ? NArchive::NExtract::NAskMode::kTest : NArchive::NExtract::NAskMode::kExtract;
	UInt64 currentTotalSize = 0;

	for (UInt32 i = 0; i < numItems; i++)
	{
		progress->InSize = progress->OutSize = currentTotalSize;
		RINOK(progress->SetCur());

		CMyComPtr<ISequentialOutStream> realOutStream;
		UInt32 index = allFilesMode ? i : indices[i];

		if (index >= items.size())
			continue;

		RINOK(extractCallback->GetStream(index, &realOutStream, askMode));

		auto& item = items[index];
		currentTotalSize += item.decompressedData.empty() ?
			(item.uncompressed_size > 0 ? item.uncompressed_size : item.size) :
			item.decompressedData.size();

		if (!testMode && !realOutStream)
			continue;

		RINOK(extractCallback->PrepareOperation(askMode));

		Int32 opRes = NArchive::NExtract::NOperationResult::kOK;

		// Extract if not already decompressed
		if (item.decompressedData.empty())
		{
			HRESULT hr = stkHandler.ExtractFile(mainStream, item);
			if (FAILED(hr))
			{
				opRes = NArchive::NExtract::NOperationResult::kDataError;
			}
		}

		// Write decompressed data
		if (opRes == NArchive::NExtract::NOperationResult::kOK && !item.decompressedData.empty())
		{
			if (!testMode && realOutStream)
			{
				UInt32 written = 0;
				HRESULT writeResult = realOutStream->Write(
					item.decompressedData.data(),
					static_cast<UInt32>(item.decompressedData.size()),
					&written
				);

				if (FAILED(writeResult) || written != item.decompressedData.size())
					opRes = NArchive::NExtract::NOperationResult::kDataError;
			}
		}

		realOutStream.Release();
		RINOK(extractCallback->SetOperationResult(opRes));
	}

	return S_OK;
	COM_TRY_END
}

STDMETHODIMP CHandler::GetStream(UInt32 index, ISequentialInStream** stream) MY_NO_THROW_DECL_ONLY
{
	*stream = nullptr;

	if (index >= items.size())
		return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

	auto& item = items[index];

	// Extract if not already done
	if (item.decompressedData.empty() && mainStream)
	{
		HRESULT hr = stkHandler.ExtractFile(mainStream, item);
		if (FAILED(hr))
			return E_FAIL;
	}

	if (item.decompressedData.empty())
	{
		*stream = new CEmptyInStream();
		(*stream)->AddRef();
		return S_OK;
	}

	CMyComPtr<CLimitedCachedInStream> limitedStream = new CLimitedCachedInStream;

	limitedStream->SetStream(mainStream, 0);

	auto& preload = limitedStream->Buffer;
	preload.Alloc(item.decompressedData.size());
	memcpy(preload, item.decompressedData.data(), item.decompressedData.size());

	limitedStream->SetCache(item.decompressedData.size(), 0);
	RINOK(limitedStream->InitAndSeek(0, item.decompressedData.size()));

	*stream = limitedStream.Detach();
	return S_OK;
}

static constexpr const Byte k_Signature[] = {
	'S', 'T', 'K', '2', '.', '0'  // STK 2.0 signature
};

API_FUNC_IsArc IsArc_STK(const Byte* p, size_t size)
{
	if (size < 6)
		return k_IsArc_Res_NEED_MORE;

	const char kSignatureSTK20[] = "STK2.0";
	const char kSignatureSTK21[] = "STK2.1";

	if (memcmp(p, kSignatureSTK20, 6) == 0)
		return k_IsArc_Res_YES;
	if (memcmp(p, kSignatureSTK21, 6) == 0)
		return k_IsArc_Res_YES;

	// Could be STK 1.0 format - let it try
	return k_IsArc_Res_NO;
}

REGISTER_ARC_I(
	"STK",
	"stk itk ltk jtk",
	0,
	0xE1,
	k_Signature,
	0,
	NArcInfoFlags::kStartOpen,
	IsArc_STK,
	0
)