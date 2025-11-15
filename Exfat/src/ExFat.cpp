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
#include "Exfat.h"
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
	ExFATHandler exfatHandler;
	std::vector<ExFATHandler::FileInfo> items;
	CMyComPtr<IInStream> mainStream;
	UInt64 totalSize = 0;
};

STDMETHODIMP CHandler::Open(IInStream* inStream, const UInt64* maxCheckStartPosition, IArchiveOpenCallback* callback) MY_NO_THROW_DECL_ONLY
{
	try
	{
		Close();

		// Check ExFAT signature at offset 3
		const size_t magicOffset = 3;
		const size_t magicSize = 8;
		Byte magic[magicSize];

		RINOK(inStream->Seek(magicOffset, STREAM_SEEK_SET, nullptr));
		RINOK(inStream->Read(magic, magicSize, nullptr));

		const Byte kSignature[] = { 0x45, 0x58, 0x46, 0x41, 0x54, 0x20, 0x20, 0x20 }; // "EXFAT   "
		if (memcmp(magic, kSignature, magicSize) != 0)
			return S_FALSE;

		// Reset stream position
		RINOK(inStream->Seek(0, STREAM_SEEK_SET, nullptr));

		// Get file size
		UInt64 fileSize = 0;
		if (maxCheckStartPosition && *maxCheckStartPosition > 0)
		{
			fileSize = *maxCheckStartPosition;
		}
		else
		{
			RINOK(inStream->Seek(0, STREAM_SEEK_END, &fileSize));
			RINOK(inStream->Seek(0, STREAM_SEEK_SET, nullptr));
		}

		// Open with ExFAT handler
		RINOK(exfatHandler.Open(inStream, &fileSize, callback));

		items = exfatHandler.items;
		mainStream = inStream;

		// Calculate total size (files only, not directories)
		UInt64 s = 0;
		for (size_t i = 0; i < items.size(); i++)
		{
			if (!items[i].isDirectory)
				s += items[i].size;
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
	exfatHandler.items.clear();
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
	kpidIsDir,
	kpidMTime,
	kpidCTime,
	kpidATime,
	kpidAttrib
};

static constexpr const PROPID kArcProps[] =
{
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
	case kpidTotalPhySize:
		prop = totalSize;
		break;
	}
	prop.Detach(value);
	return S_OK;
	COM_TRY_END
}

// Helper function to convert ExFAT timestamp to Windows FILETIME
static void ExFATTimeToFileTime(uint32_t exfatTime, FILETIME* ft)
{
	if (exfatTime == 0)
	{
		ft->dwLowDateTime = 0;
		ft->dwHighDateTime = 0;
		return;
	}

	// ExFAT epoch: 1980-01-01 00:00:00
	// Windows epoch: 1601-01-01 00:00:00
	// Difference: 11644473600 seconds
	const uint64_t EPOCH_DIFF = 11644473600ULL;
	const uint64_t TICKS_PER_SECOND = 10000000ULL;

	uint64_t windowsTime = (exfatTime + EPOCH_DIFF) * TICKS_PER_SECOND;
	ft->dwLowDateTime = (DWORD)(windowsTime & 0xFFFFFFFF);
	ft->dwHighDateTime = (DWORD)(windowsTime >> 32);
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
			prop = L"unnamed";
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
		prop = static_cast<UInt64>(item.size);
		break;

	case kpidIsDir:
		prop = item.isDirectory;
		break;

	case kpidMTime:
	{
		FILETIME ft;
		ExFATTimeToFileTime(item.modifyTime, &ft);
		prop = ft;
	}
	break;

	case kpidCTime:
	{
		FILETIME ft;
		ExFATTimeToFileTime(item.createTime, &ft);
		prop = ft;
	}
	break;

	case kpidATime:
	{
		FILETIME ft;
		ExFATTimeToFileTime(item.accessTime, &ft);
		prop = ft;
	}
	break;

	case kpidAttrib:
		prop = static_cast<UInt32>(item.attributes);
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

	// Calculate total size (files only)
	UInt64 totalExtractSize = 0;
	for (UInt32 i = 0; i < numItems; i++)
	{
		UInt32 index = allFilesMode ? i : indices[i];
		if (!items[index].isDirectory)
			totalExtractSize += items[index].size;
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

		RINOK(extractCallback->GetStream(index, &realOutStream, askMode));

		auto& item = items[index];

		// Skip directories
		if (item.isDirectory)
		{
			RINOK(extractCallback->PrepareOperation(askMode));
			RINOK(extractCallback->SetOperationResult(NArchive::NExtract::NOperationResult::kOK));
			continue;
		}

		currentTotalSize += item.size;

		if (!testMode && !realOutStream)
			continue;

		RINOK(extractCallback->PrepareOperation(askMode));

		Int32 opRes = NArchive::NExtract::NOperationResult::kOK;

		if (item.size == 0)
		{
			realOutStream->Write("", 0, nullptr);
		}
		else
		{
			// Extract file data
			std::vector<uint8_t> fileData;
			HRESULT hr = exfatHandler.ExtractFile(mainStream, item, fileData);

			if (FAILED(hr))
			{
				opRes = NArchive::NExtract::NOperationResult::kDataError;
			}
			else
			{
				// Write data
				UInt32 bytesWritten = 0;
				HRESULT writeResult = realOutStream->Write(fileData.data(), static_cast<UInt32>(fileData.size()), &bytesWritten);

				if (FAILED(writeResult) || bytesWritten != fileData.size())
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

	// Directories have no stream
	if (item.isDirectory)
		return S_OK;

	if (item.size == 0)
	{
		*stream = new CEmptyInStream();
		(*stream)->AddRef();
		return S_OK;
	}

	// Extract file data
	std::vector<uint8_t> fileData;
	HRESULT hr = exfatHandler.ExtractFile(mainStream, item, fileData);
	if (FAILED(hr))
		return E_FAIL;

	CMyComPtr<CLimitedCachedInStream> limitedStream = new CLimitedCachedInStream;

	// Set the main stream
	limitedStream->SetStream(mainStream, 0);

	// Put all data in the cache
	auto& preload = limitedStream->Buffer;
	preload.Alloc(fileData.size());
	memcpy(preload, fileData.data(), fileData.size());

	limitedStream->SetCache(fileData.size(), 0);
	RINOK(limitedStream->InitAndSeek(0, fileData.size()));

	*stream = limitedStream.Detach();
	return S_OK;
}

static constexpr const Byte k_Signature[] = {
	0x45, 0x58, 0x46, 0x41, 0x54, 0x20, 0x20, 0x20  // "EXFAT   "
};

API_FUNC_IsArc IsArc_ExFAT(const Byte* p, size_t size)
{
	// Signature is at offset 3
	if (size < 11)  // 3 + 8 bytes
		return k_IsArc_Res_NEED_MORE;

	if (memcmp(p + 3, k_Signature, 8) != 0)
		return k_IsArc_Res_NO;

	return k_IsArc_Res_YES;
}

REGISTER_ARC_I(
	"ExFAT",
	"img exfat",
	0,
	0xC5,
	k_Signature,
	3,  // Signature offset
	NArcInfoFlags::kFindSignature,
	IsArc_ExFAT,
	0
)