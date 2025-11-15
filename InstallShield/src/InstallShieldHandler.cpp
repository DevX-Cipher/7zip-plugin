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
#include "InstallShieldHandler.h"
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
	InstallShieldHandler handler;
	std::vector<InstallShieldHandler::FileInfo> items;
	CMyComPtr<IInStream> mainStream;
	UInt64 totalSize = 0;
};

STDMETHODIMP CHandler::Open(IInStream* inStream, const UInt64* maxCheckStartPosition, IArchiveOpenCallback* callback) MY_NO_THROW_DECL_ONLY
{
	try
	{
		Close();

		if (!callback || !inStream)
			return S_FALSE;

		// Try to open the InstallShield archive
		RINOK(handler.Open(inStream, nullptr, callback));

		// Copy items from handler
		items = handler.items;

		if (items.empty())
			return S_FALSE;

		mainStream = inStream;

		// Calculate total size
		UInt64 s = 0;
		for (size_t i = 0; i < items.size(); i++)
		{
			s += items[i].uncompressedSize;
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
	handler.items.clear();
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
	kpidPackSize
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
			// Convert UTF-8 std::string to UString
			const std::string& pathStr = item.path;

			// Convert UTF-8 to wide string
			int size_needed = MultiByteToWideChar(CP_UTF8, 0, pathStr.c_str(), -1, nullptr, 0);
			if (size_needed > 0)
			{
				std::wstring wpath(size_needed - 1, 0);
				MultiByteToWideChar(CP_UTF8, 0, pathStr.c_str(), -1, &wpath[0], size_needed - 1);

				UString widePath;
				for (wchar_t ch : wpath)
				{
					widePath += ch;
				}
				prop = widePath;
			}
			else
			{
				// Fallback to simple conversion
				UString widePath;
				for (size_t i = 0; i < pathStr.length(); i++)
				{
					widePath += (wchar_t)(unsigned char)pathStr[i];
				}
				prop = widePath;
			}
		}
	}
	break;

	case kpidSize:
		prop = static_cast<UInt64>(item.uncompressedSize);
		break;

	case kpidPackSize:
		prop = static_cast<UInt64>(item.compressedSize);
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

	// Calculate total size
	UInt64 totalExtractSize = 0;
	for (UInt32 i = 0; i < numItems; i++)
	{
		UInt32 index = allFilesMode ? i : indices[i];
		if (index < items.size())
			totalExtractSize += items[index].uncompressedSize;
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
		currentTotalSize += item.uncompressedSize;

		if (!testMode && !realOutStream)
			continue;

		RINOK(extractCallback->PrepareOperation(askMode));

		Int32 opRes = NArchive::NExtract::NOperationResult::kOK;

		// Write decompressed data
		if (!item.decompressedData.empty())
		{
			if (!testMode && realOutStream)
			{
				UInt32 processedSize = 0;
				HRESULT writeResult = realOutStream->Write(
					item.decompressedData.data(),
					static_cast<UInt32>(item.decompressedData.size()),
					&processedSize
				);

				if (FAILED(writeResult) || processedSize != item.decompressedData.size())
					opRes = NArchive::NExtract::NOperationResult::kDataError;
			}
		}
		else
		{
			// Empty file or no data
			if (item.uncompressedSize > 0)
				opRes = NArchive::NExtract::NOperationResult::kDataError;
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

	const auto& item = items[index];

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
	'I', 'n', 's', 't', 'a', 'l', 'l', 'S', 'h', 'i', 'e', 'l', 'd', 0x00  // InstallShield signature
};

API_FUNC_IsArc IsArc_InstallShield(const Byte* p, size_t size)
{
	if (size < 14)
		return k_IsArc_Res_NEED_MORE;

	// Check for "InstallShield" signature
	const Byte kSignatureIS[] = { 'I', 'n', 's', 't', 'a', 'l', 'l', 'S', 'h', 'i', 'e', 'l', 'd', 0x00 };
	const Byte kSignatureStream[] = { 'I', 'S', 'S', 'e', 't', 'u', 'p', 'S', 't', 'r', 'e', 'a', 'm', 0x00 };

	if (memcmp(p, kSignatureIS, 14) == 0)
		return k_IsArc_Res_YES;

	if (size >= 14 && memcmp(p, kSignatureStream, 14) == 0)
		return k_IsArc_Res_YES;

	return k_IsArc_Res_NO;
}

REGISTER_ARC_I(
	"InstallShield",
	"exe",
	0,
	0xAC,
	k_Signature,
	0,
	NArcInfoFlags::kFindSignature,
	IsArc_InstallShield,
	0
)