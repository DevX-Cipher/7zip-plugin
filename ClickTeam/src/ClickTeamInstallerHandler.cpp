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
#include "ClickTeamInstallerHandler.h"
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
	ClickTeamInstallerHandler clickHandler;
	std::vector<ClickTeamInstallerHandler::FileInfo> items;
	CMyComPtr<IInStream> mainStream;
	UInt64 totalSize = 0;
};

STDMETHODIMP CHandler::Open(IInStream* inStream, const UInt64* maxCheckStartPosition, IArchiveOpenCallback* callback) MY_NO_THROW_DECL_ONLY
{
	try
	{
		Close();

		// Verify signature
		const size_t magicSize = 6; // sizeof(kSignature)
		Byte magic[magicSize];
		RINOK(inStream->Read(magic, magicSize, nullptr));

		const Byte kSignature[] = { 0x77, 0x77, 0x67, 0x54, 0x29, 0x48 };
		if (memcmp(magic, kSignature, magicSize) != 0)
			return S_FALSE;

		// Open with ClickTeam handler
		RINOK(clickHandler.Open(inStream, nullptr, callback));

		items = clickHandler.items;
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
	clickHandler.items.clear();
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
	kpidTotalPhySize,
	kpidHeadersSize
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
	case kpidHeadersSize:
		// Could calculate from ClickTeam header if needed
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

	UInt64 totalExtractSize = 0;
	if (allFilesMode)
	{
		totalExtractSize = totalSize;
	}
	else
	{
		for (UInt32 i = 0; i < numItems; i++)
			totalExtractSize += items[indices[i]].uncompressedSize;
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

		const auto& item = items[index];
		currentTotalSize += item.uncompressedSize;

		if (!testMode && !realOutStream)
			continue;

		RINOK(extractCallback->PrepareOperation(askMode));

		if (item.uncompressedSize == 0)
		{
			realOutStream->Write("", 0, nullptr);
			RINOK(extractCallback->SetOperationResult(NArchive::NExtract::NOperationResult::kOK));
			continue;
		}

		Int32 opRes = NArchive::NExtract::NOperationResult::kOK;

		// Write decompressed data
		HRESULT writeResult = realOutStream->Write(
			item.decompressedData.data(),
			static_cast<UInt32>(item.decompressedData.size()),
			nullptr
		);

		if (writeResult != S_OK)
			opRes = NArchive::NExtract::NOperationResult::kDataError;

		realOutStream.Release();
		RINOK(extractCallback->SetOperationResult(opRes));
	}

	return S_OK;
	COM_TRY_END
}

STDMETHODIMP CHandler::GetStream(UInt32 index, ISequentialInStream** stream)
{
	*stream = nullptr;

	if (index >= items.size())
		return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

	const auto& item = items[index];

	if (!item.decompressedData.size())
	{
		*stream = new CEmptyInStream();
		(*stream)->AddRef();
		return S_OK;
	}

	// we can use CLimitedCachedInStream with everything cached
	CMyComPtr<CLimitedCachedInStream> limitedStream = new CLimitedCachedInStream;

	// Set the main stream (even though we won't read from it since everything is cached)
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
	0x77, 0x77, 0x67, 0x54, 0x29, 0x48  // ClickTeam signature (no size prefix)
};

API_FUNC_IsArc IsArc_ClickTeam(const Byte* p, size_t size)
{
	if (size < 6)
		return k_IsArc_Res_NEED_MORE;

	const Byte kSignature[] = { 0x77, 0x77, 0x67, 0x54, 0x29, 0x48 };
	if (memcmp(p, kSignature, 6) != 0)
		return k_IsArc_Res_NO;

	return k_IsArc_Res_YES;
}

REGISTER_ARC_I(
	"ClickTeam", "exe", 0, 0xAB,
	k_Signature,
	0,
	NArcInfoFlags::kFindSignature | NArcInfoFlags::kPureStartOpen,
	IsArc_ClickTeam,
	0
)