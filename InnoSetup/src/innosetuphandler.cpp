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
#include "InnoSetupHandler.h"
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
	InnoSetupInstallerHandler innoHandler;
	CMyComPtr<IInStream> mainStream;
	UInt64 totalSize = 0;
};

STDMETHODIMP CHandler::Open(IInStream* inStream, const UInt64* maxCheckStartPosition, IArchiveOpenCallback* callback) MY_NO_THROW_DECL_ONLY
{
	try
	{
		Close();

		RINOK(innoHandler.Open(inStream, maxCheckStartPosition, callback));

		mainStream = inStream;

		// Calculate total size
		UInt64 s = 0;
		for (size_t i = 0; i < innoHandler.items.size(); i++)
		{
			s += innoHandler.items[i].uncompressedSize;
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
	innoHandler.Close();
	totalSize = 0;
	return S_OK;
}

STDMETHODIMP CHandler::GetNumberOfItems(UInt32* numItems) MY_NO_THROW_DECL_ONLY
{
	*numItems = static_cast<UInt32>(innoHandler.items.size());
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
		// Could calculate from InnoSetup header if needed
		break;
	}
	prop.Detach(value);
	return S_OK;
	COM_TRY_END
}

STDMETHODIMP CHandler::GetProperty(UInt32 index, PROPID propID, PROPVARIANT* value) MY_NO_THROW_DECL_ONLY
{
	COM_TRY_BEGIN
		if (index >= innoHandler.items.size())
			return E_INVALIDARG;

	const auto& item = innoHandler.items[index];
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
		numItems = static_cast<UInt32>(innoHandler.items.size());

	UInt64 totalExtractSize = 0;
	if (allFilesMode)
	{
		totalExtractSize = totalSize;
	}
	else
	{
		for (UInt32 i = 0; i < numItems; i++)
			totalExtractSize += innoHandler.items[indices[i]].uncompressedSize;
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

		const auto& item = innoHandler.items[index];
		currentTotalSize += item.uncompressedSize;

		if (!testMode && !realOutStream)
			continue;

		RINOK(extractCallback->PrepareOperation(askMode));

		if (item.uncompressedSize == 0)
		{
			if (realOutStream)
				realOutStream->Write("", 0, nullptr);
			RINOK(extractCallback->SetOperationResult(NArchive::NExtract::NOperationResult::kOK));
			continue;
		}

		Int32 opRes = NArchive::NExtract::NOperationResult::kOK;

		// Decompress on demand (cached per-chunk) and write it out
		const std::vector<uint8_t>* pData = innoHandler.GetFileData(index);

		if (realOutStream)
		{
			if (!pData)
			{
				opRes = NArchive::NExtract::NOperationResult::kDataError;
			}
			else
			{
				HRESULT writeResult = realOutStream->Write(
					pData->data(),
					static_cast<UInt32>(pData->size()),
					nullptr
				);

				if (writeResult != S_OK)
					opRes = NArchive::NExtract::NOperationResult::kDataError;
			}
		}

		realOutStream.Release();
		RINOK(extractCallback->SetOperationResult(opRes));
	}

	return S_OK;
	COM_TRY_END
}

STDMETHODIMP CHandler::GetStream(UInt32 index, ISequentialInStream** stream)
{
	*stream = nullptr;

	if (index >= innoHandler.items.size())
		return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

	const auto& item = innoHandler.items[index];

	if (item.uncompressedSize == 0)
	{
		*stream = new CEmptyInStream();
		(*stream)->AddRef();
		return S_OK;
	}

	const std::vector<uint8_t>* pData = innoHandler.GetFileData(index);
	if (!pData || pData->empty())
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
	preload.Alloc(pData->size());
	memcpy(preload, pData->data(), pData->size());

	limitedStream->SetCache(pData->size(), 0);
	RINOK(limitedStream->InitAndSeek(0, pData->size()));

	*stream = limitedStream.Detach();
	return S_OK;
}


// Unlike ClickTeam's fixed 6-byte magic at a known offset, InnoSetup's
// "Inno Setup Setup Data" / "Inno Setup: Setup Data" signature string sits
// at a variable offset inside the host PE (it can be MBs in). IsArc only
// ever sees a small bounded prefix of the file, so it cannot reliably do
// this scan itself -- it defers to Open(), which already performs the real
// signature search (InnoSetupInstallerHandler::Analyse) across the whole
// stream and correctly returns S_FALSE if nothing is found.
API_FUNC_IsArc IsArc_InnoSetup(const Byte* p, size_t size)
{
	(void)p;

	if (size < 64)
		return k_IsArc_Res_NEED_MORE;

	return k_IsArc_Res_YES;
}

// REGISTER_ARC_I's signature slot expects a real named Byte array (like
// ClickTeam's k_Signature) so its internal ARRAY_SIZE-style macro can
// resolve the array type -- a bare brace-init { 0 } does not decay
// correctly there. This format has no fixed-offset signature to match on
// (see IsArc_InnoSetup above), so this is just a 1-byte placeholder; it is
// never used for matching since IsArc_InnoSetup ignores `p` entirely.
static constexpr const Byte k_Signature[] = { 0 };

REGISTER_ARC_I(
	"InnoSetup", "exe", 0, 0xAC,
	k_Signature,
	0,
	0,
	IsArc_InnoSetup,
	0
)