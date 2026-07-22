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
#include "UpxUnpackHandler.h"


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
	UpxUnpackHandler upxHandler;
	CMyComPtr<IInStream> mainStream;
	UInt64 totalSize = 0;
};

STDMETHODIMP CHandler::Open(IInStream* inStream, const UInt64* maxCheckStartPosition, IArchiveOpenCallback* callback) MY_NO_THROW_DECL_ONLY
{
	try
	{
		Close();

		UInt64 checkLen = 0;
		RINOK(inStream->Seek(0, STREAM_SEEK_END, &checkLen));
		RINOK(inStream->Seek(0, STREAM_SEEK_SET, nullptr));
		if (checkLen < 64)
		{
			return S_FALSE;
		}

		RINOK(inStream->Seek(0, STREAM_SEEK_SET, nullptr));

		std::string baseNameNoExt = "unpacked";
		if (callback)
		{
			CMyComPtr<IArchiveOpenVolumeCallback> volumeCallback;
			callback->QueryInterface(IID_IArchiveOpenVolumeCallback, (void**)&volumeCallback);
			if (volumeCallback)
			{
				NWindows::NCOM::CPropVariant prop;
				if (volumeCallback->GetProperty(kpidName, &prop) == S_OK && prop.vt == VT_BSTR)
				{
					std::wstring fullName(prop.bstrVal, ::SysStringLen(prop.bstrVal));

					size_t slashPos = fullName.find_last_of(L"\\/");
					std::wstring fileOnly = (slashPos == std::wstring::npos)
						? fullName
						: fullName.substr(slashPos + 1);

					size_t dotPos = fileOnly.find_last_of(L'.');
					std::wstring nameNoExtW = (dotPos == std::wstring::npos)
						? fileOnly
						: fileOnly.substr(0, dotPos);

					baseNameNoExt.assign(nameNoExtW.begin(), nameNoExtW.end());
				}
			}
		}

		if (!upxHandler.Open(inStream, baseNameNoExt))
		{
			return S_FALSE;
		}

		if (upxHandler.items.empty())
		{
			return S_FALSE;
		}

		mainStream = inStream;
		UInt64 s = 0;
		for (const auto& item : upxHandler.items)
			s += item.data.size();
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
	upxHandler.items.clear();
	totalSize = 0;
	return S_OK;
}

STDMETHODIMP CHandler::GetNumberOfItems(UInt32* numItems) MY_NO_THROW_DECL_ONLY
{
	*numItems = static_cast<UInt32>(upxHandler.items.size());
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
		if (index >= upxHandler.items.size())
			return E_INVALIDARG;

	const auto& item = upxHandler.items[index];
	NWindows::NCOM::CPropVariant prop;

	switch (propID)
	{
	case kpidPath:
		prop = GetUnicodeString(item.displayName.c_str());
		break;

	case kpidSize:
		prop = static_cast<UInt64>(item.data.size());
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
		numItems = static_cast<UInt32>(upxHandler.items.size());

	UInt64 totalExtractSize = 0;
	if (allFilesMode)
	{
		totalExtractSize = totalSize;
	}
	else
	{
		for (UInt32 i = 0; i < numItems; i++)
			totalExtractSize += upxHandler.items[indices[i]].data.size();
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

		const auto& item = upxHandler.items[index];
		currentTotalSize += item.data.size();

		if (!testMode && !realOutStream)
			continue;

		RINOK(extractCallback->PrepareOperation(askMode));

		Int32 opRes = item.ok
			? NArchive::NExtract::NOperationResult::kOK
			: NArchive::NExtract::NOperationResult::kDataError;

		if (!item.data.empty() && realOutStream)
		{
			HRESULT writeResult = realOutStream->Write(
				item.data.data(),
				static_cast<UInt32>(item.data.size()),
				nullptr
			);
			if (writeResult != S_OK)
				opRes = NArchive::NExtract::NOperationResult::kDataError;
		}
		else if (realOutStream)
		{
			realOutStream->Write("", 0, nullptr);
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

	if (index >= upxHandler.items.size())
		return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

	const auto& item = upxHandler.items[index];

	if (item.data.empty())
	{
		*stream = new CEmptyInStream();
		(*stream)->AddRef();
		return S_OK;
	}

	CMyComPtr<CLimitedCachedInStream> limitedStream = new CLimitedCachedInStream;
	limitedStream->SetStream(mainStream, 0);

	auto& preload = limitedStream->Buffer;
	preload.Alloc(item.data.size());
	memcpy(preload, item.data.data(), item.data.size());

	limitedStream->SetCache(item.data.size(), 0);
	RINOK(limitedStream->InitAndSeek(0, item.data.size()));

	*stream = limitedStream.Detach();
	return S_OK;
}

static constexpr const Byte k_Signature[] = {
	0x77, 0x77, 0x67, 0x54, 0x29, 0x50
};

API_FUNC_IsArc IsArc_UPX(const Byte* p, size_t size)
{
	if (size < 6)
		return k_IsArc_Res_NEED_MORE;

	const Byte kSignature[] = { 0x77, 0x77, 0x67, 0x54, 0x29, 0x50 };
	if (memcmp(p, kSignature, 6) != 0)
		return k_IsArc_Res_NO;

	return k_IsArc_Res_YES;
}

REGISTER_ARC_I(
	"EXE", "exe", 0, 0xAB,
	k_Signature,
	0,
	NArcInfoFlags::kFindSignature | NArcInfoFlags::kPureStartOpen,
	IsArc_UPX,
	0
)