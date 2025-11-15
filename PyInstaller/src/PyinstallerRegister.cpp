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
#include "PyInstallerHandler.h"
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
	PyInstallerHandler pyHandler;
	std::vector<PyInstallerHandler::ArchiveEntry> items;
	CMyComPtr<IInStream> mainStream;
	UInt64 totalSize = 0;
};

STDMETHODIMP CHandler::Open(IInStream* inStream, const UInt64* maxCheckStartPosition, IArchiveOpenCallback* callback) MY_NO_THROW_DECL_ONLY
{
	try
	{
		Close();

		// Get file size
		UInt64 fileSize = 0;
		RINOK(inStream->Seek(0, STREAM_SEEK_END, &fileSize));
		if (fileSize == 0)
			return S_FALSE;
		RINOK(inStream->Seek(0, STREAM_SEEK_SET, nullptr));

		// Get file name and verify .exe extension
		CMyComPtr<IArchiveOpenVolumeCallback> volumeCallback;
		RINOK(callback->QueryInterface(IID_IArchiveOpenVolumeCallback, (void**)&volumeCallback));
		if (!volumeCallback)
			return S_FALSE;

		UString name;
		{
			NWindows::NCOM::CPropVariant prop;
			RINOK(volumeCallback->GetProperty(kpidName, &prop));
			if (prop.vt != VT_BSTR)
				return S_FALSE;
			name = prop.bstrVal;
		}

		// Check for .exe extension
		int dotPos = name.ReverseFind_Dot();
		if (dotPos == -1)
			return S_FALSE;

		const UString ext = name.Ptr(dotPos + 1);
		if (!StringsAreEqualNoCase_Ascii(ext, "exe"))
			return S_FALSE;

		// Open with PyInstaller handler
		RINOK(pyHandler.Open(inStream, nullptr, callback));

		items = pyHandler.items;
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
	pyHandler.items.clear();
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
	kpidSize
};

static constexpr const PROPID kArcProps[] =
{
	kpidPhySize
};

IMP_IInArchive_Props
IMP_IInArchive_ArcProps

STDMETHODIMP CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT* value) MY_NO_THROW_DECL_ONLY
{
	COM_TRY_BEGIN
		NWindows::NCOM::CPropVariant prop;
	switch (propID)
	{
	case kpidPhySize:
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
		prop = item.name.c_str();
		break;

	case kpidSize:
		prop = static_cast<UInt64>(item.uncompressedSize);
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

STDMETHODIMP CHandler::GetStream(UInt32 index, ISequentialInStream** stream) MY_NO_THROW_DECL_ONLY
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

	CMyComPtr<CLimitedCachedInStream> limitedStream = new CLimitedCachedInStream;

	// Set the main stream
	limitedStream->SetStream(mainStream, 0);

	// Put all data in the cache
	auto& preload = limitedStream->Buffer;
	preload.Alloc(item.decompressedData.size());
	memcpy(preload, item.decompressedData.data(), item.decompressedData.size());

	limitedStream->SetCache(item.decompressedData.size(), 0);
	RINOK(limitedStream->InitAndSeek(0, item.decompressedData.size()));

	*stream = limitedStream.Detach();
	return S_OK;
}

static constexpr const Byte k_Signature[] = {
	'M', 'E', 'I', 0x0C, 0x0B, 0x0A, 0x0B, 0x0E  // PyInstaller magic
};

API_FUNC_IsArc IsArc_PyInstaller(const Byte* p, size_t size)
{
	if (size < 8)
		return k_IsArc_Res_NEED_MORE;

	// PyInstaller magic can be anywhere in the file, typically at the end
	// Just return YES if we have enough data to check
	return k_IsArc_Res_YES;
}

// Register the archive
REGISTER_ARC_I(
	"PyInstaller",
	"exe",
	0,
	0xAA,
	k_Signature,
	0,
	NArcInfoFlags::kFindSignature | NArcInfoFlags::kPureStartOpen,
	IsArc_PyInstaller,
	0
)