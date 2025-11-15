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
#include "RPAHandler.h"
#include <cwchar>

class CHandler :
	public IInArchive,
	public IInArchiveGetStream,
	public CMyUnknownImp
{
public:
	CHandler() : batchLoadEnabled(false), hasArchiveCache(false) {}

	~CHandler()
	{
		if (batchLoadEnabled)
			rpaHandler.CloseBatchLoad();
		archiveDataCache.clear();
	}

	MY_UNKNOWN_IMP2(IInArchive, IInArchiveGetStream)
		INTERFACE_IInArchive(override)

		STDMETHOD(GetStream)(UInt32 index, ISequentialInStream** stream) override;

private:
	RPAArchiveHandler rpaHandler;
	std::vector<std::pair<std::string, RPAArchiveHandler::ArchiveIndex>> itemsList;
	CMyComPtr<IInStream> mainStream;
	UInt64 totalSize = 0;
	double archiveVersion = 0.0;
	bool batchLoadEnabled;
	bool hasArchiveCache;
	std::vector<uint8_t> archiveDataCache;

	bool CreateMemoryCache(IInStream* stream, UInt64 maxSize);
};

bool CHandler::CreateMemoryCache(IInStream* stream, UInt64 maxSize)
{
	UInt64 streamSize = 0;
	if (FAILED(stream->Seek(0, STREAM_SEEK_END, &streamSize)))
		return false;

	if (streamSize > maxSize || streamSize == 0)
		return false;

	try
	{
		archiveDataCache.resize(static_cast<size_t>(streamSize));
	}
	catch (...)
	{
		return false;
	}

	if (FAILED(stream->Seek(0, STREAM_SEEK_SET, nullptr)))
	{
		archiveDataCache.clear();
		return false;
	}

	UInt32 bytesRead = 0;
	UInt64 totalRead = 0;
	const UInt32 chunkSize = 16 * 1024 * 1024;

	while (totalRead < streamSize)
	{
		UInt32 toRead = static_cast<UInt32>(std::min<UInt64>(chunkSize, streamSize - totalRead));
		HRESULT hr = stream->Read(&archiveDataCache[static_cast<size_t>(totalRead)], toRead, &bytesRead);

		if (FAILED(hr) || bytesRead == 0)
		{
			archiveDataCache.clear();
			return false;
		}
		totalRead += bytesRead;
	}

	hasArchiveCache = true;
	return true;
}

STDMETHODIMP CHandler::Open(IInStream* inStream, const UInt64* maxCheckStartPosition, IArchiveOpenCallback* callback) MY_NO_THROW_DECL_ONLY
{
	try
	{
		Close();

		// Check RPA signature
		const size_t maxHeaderSize = 256;
		Byte header[maxHeaderSize];
		UInt32 bytesRead = 0;

		RINOK(inStream->Seek(0, STREAM_SEEK_SET, nullptr));
		RINOK(inStream->Read(header, maxHeaderSize, &bytesRead));

		if (bytesRead < 8)
			return S_FALSE;

		// Check for RPA signatures
		const Byte kSignatureRPA32[] = { 'R', 'P', 'A', '-', '3', '.', '2', ' ' };
		const Byte kSignatureRPA3[] = { 'R', 'P', 'A', '-', '3', '.', '0', ' ' };
		const Byte kSignatureRPA2[] = { 'R', 'P', 'A', '-', '2', '.', '0', ' ' };

		bool isRPA = false;
		if (memcmp(header, kSignatureRPA32, sizeof(kSignatureRPA32)) == 0 ||
			memcmp(header, kSignatureRPA3, sizeof(kSignatureRPA3)) == 0 ||
			memcmp(header, kSignatureRPA2, sizeof(kSignatureRPA2)) == 0)
		{
			isRPA = true;
		}

		if (!isRPA)
			return S_FALSE;

		// Reset stream
		RINOK(inStream->Seek(0, STREAM_SEEK_SET, nullptr));

		// Try to create memory cache for faster access
		CreateMemoryCache(inStream, 500 * 1024 * 1024);

		if (hasArchiveCache)
			batchLoadEnabled = true;

		// Open with RPA handler
		RINOK(rpaHandler.Open(inStream, nullptr, callback));

		mainStream = inStream;

		// Copy items list
		itemsList.clear();
		itemsList.reserve(rpaHandler.items.size());
		for (const auto& item : rpaHandler.items)
		{
			itemsList.push_back(item);
		}

		archiveVersion = rpaHandler.GetArchiveVersion();

		// Calculate total size
		UInt64 s = 0;
		for (size_t i = 0; i < itemsList.size(); i++)
		{
			s += itemsList[i].second.length;
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
	itemsList.clear();
	rpaHandler.items.clear();
	archiveDataCache.clear();
	archiveDataCache.shrink_to_fit();
	hasArchiveCache = false;

	if (batchLoadEnabled)
	{
		rpaHandler.CloseBatchLoad();
		batchLoadEnabled = false;
	}

	totalSize = 0;
	archiveVersion = 0.0;
	return S_OK;
}

STDMETHODIMP CHandler::GetNumberOfItems(UInt32* numItems) MY_NO_THROW_DECL_ONLY
{
	*numItems = static_cast<UInt32>(itemsList.size());
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
	kpidSubType,
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
	case kpidSubType:
	{
		double ver = rpaHandler.GetArchiveVersion();
		const wchar_t* versionStr = L"Unknown";

		if (ver == 1.0)
			versionStr = L"RPA-1.0";
		else if (ver == 2.0)
			versionStr = L"RPA-2.0";
		else if (ver == 3.0)
			versionStr = L"RPA-3.0";
		else if (ver == 3.2)
			versionStr = L"RPA-3.2";

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

STDMETHODIMP CHandler::GetProperty(UInt32 index, PROPID propID, PROPVARIANT* value) MY_NO_THROW_DECL_ONLY
{
	COM_TRY_BEGIN
		if (index >= itemsList.size())
			return E_INVALIDARG;

	const auto& item = itemsList[index];
	const std::string& fileName = item.first;
	const auto& fileInfo = item.second;
	NWindows::NCOM::CPropVariant prop;

	switch (propID)
	{
	case kpidPath:
	{
		if (fileName.empty())
		{
			prop = L"unnamed.bin";
		}
		else
		{
			UString widePath;
			for (size_t i = 0; i < fileName.length(); i++)
			{
				widePath += (wchar_t)(unsigned char)fileName[i];
			}
			prop = widePath;
		}
	}
	break;

	case kpidSize:
		prop = static_cast<UInt64>(fileInfo.length);
		break;

	case kpidPackSize:
	{
		UInt64 packedSize = 0;
		for (const auto& tuple : fileInfo.tuples)
		{
			packedSize += tuple.second.length;
		}
		prop = packedSize;
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
		numItems = static_cast<UInt32>(itemsList.size());

	if (numItems == 0)
		return S_OK;

	// Calculate total size
	UInt64 totalExtractSize = 0;
	for (UInt32 i = 0; i < numItems; i++)
	{
		UInt32 index = allFilesMode ? i : indices[i];
		if (index < itemsList.size())
			totalExtractSize += itemsList[index].second.length;
	}

	RINOK(extractCallback->SetTotal(totalExtractSize));

	CMyComPtr<CLocalProgress> progress = new CLocalProgress;
	progress->Init(extractCallback, false);

	const Int32 askMode = testMode ? NArchive::NExtract::NAskMode::kTest : NArchive::NExtract::NAskMode::kExtract;

	// Use batch extraction for multiple files with cache
	if (hasArchiveCache && numItems > 5)
	{
		UInt64 currentSize = 0;
		for (UInt32 i = 0; i < numItems; i++)
		{
			UInt32 index = allFilesMode ? i : indices[i];
			if (index >= itemsList.size())
				continue;

			const auto& item = itemsList[index];
			const auto& fileInfo = item.second;

			progress->InSize = progress->OutSize = currentSize;
			RINOK(progress->SetCur());

			CMyComPtr<ISequentialOutStream> realOutStream;
			RINOK(extractCallback->GetStream(index, &realOutStream, askMode));

			currentSize += fileInfo.length;

			if (!testMode && !realOutStream)
				continue;

			RINOK(extractCallback->PrepareOperation(askMode));

			// Extract from cache
			std::vector<uint8_t> fileData;
			fileData.reserve(fileInfo.length);

			for (const auto& tuplePair : fileInfo.tuples)
			{
				const auto& tuple = tuplePair.second;
				fileData.insert(fileData.end(), tuple.prefix.begin(), tuple.prefix.end());

				size_t dataLength = tuple.length - tuple.prefix.size();
				if (dataLength > 0 && tuple.offset + dataLength <= archiveDataCache.size())
				{
					const uint8_t* srcData = &archiveDataCache[static_cast<size_t>(tuple.offset)];
					fileData.insert(fileData.end(), srcData, srcData + dataLength);
				}
			}

			Int32 opRes = NArchive::NExtract::NOperationResult::kOK;

			if (!testMode && realOutStream)
			{
				UInt32 written = 0;
				HRESULT writeResult = realOutStream->Write(fileData.data(), static_cast<UInt32>(fileData.size()), &written);
				if (FAILED(writeResult) || written != fileData.size())
					opRes = NArchive::NExtract::NOperationResult::kDataError;
			}

			realOutStream.Release();
			RINOK(extractCallback->SetOperationResult(opRes));
		}
		return S_OK;
	}

	// Standard sequential extraction
	UInt64 currentTotalSize = 0;
	for (UInt32 i = 0; i < numItems; i++)
	{
		UInt32 index = allFilesMode ? i : indices[i];
		if (index >= itemsList.size())
			continue;

		const auto& item = itemsList[index];
		const std::string& fileName = item.first;
		const auto& fileInfo = item.second;

		progress->InSize = progress->OutSize = currentTotalSize;
		RINOK(progress->SetCur());

		CMyComPtr<ISequentialOutStream> realOutStream;
		RINOK(extractCallback->GetStream(index, &realOutStream, askMode));

		currentTotalSize += fileInfo.length;

		if (!testMode && !realOutStream)
			continue;

		RINOK(extractCallback->PrepareOperation(askMode));

		Int32 opRes = NArchive::NExtract::NOperationResult::kOK;
		std::vector<uint8_t> fileData;

		// Extract file data
		HRESULT extractResult;
		if (hasArchiveCache)
		{
			fileData.reserve(fileInfo.length);
			for (const auto& tuplePair : fileInfo.tuples)
			{
				const auto& tuple = tuplePair.second;
				fileData.insert(fileData.end(), tuple.prefix.begin(), tuple.prefix.end());

				size_t dataLength = tuple.length - tuple.prefix.size();
				if (dataLength > 0 && tuple.offset + dataLength <= archiveDataCache.size())
				{
					const uint8_t* srcData = &archiveDataCache[static_cast<size_t>(tuple.offset)];
					fileData.insert(fileData.end(), srcData, srcData + dataLength);
				}
			}
			extractResult = S_OK;
		}
		else
		{
			extractResult = rpaHandler.ExtractFile(mainStream, fileName, fileData);
		}

		if (FAILED(extractResult))
		{
			opRes = NArchive::NExtract::NOperationResult::kDataError;
		}
		else if (!testMode && realOutStream)
		{
			UInt32 written = 0;
			HRESULT writeResult = realOutStream->Write(fileData.data(), static_cast<UInt32>(fileData.size()), &written);
			if (FAILED(writeResult) || written != fileData.size())
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

	if (index >= itemsList.size())
		return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

	const auto& item = itemsList[index];
	const std::string& fileName = item.first;
	const auto& fileInfo = item.second;

	if (fileInfo.length == 0)
	{
		*stream = new CEmptyInStream();
		(*stream)->AddRef();
		return S_OK;
	}

	std::vector<uint8_t> fileData;
	HRESULT result = S_OK;

	// Extract file data
	if (hasArchiveCache)
	{
		fileData.reserve(fileInfo.length);
		for (const auto& tuplePair : fileInfo.tuples)
		{
			const auto& tuple = tuplePair.second;
			fileData.insert(fileData.end(), tuple.prefix.begin(), tuple.prefix.end());

			size_t dataLength = tuple.length - tuple.prefix.size();
			if (dataLength > 0 && tuple.offset + dataLength <= archiveDataCache.size())
			{
				const uint8_t* srcData = &archiveDataCache[static_cast<size_t>(tuple.offset)];
				fileData.insert(fileData.end(), srcData, srcData + dataLength);
			}
		}
	}
	else
	{
		if (!mainStream)
			return E_FAIL;
		result = rpaHandler.ExtractFile(mainStream, fileName, fileData);
	}

	if (FAILED(result))
		return E_FAIL;

	CMyComPtr<CLimitedCachedInStream> limitedStream = new CLimitedCachedInStream;

	limitedStream->SetStream(mainStream, 0);

	auto& preload = limitedStream->Buffer;
	preload.Alloc(fileData.size());
	memcpy(preload, fileData.data(), fileData.size());

	limitedStream->SetCache(fileData.size(), 0);
	RINOK(limitedStream->InitAndSeek(0, fileData.size()));

	*stream = limitedStream.Detach();
	return S_OK;
}

static constexpr const Byte k_Signature[] = {
	'R', 'P', 'A', '-', '3', '.', '0', ' '  // RPA-3.0 signature
};

API_FUNC_IsArc IsArc_RPA(const Byte* p, size_t size)
{
	if (size < 8)
		return k_IsArc_Res_NEED_MORE;

	// Check for any RPA version signature
	if (memcmp(p, "RPA-", 4) != 0)
		return k_IsArc_Res_NO;

	// Check version format: RPA-X.X where X are digits
	if (size >= 8 && p[4] >= '1' && p[4] <= '9' && p[5] == '.' && p[6] >= '0' && p[6] <= '9')
		return k_IsArc_Res_YES;

	return k_IsArc_Res_NO;
}

REGISTER_ARC_I(
	"RPA",
	"rpa rpi",
	0,
	0xC9,
	k_Signature,
	0,
	NArcInfoFlags::kFindSignature,
	IsArc_RPA,
	0
)