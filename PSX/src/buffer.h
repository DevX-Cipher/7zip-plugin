// Custom memory output stream for PKG
class CPKGMemoryOutStream : public ISequentialOutStream, public CMyUnknownImp
{
  Byte* _data;
  size_t _size;
  size_t _pos;

public:
  MY_UNKNOWN_IMP1(ISequentialOutStream)

    void Init(Byte* data, size_t size) {
    _data = data;
    _size = size;
    _pos = 0;
  }

  STDMETHOD(Write)(const void* data, UInt32 size, UInt32* processedSize) {
    if (_pos + size > _size)
      return E_FAIL;
    memcpy(_data + _pos, data, size);
    _pos += size;
    if (processedSize)
      *processedSize = size;
    return S_OK;
  }
};

// Custom memory input stream for PKG
class CPKGBufInStream : public IInStream, public CMyUnknownImp
{
  const Byte* _data;
  size_t _size;
  size_t _pos;

public:
  MY_UNKNOWN_IMP2(IInStream, ISequentialInStream)

    void Init(const Byte* data, size_t size) {
    _data = data;
    _size = size;
    _pos = 0;
  }

  STDMETHOD(Read)(void* data, UInt32 size, UInt32* processedSize) {
    size_t remain = _size - _pos;
    if (size > remain)
      size = (UInt32)remain;
    memcpy(data, _data + _pos, size);
    _pos += size;
    if (processedSize)
      *processedSize = size;
    return S_OK;
  }

  STDMETHOD(Seek)(Int64 offset, UInt32 seekOrigin, UInt64* newPosition) {
    switch (seekOrigin) {
    case STREAM_SEEK_SET: _pos = (size_t)offset; break;
    case STREAM_SEEK_CUR: _pos += (size_t)offset; break;
    case STREAM_SEEK_END: _pos = _size + (size_t)offset; break;
    default: return STG_E_INVALIDFUNCTION;
    }
    if (newPosition)
      *newPosition = _pos;
    return S_OK;
  }
};