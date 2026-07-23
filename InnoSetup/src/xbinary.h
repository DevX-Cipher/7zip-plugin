#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace xbinary {

  struct PDSTRUCT {
    bool bIsStopped = false;
  };

  inline bool isPdStructNotCanceled(PDSTRUCT* pPdStruct)
  {
    return !(pPdStruct && pPdStruct->bIsStopped);
  }

  enum class FPART_PROP {
    ORIGINALNAME,
    UNCOMPRESSEDSIZE,
    COMPRESSEDSIZE,
    RESULTCRC,
    ISFOLDER,
    STREAMOFFSET,
    STREAMSIZE,
    HANDLEMETHOD,
  };

  enum class HANDLE_METHOD {
    STORE,
    LZMA,
    LZMA2,
  };

  class PropValue {
  public:
    enum class Type { NONE, INT64, STRING, BOOL, UINT32, HANDLE_METHOD_T };

    PropValue() : m_type(Type::NONE), m_i64(0), m_b(false), m_u32(0) {}
    PropValue(int64_t v) : m_type(Type::INT64), m_i64(v), m_b(false), m_u32(0) {}
    PropValue(const std::string& v) : m_type(Type::STRING), m_i64(0), m_s(v), m_b(false), m_u32(0) {}
    PropValue(bool v) : m_type(Type::BOOL), m_i64(0), m_b(v), m_u32(0) {}
    PropValue(uint32_t v) : m_type(Type::UINT32), m_i64(0), m_b(false), m_u32(v) {}
    PropValue(HANDLE_METHOD v) : m_type(Type::HANDLE_METHOD_T), m_i64(0), m_b(false), m_u32(0), m_method(v) {}

    int64_t toLongLong() const { return m_type == Type::INT64 ? m_i64 : (m_type == Type::UINT32 ? (int64_t)m_u32 : 0); }
    std::string toString() const { return m_type == Type::STRING ? m_s : std::string(); }
    bool toBool() const { return m_type == Type::BOOL ? m_b : false; }
    HANDLE_METHOD toHandleMethod() const { return m_method; }

  private:
    Type m_type;
    int64_t m_i64;
    std::string m_s;
    bool m_b;
    uint32_t m_u32;
    HANDLE_METHOD m_method = HANDLE_METHOD::STORE;
  };

  using PropertyMap = std::map<FPART_PROP, PropValue>;

  struct ARCHIVERECORD {
    int64_t nStreamOffset = 0;
    int64_t nStreamSize = 0;
    PropertyMap mapProperties;
  };

  struct DATAPROCESS_STATE {
    PropertyMap mapProperties;
    std::istream* pDeviceInput = nullptr;
    std::ostream* pDeviceOutput = nullptr;
    int64_t nInputOffset = 0;
    int64_t nInputLimit = 0;
    int64_t nProcessedOffset = 0;
    int64_t nProcessedLimit = -1;
  };

  enum class UNPACK_PROP { NONE };

  struct UNPACK_STATE {
    void* pContext = nullptr;
    int32_t nCurrentIndex = 0;
    int32_t nNumberOfRecords = 0;
  };

  class XBinaryLite {
  public:
    explicit XBinaryLite(std::istream* pDevice) : m_pDevice(pDevice) {}
    virtual ~XBinaryLite() = default;

    std::istream* getDevice() const { return m_pDevice; }

    int64_t getSize() const
    {
      if (!m_pDevice) return 0;
      auto oldPos = m_pDevice->tellg();
      m_pDevice->seekg(0, std::ios::end);
      int64_t nSize = (int64_t)m_pDevice->tellg();
      m_pDevice->seekg(oldPos);
      return nSize;
    }

    std::vector<char> read_array(int64_t nOffset, int64_t nSize) const
    {
      std::vector<char> result;
      if (!m_pDevice || nSize <= 0) return result;
      result.resize((size_t)nSize);
      m_pDevice->seekg(nOffset);
      m_pDevice->read(result.data(), nSize);
      std::streamsize nRead = m_pDevice->gcount();
      if (nRead < (std::streamsize)nSize) {
        result.resize((size_t)nRead);
      }
      return result;
    }

    std::vector<char> read_array_process(int64_t nOffset, int64_t nSize, PDSTRUCT* pPdStruct) const
    {
      (void)pPdStruct;
      return read_array(nOffset, nSize);
    }

    uint8_t read_uint8(int64_t nOffset) const
    {
      auto data = read_array(nOffset, 1);
      if (data.empty()) return 0;
      return (uint8_t)data[0];
    }

    uint16_t read_uint16(int64_t nOffset, bool bBigEndian) const
    {
      auto data = read_array(nOffset, 2);
      if (data.size() < 2) return 0;
      uint16_t v = (uint8_t)data[0] | ((uint8_t)data[1] << 8);
      if (bBigEndian) v = (uint16_t)(((v & 0xFF) << 8) | ((v >> 8) & 0xFF));
      return v;
    }

    uint32_t read_uint32(int64_t nOffset, bool bBigEndian) const
    {
      auto data = read_array(nOffset, 4);
      if (data.size() < 4) return 0;
      uint32_t v = (uint8_t)data[0] | ((uint32_t)(uint8_t)data[1] << 8) | ((uint32_t)(uint8_t)data[2] << 16) |
        ((uint32_t)(uint8_t)data[3] << 24);
      if (bBigEndian) {
        v = ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) | ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
      }
      return v;
    }

    uint64_t read_uint64(int64_t nOffset, bool bBigEndian) const
    {
      auto data = read_array(nOffset, 8);
      if (data.size() < 8) return 0;
      uint64_t v = 0;
      for (int i = 0; i < 8; i++) {
        v |= ((uint64_t)(uint8_t)data[i]) << (8 * i);
      }
      if (bBigEndian) {
        uint64_t r = 0;
        for (int i = 0; i < 8; i++) {
          r = (r << 8) | ((v >> (8 * i)) & 0xFF);
        }
        v = r;
      }
      return v;
    }

    int64_t find_utf8String(int64_t nOffset, int64_t nSize, const std::string& sString, PDSTRUCT* pPdStruct) const
    {
      (void)pPdStruct;
      if (!m_pDevice || sString.empty()) return -1;

      const int64_t nChunkSize = 1 << 20;  
      int64_t nOverlap = (int64_t)sString.size() - 1;
      int64_t nPos = nOffset;

      while (nPos < nOffset + nSize) {
        int64_t nRemaining = (nOffset + nSize) - nPos;
        int64_t nReadSize = (nChunkSize < nRemaining) ? nChunkSize : nRemaining;

        auto data = read_array(nPos, nReadSize);
        if (data.empty()) break;

        auto it = std::search(data.begin(), data.end(),
          sString.begin(), sString.end());
        if (it != data.end()) {
          return nPos + std::distance(data.begin(), it);
        }

        if ((int64_t)data.size() < nReadSize) break;  // EOF

        nPos += nReadSize - nOverlap;
        if (nOverlap <= 0) nPos += 1;
      }

      return -1;
    }

    int64_t find_array(int64_t nOffset, int64_t nSize, const char* pData, int64_t nDataSize, PDSTRUCT* pPdStruct) const
    {
      (void)pPdStruct;
      if (!m_pDevice || nDataSize <= 0) return -1;

      const int64_t nChunkSize = 1 << 20;
      int64_t nOverlap = nDataSize - 1;
      int64_t nPos = nOffset;

      while (nPos < nOffset + nSize) {
        int64_t nRemaining = (nOffset + nSize) - nPos;
        int64_t nReadSize = (nChunkSize < nRemaining) ? nChunkSize : nRemaining;

        auto data = read_array(nPos, nReadSize);
        if (data.empty()) break;

        auto it = std::search(data.begin(), data.end(), pData, pData + nDataSize);
        if (it != data.end()) {
          return nPos + std::distance(data.begin(), it);
        }

        if ((int64_t)data.size() < nReadSize) break;

        nPos += nReadSize - nOverlap;
        if (nOverlap <= 0) nPos += 1;
      }

      return -1;
    }

  private:
    std::istream* m_pDevice;
  };

}  // namespace xbinary
