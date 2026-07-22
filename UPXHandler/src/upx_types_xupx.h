#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <map>
#include <fstream>
#include <memory>
#include <stdexcept>

using qint8 = int8_t;
using qint16 = int16_t;
using qint32 = int32_t;
using qint64 = int64_t;
using quint8 = uint8_t;
using quint16 = uint16_t;
using quint32 = uint32_t;
using quint64 = uint64_t;
using XADDR = int64_t;

namespace XUPX {
  enum UPX_FORMAT : quint8 {
    UPX_F_DOS_COM = 1,
    UPX_F_DOS_SYS = 2,
    UPX_F_DOS_EXE = 3,
    UPX_F_DJGPP2_COFF = 4,
    UPX_F_WATCOM_LE = 5,
    UPX_F_DOS_EXEH = 7,
    UPX_F_TMT_ADAM = 8,
    UPX_F_W32PE_I386 = 9,
    UPX_F_LINUX_i386 = 10,
    UPX_F_LINUX_ELF_i386 = 12,
    UPX_F_LINUX_SH_i386 = 14,
    UPX_F_VMLINUZ_i386 = 15,
    UPX_F_BVMLINUZ_i386 = 16,
    UPX_F_ELKS_8086 = 17,
    UPX_F_PS1_EXE = 18,
    UPX_F_VMLINUX_i386 = 19,
    UPX_F_LINUX_ELFI_i386 = 20,
    UPX_F_WINCE_ARM = 21,
    UPX_F_LINUX_ELF64_AMD64 = 22,
    UPX_F_LINUX_ELF32_ARM = 23,
    UPX_F_BSD_i386 = 24,
    UPX_F_BSD_ELF_i386 = 25,
    UPX_F_BSD_SH_i386 = 26,
    UPX_F_VMLINUX_AMD64 = 27,
    UPX_F_VMLINUX_ARM = 28,
    UPX_F_MACH_i386 = 29,
    UPX_F_LINUX_ELF32_MIPSEL = 30,
    UPX_F_VMLINUZ_ARM = 31,
    UPX_F_MACH_ARM = 32,
    UPX_F_DYLIB_i386 = 33,
    UPX_F_MACH_AMD64 = 34,
    UPX_F_DYLIB_AMD64 = 35,
    UPX_F_W64PE_AMD64 = 36,
    UPX_F_MACH_ARM64 = 37,
    UPX_F_LINUX_ELF64_PPC64LE = 39,
    UPX_F_VMLINUX_PPC64LE = 40,
    UPX_F_LINUX_ELF64_ARM64 = 42,
    UPX_F_W64PE_ARM64 = 43,
    UPX_F_W64PE_ARM64EC = 44,

    UPX_F_ATARI_TOS = 129,
    UPX_F_MACH_PPC32 = 131,
    UPX_F_LINUX_ELF32_PPC32 = 132,
    UPX_F_LINUX_ELF32_ARMEB = 133,
    UPX_F_MACH_FAT = 134,
    UPX_F_VMLINUX_ARMEB = 135,
    UPX_F_VMLINUX_PPC32 = 136,
    UPX_F_LINUX_ELF32_MIPS = 137,
    UPX_F_DYLIB_PPC32 = 138,
    UPX_F_MACH_PPC64 = 139,
    UPX_F_LINUX_ELF64_PPC64 = 140,
    UPX_F_VMLINUX_PPC64 = 141,
    UPX_F_DYLIB_PPC64 = 142
  };

  enum UPX_METHOD : quint8 {
    UPX_M_NRV2B_LE32 = 2,
    UPX_M_NRV2B_8 = 3,
    UPX_M_NRV2B_LE16 = 4,
    UPX_M_NRV2D_LE32 = 5,
    UPX_M_NRV2D_8 = 6,
    UPX_M_NRV2D_LE16 = 7,
    UPX_M_NRV2E_LE32 = 8,
    UPX_M_NRV2E_8 = 9,
    UPX_M_NRV2E_LE16 = 10,
    UPX_M_LZMA = 14,
    UPX_M_DEFLATE = 15
  };

#pragma pack(push, 1)
  struct p_info {
    quint32 p_filesize;
    quint32 p_blocksize;
  };

  struct b_info {
    quint32 sz_cpr;
    quint32 sz_unc;
    quint8 b_method;
    quint8 b_ftid;
    quint8 b_cto8;
    quint8 reserved;
  };

  struct l_info {
    quint32 l_magic;
    quint16 l_lsize;
    quint16 l_version;
  };
#pragma pack(pop)

  struct INTERNAL_INFO {
    char magic[4] = { '\0' };
    quint8 version = 0;
    quint8 format = 0;
    quint8 method = 0;
    quint8 level = 0;
    quint32 u_adler = 0;
    quint32 c_adler = 0;
    quint32 u_len = 0;
    quint32 c_len = 0;
    quint32 u_file_size = 0;
    quint32 off_filter = 0;
    quint8 filter = 0;
    quint8 filter_cto = 0;
    quint8 n_mru = 0;
    quint32 nPackHeaderSize = 0;
    qint64 nHeaderOffset = 0;
    qint64 nDataOffset = 0;
    bool bIsValid = false;
  };

  enum FT : qint32 {
    FT_UNKNOWN = 0,
    FT_MSDOS,
    FT_COM,
    FT_PE32,
    FT_PE64,
    FT_ELF32,
    FT_ELF64,
    FT_MACHO32,
    FT_MACHO64,
    FT_MACHOFAT,
    FT_UPX
  };
}
