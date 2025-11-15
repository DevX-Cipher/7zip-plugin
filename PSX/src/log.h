#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include <fstream>
#include <string>
#include <cstdarg>
#include <cwchar>

#ifdef _DEBUG

// --- Internal logging helper ---
inline void _writeLog(const std::wstring& fileName, const wchar_t* level, const wchar_t* format, va_list args) {
  wchar_t* userProfile = nullptr;
  size_t len = 0;
  errno_t err = _wdupenv_s(&userProfile, &len, L"USERPROFILE");
  if (err != 0 || !userProfile) return;

  std::wstring logFilePath = std::wstring(userProfile) + L"\\Desktop\\" + fileName;
  free(userProfile); // _wdupenv_s allocates memory

  wchar_t buffer[1024];
  vswprintf(buffer, sizeof(buffer) / sizeof(buffer[0]), format, args); // safer than old vswprintf

  std::wofstream logFile(logFilePath, std::ios::app);
  if (logFile.is_open()) {
    logFile << L"[" << level << L"] " << buffer << std::endl;
    logFile.close();
  }
}

// --- LogDebug ---
inline void logDebug(const wchar_t* format, ...) {
  va_list args;
  va_start(args, format);
  _writeLog(L"PSX_debug.log", L"DEBUG", format, args);
  va_end(args);
}

// --- LogInfo ---
inline void logInfo(const wchar_t* format, ...) {
  va_list args;
  va_start(args, format);
  _writeLog(L"PSX_info.log", L"INFO", format, args);
  va_end(args);
}

// --- LogError ---
inline void logError(const wchar_t* format, ...) {
  va_list args;
  va_start(args, format);
  _writeLog(L"PSX_error.log", L"ERROR", format, args);
  va_end(args);
}

// --- Overloads for std::string/std::wstring ---
inline void logDebug(const std::wstring& msg) { logDebug(L"%s", msg.c_str()); }
inline void logDebug(const std::string& msg) { logDebug(L"%S", msg.c_str()); }

inline void logInfo(const std::wstring& msg) { logInfo(L"%s", msg.c_str()); }
inline void logInfo(const std::string& msg) { logInfo(L"%S", msg.c_str()); }

inline void logError(const std::wstring& msg) { logError(L"%s", msg.c_str()); }
inline void logError(const std::string& msg) { logError(L"%S", msg.c_str()); }

#else

// --- No-op in release builds ---
inline void logDebug(const wchar_t*, ...) {}
inline void logInfo(const wchar_t*, ...) {}
inline void logError(const wchar_t*, ...) {}

inline void logDebug(const std::wstring&) {}
inline void logInfo(const std::wstring&) {}
inline void logError(const std::wstring&) {}

inline void logDebug(const std::string&) {}
inline void logInfo(const std::string&) {}
inline void logError(const std::string&) {}

#endif
