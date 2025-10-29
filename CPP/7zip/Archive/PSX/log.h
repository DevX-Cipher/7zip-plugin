#pragma once

#ifdef _DEBUG

// Trait to detect if T can be streamed into std::ostream
template <typename T>
class is_streamable {
private:
  template <typename U>
  static auto test(int) -> decltype(std::declval<std::ostream&>() << std::declval<U>(), std::true_type());

  template <typename>
  static std::false_type test(...);

public:
  static constexpr bool value = decltype(test<T>(0))::value;
};

// Helper to stream a single argument
template <typename T>
inline typename std::enable_if<is_streamable<T>::value>::type
logDebugHelper(std::ostringstream& oss, T&& arg) {
  oss << std::forward<T>(arg);
}

template <typename T>
inline typename std::enable_if<!is_streamable<T>::value>::type
logDebugHelper(std::ostringstream& oss, T&&) {
  oss << "[unstreamable type]";
}

// Variadic helper to stream multiple arguments
template <typename T, typename... Args>
inline void logDebugHelper(std::ostringstream& oss, T&& first, Args&&... rest) {
  logDebugHelper(oss, std::forward<T>(first));
  logDebugHelper(oss, std::forward<Args>(rest)...);
}

// Main logging function
template <typename... Args>
inline void logDebug(Args&&... args) {
  static std::string logPath;
  if (logPath.empty()) {
    wchar_t desktop[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_DESKTOP, nullptr, 0, desktop))) {
      std::wstring wpath = std::wstring(desktop) + L"\\unified_pkg_debug.log";
      int sz = WideCharToMultiByte(CP_UTF8, 0, wpath.c_str(), -1, nullptr, 0, nullptr, nullptr);
      if (sz > 0) {
        logPath.resize(sz - 1);
        WideCharToMultiByte(CP_UTF8, 0, wpath.c_str(), -1, &logPath[0], sz - 1, nullptr, nullptr);
      }
    }
  }

  if (logPath.empty()) return;

  std::ofstream f(logPath, std::ios::app);
  if (!f.is_open()) return;

  auto now = std::chrono::system_clock::now();
  std::time_t t_c = std::chrono::system_clock::to_time_t(now);
  f << "[" << std::put_time(std::localtime(&t_c), "%Y-%m-%d %H:%M:%S") << "] ";

  std::ostringstream oss;
  logDebugHelper(oss, std::forward<Args>(args)...);
  f << oss.str() << "\n";
}
#endif // _DEBUG
