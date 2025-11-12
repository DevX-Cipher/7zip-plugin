#define NOMINMAX
#include <windows.h>
#undef min
#undef max
#include <algorithm>
#include <vector>
#include <string>
#include <sstream>
#include <cstdint>
#include <map>
#include <iostream>
#include <fstream>
#include <ctime>
#include <chrono>
#include <shlobj.h>
#include <thread>
#include <mutex>
#include <atomic>
#include "zlib_decoder.h"

// Forward declarations for COM interfaces
interface IInStream;
interface IArchiveOpenCallback;
interface IArchiveOpenVolumeCallback;

// Utility macro for checking HRESULT
#ifndef RINOK
#define RINOK(x) { HRESULT __result_ = (x); if (__result_ != S_OK) return __result_; }
#endif

#ifdef _DEBUG
static void logDebug(const std::string& message);
static void logDebug(const std::wstring& message);
#else
#define logDebug(...) ((void)0)
#endif

static std::string wideToUtf8(const std::wstring& wstr);
static std::wstring utf8ToWide(const std::string& str);

// RPA Archive Format Constants
namespace RPA {
	const double VERSION_UNKNOWN = -1.0;
	const double VERSION_RPA_1 = 1.0;
	const double VERSION_RPA_2 = 2.0;
	const double VERSION_RPA_3 = 3.0;
	const double VERSION_RPA_3_2 = 3.2;

	const std::string MAGIC_RPA_1_RPA = ".rpa";
	const std::string MAGIC_RPA_1_RPI = ".rpi";
	const std::string MAGIC_RPA_2 = "RPA-2.0 ";
	const std::string MAGIC_RPA_3 = "RPA-3.0 ";
	const std::string MAGIC_RPA_3_2 = "RPA-3.2 ";

	const int64_t DEFAULT_OBFUSCATION_KEY = 0xDEADBEEF;
}

// Pickle parser opcodes
namespace Pickle {
	const uint8_t MARK = '(';
	const uint8_t STOP = '.';
	const uint8_t INT = 'I';
	const uint8_t LONG = 'L';
	const uint8_t STRING = 'S';
	const uint8_t NONE = 'N';
	const uint8_t PYUNICODE = 'V';
	const uint8_t APPEND = 'a';
	const uint8_t BUILD = 'b';
	const uint8_t GLOBAL = 'c';
	const uint8_t DICT = 'd';
	const uint8_t EMPTY_DICT = '}';
	const uint8_t APPENDS = 'e';
	const uint8_t GET = 'g';
	const uint8_t BINGET = 'h';
	const uint8_t INST = 'i';
	const uint8_t LONG_BINGET = 'j';
	const uint8_t LIST = 'l';
	const uint8_t EMPTY_LIST = ']';
	const uint8_t OBJ = 'o';
	const uint8_t PUT = 'p';
	const uint8_t BINPUT = 'q';
	const uint8_t LONG_BINPUT = 'r';
	const uint8_t SETITEM = 's';
	const uint8_t TUPLE = 't';
	const uint8_t EMPTY_TUPLE = ')';
	const uint8_t SETITEMS = 'u';
	const uint8_t BINFLOAT = 'G';

	// Protocol 2
	const uint8_t PROTO = '\x80';
	const uint8_t NEWOBJ = '\x81';
	const uint8_t EXT1 = '\x82';
	const uint8_t EXT2 = '\x83';
	const uint8_t EXT4 = '\x84';
	const uint8_t TUPLE1 = '\x85';
	const uint8_t TUPLE2 = '\x86';
	const uint8_t TUPLE3 = '\x87';
	const uint8_t NEWTRUE = '\x88';
	const uint8_t NEWFALSE = '\x89';
	const uint8_t LONG1 = '\x8a';
	const uint8_t LONG4 = '\x8b';

	// String opcodes
	const uint8_t BINSTRING = 'T';
	const uint8_t SHORT_BINSTRING = 'U';
	const uint8_t BINBYTES = 'B';
	const uint8_t SHORT_BINBYTES = 'C';
	const uint8_t BINUNICODE = 'X';

	// Integer opcodes
	const uint8_t BININT = 'J';
	const uint8_t BININT1 = 'K';
	const uint8_t BININT2 = 'M';

	// Protocol 4
	const uint8_t SHORT_BINUNICODE = '\x8c';
	const uint8_t BINUNICODE8 = '\x8d';
	const uint8_t BINBYTES8 = '\x8e';
	const uint8_t EMPTY_SET = '\x8f';
	const uint8_t ADDITEMS = '\x90';
	const uint8_t FROZENSET = '\x91';
	const uint8_t NEWOBJ_EX = '\x92';
	const uint8_t STACK_GLOBAL = '\x93';
	const uint8_t MEMOIZE = '\x94';
	const uint8_t FRAME = '\x95';

	// Protocol 5
	const uint8_t BYTEARRAY8 = '\x96';
	const uint8_t NEXT_BUFFER = '\x97';
	const uint8_t READONLY_BUFFER = '\x98';
}

class PickleParser {
public:
	enum ValueType {
		TYPE_NONE,
		TYPE_INT,
		TYPE_LONG,
		TYPE_STRING,
		TYPE_UNICODE,
		TYPE_LIST,
		TYPE_TUPLE,
		TYPE_DICT,
		TYPE_BYTES
	};

	struct Value {
		ValueType type;
		union {
			int64_t intValue;
			double floatValue;
		};
		std::string strValue;
		std::vector<uint8_t> bytesValue;
		std::vector<std::shared_ptr<Value>> listValue;
		std::map<std::string, std::shared_ptr<Value>> dictValue;

		Value(ValueType t = TYPE_NONE) : type(t), intValue(0) {}
	};

	PickleParser(const uint8_t* d, size_t s) : data(d), size(s), pos(0) {}

	std::shared_ptr<Value> parse();

private:
	const uint8_t* data;
	size_t size;
	size_t pos;
	std::vector<std::shared_ptr<void>> stack;
	std::map<int, std::shared_ptr<void>> memo;

	uint8_t readByte() {
		if (pos >= size) throw std::runtime_error("Unexpected end of pickle data");
		return data[pos++];
	}

	int32_t readInt32() {
		if (pos + 4 > size) throw std::runtime_error("Unexpected end of pickle data");
		int32_t value = *reinterpret_cast<const int32_t*>(&data[pos]);
		pos += 4;
		return value;
	}

	uint32_t readUInt32() {
		if (pos + 4 > size) throw std::runtime_error("Unexpected end of pickle data");
		uint32_t value = *reinterpret_cast<const uint32_t*>(&data[pos]);
		pos += 4;
		return value;
	}

	int16_t readInt16() {
		if (pos + 2 > size) throw std::runtime_error("Unexpected end of pickle data");
		int16_t value = *reinterpret_cast<const int16_t*>(&data[pos]);
		pos += 2;
		return value;
	}

	uint64_t readUInt64() {
		if (pos + 8 > size) throw std::runtime_error("Unexpected end of pickle data");
		uint64_t value = *reinterpret_cast<const uint64_t*>(&data[pos]);
		pos += 8;
		return value;
	}

	std::string readLine() {
		std::string line;
		while (pos < size) {
			char ch = static_cast<char>(data[pos++]);
			if (ch == '\n') break;
			if (ch == '\r') {
				if (pos < size && data[pos] == '\n') pos++;
				break;
			}
			line += ch;
		}
		return line;
	}

	std::string readString(size_t len) {
		if (pos + len > size) throw std::runtime_error("Unexpected end of pickle data");
		std::string str(reinterpret_cast<const char*>(&data[pos]), len);
		pos += len;
		return str;
	}

	std::shared_ptr<Value> popStack() {
		if (stack.empty()) throw std::runtime_error("Stack underflow");
		auto val = std::static_pointer_cast<Value>(stack.back());
		stack.pop_back();
		return val;
	}

	void pushStack(std::shared_ptr<Value> val) {
		stack.push_back(val);
	}

	std::vector<std::shared_ptr<Value>> popMark() {
		std::vector<std::shared_ptr<Value>> items;
		while (!stack.empty()) {
			auto item = stack.back();
			stack.pop_back();
			if (!item) break; // Found mark
			items.insert(items.begin(), std::static_pointer_cast<Value>(item));
		}
		return items;
	}
};

std::shared_ptr<PickleParser::Value> PickleParser::parse() {
	while (pos < size) {
		uint8_t opcode = readByte();

		try {
			switch (opcode) {
			case Pickle::PROTO: {
				uint8_t version = readByte();
				logDebug("Pickle protocol version: " + std::to_string(version));
				break;
			}

			case Pickle::MARK:
				stack.push_back(nullptr); // Mark
				break;

			case Pickle::STOP:
				if (!stack.empty()) {
					return std::static_pointer_cast<Value>(stack.back());
				}
				return std::make_shared<Value>(TYPE_NONE);

			case Pickle::INT: {
				std::string line = readLine();
				int64_t val = std::stoll(line);
				auto value = std::make_shared<Value>(TYPE_INT);
				value->intValue = val;
				pushStack(value);
				break;
			}

			case Pickle::BININT: {
				int32_t val = readInt32();
				auto value = std::make_shared<Value>(TYPE_INT);
				value->intValue = val;
				pushStack(value);
				break;
			}

			case Pickle::BININT1: {
				uint8_t val = readByte();
				auto value = std::make_shared<Value>(TYPE_INT);
				value->intValue = val;
				pushStack(value);
				break;
			}

			case Pickle::BININT2: {
				uint16_t val = readInt16();
				auto value = std::make_shared<Value>(TYPE_INT);
				value->intValue = val;
				pushStack(value);
				break;
			}

			case Pickle::LONG: {
				std::string line = readLine();
				if (!line.empty() && line.back() == 'L') {
					line.pop_back();
				}
				int64_t val = std::stoll(line);
				auto value = std::make_shared<Value>(TYPE_LONG);
				value->intValue = val;
				pushStack(value);
				break;
			}

			case Pickle::LONG1: {
				uint8_t len = readByte();
				int64_t val = 0;
				for (int i = 0; i < len && i < 8; i++) {
					val |= static_cast<int64_t>(readByte()) << (i * 8);
				}
				auto value = std::make_shared<Value>(TYPE_LONG);
				value->intValue = val;
				pushStack(value);
				break;
			}

			case Pickle::LONG4: {
				uint32_t len = readUInt32();
				int64_t val = 0;
				for (uint32_t i = 0; i < len && i < 8; i++) {
					val |= static_cast<int64_t>(readByte()) << (i * 8);
				}
				auto value = std::make_shared<Value>(TYPE_LONG);
				value->intValue = val;
				pushStack(value);
				break;
			}

			case Pickle::STRING: {
				std::string line = readLine();
				// Remove quotes
				if (line.size() >= 2 && line.front() == '\'' && line.back() == '\'') {
					line = line.substr(1, line.size() - 2);
				}
				auto value = std::make_shared<Value>(TYPE_STRING);
				value->strValue = line;
				pushStack(value);
				break;
			}

			case Pickle::BINSTRING:
			case Pickle::BINBYTES: {
				uint32_t len = readUInt32();
				auto str = readString(len);
				if (opcode == Pickle::BINBYTES) {
					auto value = std::make_shared<Value>(TYPE_BYTES);
					value->bytesValue.assign(str.begin(), str.end());
					pushStack(value);
				}
				else {
					auto value = std::make_shared<Value>(TYPE_STRING);
					value->strValue = str;
					pushStack(value);
				}
				break;
			}

			case Pickle::SHORT_BINSTRING:
			case Pickle::SHORT_BINBYTES: {
				uint8_t len = readByte();
				auto str = readString(len);
				if (opcode == Pickle::SHORT_BINBYTES) {
					auto value = std::make_shared<Value>(TYPE_BYTES);
					value->bytesValue.assign(str.begin(), str.end());
					pushStack(value);
				}
				else {
					auto value = std::make_shared<Value>(TYPE_STRING);
					value->strValue = str;
					pushStack(value);
				}
				break;
			}

			case Pickle::PYUNICODE:
			case Pickle::BINUNICODE: {
				uint32_t len = (opcode == Pickle::BINUNICODE) ? readUInt32() : 0;
				std::string str = (opcode == Pickle::BINUNICODE) ?
					readString(len) : readLine();
				auto value = std::make_shared<Value>(TYPE_UNICODE);
				value->strValue = str;
				pushStack(value);
				break;
			}

			case Pickle::SHORT_BINUNICODE: {
				uint8_t len = readByte();
				std::string str = readString(len);
				auto value = std::make_shared<Value>(TYPE_UNICODE);
				value->strValue = str;
				pushStack(value);
				break;
			}

			case Pickle::BINUNICODE8: {
				uint64_t len = readUInt64();
				if (len > 0x7FFFFFFF) {
					throw std::runtime_error("String too large");
				}
				std::string str = readString(static_cast<size_t>(len));
				auto value = std::make_shared<Value>(TYPE_UNICODE);
				value->strValue = str;
				pushStack(value);
				break;
			}

			case Pickle::BINBYTES8: {
				uint64_t len = readUInt64();
				if (len > 0x7FFFFFFF) {
					throw std::runtime_error("Bytes too large");
				}
				std::string str = readString(static_cast<size_t>(len));
				auto value = std::make_shared<Value>(TYPE_BYTES);
				value->bytesValue.assign(str.begin(), str.end());
				pushStack(value);
				break;
			}

			case Pickle::FRAME: {
				uint64_t frameSize = readUInt64();
#ifdef _DEBUG
				logDebug("Frame size: " + std::to_string(frameSize));
#endif
				break;
			}

			case Pickle::MEMOIZE: {
				if (!stack.empty()) {
					int idx = static_cast<int>(memo.size());
					memo[idx] = stack.back();
				}
				break;
			}

			case Pickle::STACK_GLOBAL: {
				if (stack.size() >= 2) {
					popStack(); // name
					popStack(); // module
				}
				auto value = std::make_shared<Value>(TYPE_NONE);
				pushStack(value);
				break;
			}

			case Pickle::EMPTY_SET: {
				auto value = std::make_shared<Value>(TYPE_LIST);
				pushStack(value);
				break;
			}

			case Pickle::ADDITEMS: {
				auto items = popMark();
				auto set = popStack();
				pushStack(set);
				break;
			}

			case Pickle::FROZENSET: {
				auto items = popMark();
				auto value = std::make_shared<Value>(TYPE_LIST);
				value->listValue = items;
				pushStack(value);
				break;
			}

			case Pickle::NEWOBJ_EX: {
				if (stack.size() >= 3) {
					popStack(); // kwargs
					popStack(); // args
					popStack(); // cls
				}
				auto value = std::make_shared<Value>(TYPE_NONE);
				pushStack(value);
				break;
			}

			case Pickle::NEXT_BUFFER:
			case Pickle::READONLY_BUFFER:
			case Pickle::BYTEARRAY8: {
				auto value = std::make_shared<Value>(TYPE_NONE);
				pushStack(value);
				break;
			}

			case Pickle::NONE: {
				auto value = std::make_shared<Value>(TYPE_NONE);
				pushStack(value);
				break;
			}

			case Pickle::NEWTRUE: {
				auto value = std::make_shared<Value>(TYPE_INT);
				value->intValue = 1;
				pushStack(value);
				break;
			}

			case Pickle::NEWFALSE: {
				auto value = std::make_shared<Value>(TYPE_INT);
				value->intValue = 0;
				pushStack(value);
				break;
			}

			case Pickle::EMPTY_LIST: {
				auto value = std::make_shared<Value>(TYPE_LIST);
				pushStack(value);
				break;
			}

			case Pickle::APPEND: {
				auto item = popStack();
				auto list = popStack();
				if (list->type == TYPE_LIST) {
					list->listValue.push_back(item);
				}
				pushStack(list);
				break;
			}

			case Pickle::APPENDS: {
				auto items = popMark();
				auto list = popStack();
				if (list->type == TYPE_LIST) {
					list->listValue.insert(list->listValue.end(), items.begin(), items.end());
				}
				pushStack(list);
				break;
			}

			case Pickle::LIST: {
				auto items = popMark();
				auto value = std::make_shared<Value>(TYPE_LIST);
				value->listValue = items;
				pushStack(value);
				break;
			}

			case Pickle::EMPTY_TUPLE: {
				auto value = std::make_shared<Value>(TYPE_TUPLE);
				pushStack(value);
				break;
			}

			case Pickle::TUPLE: {
				auto items = popMark();
				auto value = std::make_shared<Value>(TYPE_TUPLE);
				value->listValue = items;
				pushStack(value);
				break;
			}

			case Pickle::TUPLE1: {
				auto item = popStack();
				auto value = std::make_shared<Value>(TYPE_TUPLE);
				value->listValue.push_back(item);
				pushStack(value);
				break;
			}

			case Pickle::TUPLE2: {
				auto item2 = popStack();
				auto item1 = popStack();
				auto value = std::make_shared<Value>(TYPE_TUPLE);
				value->listValue.push_back(item1);
				value->listValue.push_back(item2);
				pushStack(value);
				break;
			}

			case Pickle::TUPLE3: {
				auto item3 = popStack();
				auto item2 = popStack();
				auto item1 = popStack();
				auto value = std::make_shared<Value>(TYPE_TUPLE);
				value->listValue.push_back(item1);
				value->listValue.push_back(item2);
				value->listValue.push_back(item3);
				pushStack(value);
				break;
			}

			case Pickle::EMPTY_DICT: {
				auto value = std::make_shared<Value>(TYPE_DICT);
				pushStack(value);
				break;
			}

			case Pickle::DICT: {
				auto items = popMark();
				auto value = std::make_shared<Value>(TYPE_DICT);
				for (size_t i = 0; i + 1 < items.size(); i += 2) {
					std::string key;
					if (items[i]->type == TYPE_STRING || items[i]->type == TYPE_UNICODE) {
						key = items[i]->strValue;
					}
					value->dictValue[key] = items[i + 1];
				}
				pushStack(value);
				break;
			}

			case Pickle::SETITEM: {
				auto val = popStack();
				auto key = popStack();
				auto dict = popStack();
				if (dict->type == TYPE_DICT) {
					std::string keyStr;
					if (key->type == TYPE_STRING || key->type == TYPE_UNICODE) {
						keyStr = key->strValue;
					}
					dict->dictValue[keyStr] = val;
				}
				pushStack(dict);
				break;
			}

			case Pickle::SETITEMS: {
				auto items = popMark();
				auto dict = popStack();
				if (dict->type == TYPE_DICT) {
					for (size_t i = 0; i + 1 < items.size(); i += 2) {
						std::string key;
						if (items[i]->type == TYPE_STRING || items[i]->type == TYPE_UNICODE) {
							key = items[i]->strValue;
						}
						dict->dictValue[key] = items[i + 1];
					}
				}
				pushStack(dict);
				break;
			}

			case Pickle::PUT: {
				std::string line = readLine();
				int idx = std::stoi(line);
				if (!stack.empty()) {
					memo[idx] = stack.back();
				}
				break;
			}

			case Pickle::BINPUT: {
				uint8_t idx = readByte();
				if (!stack.empty()) {
					memo[idx] = stack.back();
				}
				break;
			}

			case Pickle::LONG_BINPUT: {
				uint32_t idx = readUInt32();
				if (!stack.empty()) {
					memo[idx] = stack.back();
				}
				break;
			}

			case Pickle::GET: {
				std::string line = readLine();
				int idx = std::stoi(line);
				if (memo.find(idx) != memo.end()) {
					stack.push_back(memo[idx]);
				}
				break;
			}

			case Pickle::BINGET: {
				uint8_t idx = readByte();
				if (memo.find(idx) != memo.end()) {
					stack.push_back(memo[idx]);
				}
				break;
			}

			case Pickle::LONG_BINGET: {
				uint32_t idx = readUInt32();
				if (memo.find(idx) != memo.end()) {
					stack.push_back(memo[idx]);
				}
				break;
			}

			case Pickle::GLOBAL: {
				std::string module = readLine();
				std::string name = readLine();
				auto value = std::make_shared<Value>(TYPE_NONE);
				pushStack(value);
				break;
			}

			case Pickle::BUILD:
			case Pickle::INST:
			case Pickle::OBJ:
			case Pickle::NEWOBJ:
				break;

			default:
#ifdef _DEBUG
				logDebug("Unknown pickle opcode: 0x" +
					std::to_string(static_cast<int>(opcode)));
#endif
				break;
			}
		}
		catch (const std::exception& e) {
			logDebug("Error processing opcode 0x" +
				std::to_string(static_cast<int>(opcode)) + ": " + e.what());
			throw;
		}
	}

	if (!stack.empty()) {
		return std::static_pointer_cast<Value>(stack.back());
	}
	return std::make_shared<Value>(TYPE_NONE);
}

class MemoryMappedFile {
public:
	MemoryMappedFile() : hFile(INVALID_HANDLE_VALUE), hMapping(nullptr),
		pData(nullptr), fileSize(0) {
	}

	~MemoryMappedFile() {
		Close();
	}

	bool Open(const std::wstring& path) {
		Close();

		hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
			nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (hFile == INVALID_HANDLE_VALUE) {
			return false;
		}

		LARGE_INTEGER size;
		if (!GetFileSizeEx(hFile, &size)) {
			CloseHandle(hFile);
			hFile = INVALID_HANDLE_VALUE;
			return false;
		}

		fileSize = size.QuadPart;

		hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
		if (!hMapping) {
			CloseHandle(hFile);
			hFile = INVALID_HANDLE_VALUE;
			return false;
		}

		pData = static_cast<const uint8_t*>(
			MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0));

		if (!pData) {
			CloseHandle(hMapping);
			CloseHandle(hFile);
			hMapping = nullptr;
			hFile = INVALID_HANDLE_VALUE;
			return false;
		}

		return true;
	}

	void Close() {
		if (pData) {
			UnmapViewOfFile(pData);
			pData = nullptr;
		}
		if (hMapping) {
			CloseHandle(hMapping);
			hMapping = nullptr;
		}
		if (hFile != INVALID_HANDLE_VALUE) {
			CloseHandle(hFile);
			hFile = INVALID_HANDLE_VALUE;
		}
		fileSize = 0;
	}

	const uint8_t* GetData() const { return pData; }
	uint64_t GetSize() const { return fileSize; }
	bool IsOpen() const { return pData != nullptr; }

private:
	HANDLE hFile;
	HANDLE hMapping;
	const uint8_t* pData;
	uint64_t fileSize;
};

class RPAArchiveHandler {
public:
	struct Tuple {
		int64_t offset;
		int64_t length;
		std::vector<uint8_t> prefix;

		Tuple() : offset(0), length(0) {}
	};

	struct ArchiveIndex {
		std::map<int, Tuple> tuples;
		std::string fullPath;
		std::string treePath;
		std::string parentPath;
		bool inArchive;
		int64_t length;

		ArchiveIndex() : inArchive(false), length(0) {}
	};

	struct BatchLoadRequest {
		std::string fileName;
		std::vector<uint8_t>* output;
		bool success;

		BatchLoadRequest() : output(nullptr), success(false) {}
		BatchLoadRequest(const std::string& name, std::vector<uint8_t>* out)
			: fileName(name), output(out), success(false) {
		}
	};

	RPAArchiveHandler();
	~RPAArchiveHandler();

	std::map<std::string, ArchiveIndex> items;

	HRESULT Open(IInStream* stream, const UInt64* fileSize, IArchiveOpenCallback* callback);
	HRESULT ExtractFile(IInStream* stream, const std::string& fileName, std::vector<uint8_t>& output);

	HRESULT OpenForBatchLoad(const std::wstring& archivePath);
	HRESULT BatchExtractFiles(const std::vector<std::string>& fileNames,
		std::vector<std::vector<uint8_t>>& outputs,
		int numThreads = 0);
	void CloseBatchLoad();

	double GetArchiveVersion() const { return archiveVersion; }
	int64_t GetObfuscationKey() const { return obfuscationKey; }
	size_t GetFileCount() const { return items.size(); }

private:
	std::string archivePath;
	std::string indexPath;
	std::string firstLine;
	std::vector<std::string> metadata;

	double archiveVersion;
	int64_t offset;
	int64_t obfuscationKey;
	int padding;
	bool optionsConfirmed;

	std::map<std::string, ArchiveIndex> index;
	IArchiveOpenVolumeCallback* volCallback;

	MemoryMappedFile mmapFile;
	std::mutex extractMutex;

	HRESULT readFirstLine(IInStream* stream);
	HRESULT readFirstLineFromMemory(const uint8_t* data, size_t size);
	double detectVersion(IInStream* stream);
	HRESULT parseMetadata();
	int64_t calculateOffset();
	int64_t calculateObfuscationKey();
	HRESULT parseIndex(IInStream* stream);
	HRESULT parseIndexFromMemory(const uint8_t* data, size_t size);
	HRESULT deobfuscateIndexData();
	bool checkVersion(double version, double check);

	// Pickle parsing
	HRESULT parsePickleData(const std::vector<uint8_t>& data);

	// Batch extraction worker
	void batchExtractWorker(const std::vector<BatchLoadRequest*>& requests,
		std::atomic<int>& progress);
};

// Utility functions
static std::wstring getDesktopPath() {
	wchar_t path[MAX_PATH];
	if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_DESKTOP, nullptr, SHGFP_TYPE_CURRENT, path))) {
		return std::wstring(path);
	}
	return L".";
}

#ifdef _DEBUG
static void logDebug(const std::string& message) {
	static std::string logFilePath;
	if (logFilePath.empty()) {
		std::wstring desktopPath = getDesktopPath();
		std::wstring logPathW = desktopPath + L"\\rpa_debug.log";
		logFilePath = wideToUtf8(logPathW);
	}

	std::ofstream logFile(logFilePath, std::ios::app);
	if (!logFile.is_open()) return;

	auto now = std::chrono::system_clock::now();
	std::time_t now_c = std::chrono::system_clock::to_time_t(now);
	char timeStr[64] = {};
	ctime_s(timeStr, sizeof(timeStr), &now_c);
	timeStr[strcspn(timeStr, "\n")] = 0;

	logFile << "[" << timeStr << "] " << message << "\n";
}

static void logDebug(const std::wstring& message) {
	logDebug(wideToUtf8(message));
}
#endif

static std::string wideToUtf8(const std::wstring& wstr) {
	if (wstr.empty()) return {};
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
	if (size_needed <= 1) return {};
	std::string strTo(size_needed - 1, 0);
	WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &strTo[0], size_needed - 1, nullptr, nullptr);
	return strTo;
}

static std::wstring utf8ToWide(const std::string& str) {
	if (str.empty()) return {};
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
	if (size_needed <= 1) return {};
	std::wstring wstrTo(size_needed - 1, 0);
	MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstrTo[0], size_needed - 1);
	return wstrTo;
}

// Constructor/Destructor
RPAArchiveHandler::RPAArchiveHandler()
	: archiveVersion(RPA::VERSION_UNKNOWN)
	, offset(0)
	, obfuscationKey(RPA::DEFAULT_OBFUSCATION_KEY)
	, padding(0)
	, optionsConfirmed(false)
	, volCallback(nullptr)
{
}

RPAArchiveHandler::~RPAArchiveHandler() {
	CloseBatchLoad();
	if (volCallback) {
		volCallback->Release();
		volCallback = nullptr;
	}
}

// Helper method implementations
bool RPAArchiveHandler::checkVersion(double version, double check) {
	return std::abs(version - check) < 0.01;
}

HRESULT RPAArchiveHandler::readFirstLine(IInStream* stream) {
	RINOK(stream->Seek(0, STREAM_SEEK_SET, nullptr));

	std::string line;
	char ch;
	UInt32 bytesRead;

	while (true) {
		RINOK(stream->Read(reinterpret_cast<BYTE*>(&ch), 1, &bytesRead));
		if (bytesRead == 0 || ch == '\n' || ch == '\r') break;
		line += ch;
	}

	firstLine = line;
	logDebug("First line: " + firstLine);
	return S_OK;
}

HRESULT RPAArchiveHandler::readFirstLineFromMemory(const uint8_t* data, size_t size) {
	std::string line;
	size_t pos = 0;

	while (pos < size) {
		char ch = static_cast<char>(data[pos++]);
		if (ch == '\n' || ch == '\r') break;
		line += ch;
	}

	firstLine = line;
	logDebug("First line: " + firstLine);
	return S_OK;
}

double RPAArchiveHandler::detectVersion(IInStream* stream) {
	if (firstLine.find(RPA::MAGIC_RPA_3_2) == 0) {
		return RPA::VERSION_RPA_3_2;
	}
	if (firstLine.find(RPA::MAGIC_RPA_3) == 0) {
		return RPA::VERSION_RPA_3;
	}
	if (firstLine.find(RPA::MAGIC_RPA_2) == 0) {
		return RPA::VERSION_RPA_2;
	}

	std::string lowerPath = archivePath;
	std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);

	if (lowerPath.find(".rpa") != std::string::npos || lowerPath.find(".rpi") != std::string::npos) {
		return RPA::VERSION_RPA_1;
	}

	return RPA::VERSION_UNKNOWN;
}

HRESULT RPAArchiveHandler::parseMetadata() {
	metadata.clear();
	std::istringstream iss(firstLine);
	std::string token;

	while (iss >> token) {
		metadata.push_back(token);
	}

	logDebug("Metadata elements: " + std::to_string(metadata.size()));
	return S_OK;
}

int64_t RPAArchiveHandler::calculateOffset() {
	if (metadata.size() < 2) return 0;

	try {
		return std::stoll(metadata[1], nullptr, 16);
	}
	catch (...) {
		return 0;
	}
}

int64_t RPAArchiveHandler::calculateObfuscationKey() {
	int64_t key = 0;

	if (checkVersion(archiveVersion, RPA::VERSION_RPA_3)) {
		for (size_t i = 2; i < metadata.size(); i++) {
			try {
				key ^= std::stoll(metadata[i], nullptr, 16);
			}
			catch (...) {}
		}
	}
	else if (checkVersion(archiveVersion, RPA::VERSION_RPA_3_2)) {
		for (size_t i = 3; i < metadata.size(); i++) {
			try {
				key ^= std::stoll(metadata[i], nullptr, 16);
			}
			catch (...) {}
		}
	}

	return key;
}

HRESULT RPAArchiveHandler::parsePickleData(const std::vector<uint8_t>& data) {
#ifdef _DEBUG
	logDebug("Parsing pickle data, size: " + std::to_string(data.size()));
#endif

	try {
		PickleParser parser(data.data(), data.size());
		auto root = parser.parse();

		if (!root || root->type != PickleParser::TYPE_DICT) {
			return E_FAIL;
		}

		for (const auto& entry : root->dictValue) {
			const std::string& fileName = entry.first;
			auto& fileData = entry.second;

			if (!fileData || (fileData->type != PickleParser::TYPE_LIST &&
				fileData->type != PickleParser::TYPE_TUPLE)) {
				continue;
			}

			ArchiveIndex archIndex;
			archIndex.treePath = fileName;
			archIndex.inArchive = true;
			archIndex.length = 0;

			size_t lastSlash = fileName.find_last_of("/\\");
			if (lastSlash != std::string::npos) {
				archIndex.parentPath = fileName.substr(0, lastSlash);
			}

			int tupleIndex = 0;
			const size_t numTuples = fileData->listValue.size();

			for (size_t i = 0; i < numTuples; ++i) {
				auto& tupleData = fileData->listValue[i];

				if (!tupleData || (tupleData->type != PickleParser::TYPE_TUPLE &&
					tupleData->type != PickleParser::TYPE_LIST)) {
					continue;
				}

				if (tupleData->listValue.size() < 2) continue;

				Tuple tuple;

				auto& offsetVal = tupleData->listValue[0];
				if (offsetVal->type == PickleParser::TYPE_INT ||
					offsetVal->type == PickleParser::TYPE_LONG) {
					tuple.offset = offsetVal->intValue;
				}
				else {
					continue;
				}

				auto& lengthVal = tupleData->listValue[1];
				if (lengthVal->type == PickleParser::TYPE_INT ||
					lengthVal->type == PickleParser::TYPE_LONG) {
					tuple.length = lengthVal->intValue;
				}
				else {
					continue;
				}

				if (tupleData->listValue.size() >= 3) {
					auto& prefixData = tupleData->listValue[2];
					if (prefixData->type == PickleParser::TYPE_STRING &&
						!prefixData->strValue.empty()) {
						tuple.prefix.assign(prefixData->strValue.begin(),
							prefixData->strValue.end());
					}
					else if (prefixData->type == PickleParser::TYPE_BYTES &&
						!prefixData->bytesValue.empty()) {
						tuple.prefix = std::move(prefixData->bytesValue);
					}
				}

				archIndex.tuples[tupleIndex++] = std::move(tuple);
				archIndex.length += tuple.length;
			}

			if (!archIndex.tuples.empty()) {
				items.emplace(fileName, std::move(archIndex));
			}
		}

		logDebug("Successfully parsed " + std::to_string(items.size()) + " files");
		return S_OK;
	}
	catch (const std::exception& e) {
		logDebug("Error parsing pickle: " + std::string(e.what()));
		return E_FAIL;
	}
}

HRESULT RPAArchiveHandler::parseIndex(IInStream* stream) {
	logDebug("Parsing archive index at offset: " + std::to_string(offset));

	UInt64 currentPos = offset;
	RINOK(stream->Seek(currentPos, STREAM_SEEK_SET, nullptr));

	UInt64 streamLength;
	RINOK(stream->Seek(0, STREAM_SEEK_END, &streamLength));

	size_t indexSize = static_cast<size_t>(streamLength - currentPos);

	if (indexSize > 100 * 1024 * 1024) {
		logDebug("Index size too large: " + std::to_string(indexSize));
		return E_FAIL;
	}

	RINOK(stream->Seek(currentPos, STREAM_SEEK_SET, nullptr));

	std::vector<uint8_t> compressedIndex;
	compressedIndex.resize(indexSize);

	UInt32 bytesRead = 0;
	RINOK(stream->Read(compressedIndex.data(), static_cast<UInt32>(indexSize), &bytesRead));

	if (bytesRead != indexSize) {
		logDebug("Failed to read complete index");
		return E_FAIL;
	}

	ByteVector* output = bytevector_create(indexSize * 4);
	if (!output) {
		logDebug("Failed to allocate buffer for index decompression");
		return E_FAIL;
	}

	size_t bytes_consumed = 0;
	int result = zlib_decompress_no_checksum(compressedIndex.data(), compressedIndex.size(),
		output, &bytes_consumed);

	compressedIndex.clear();
	compressedIndex.shrink_to_fit();

	if (result < 0 || output->length == 0) {
		logDebug("Failed to decompress index");
		bytevector_free(output);
		return E_FAIL;
	}

#ifdef _DEBUG
	logDebug("Decompressed index: " + std::to_string(output->length) + " bytes");
#endif

	std::vector<uint8_t> decompressed;
	decompressed.reserve(output->length);
	decompressed.assign(output->data, output->data + output->length);
	bytevector_free(output);

	HRESULT hr = parsePickleData(decompressed);

	return hr;
}

HRESULT RPAArchiveHandler::parseIndexFromMemory(const uint8_t* data, size_t size) {
	logDebug("Parsing archive index from memory at offset: " + std::to_string(offset));

	if (offset >= size) {
		logDebug("Invalid offset");
		return E_FAIL;
	}

	size_t indexSize = size - offset;

	if (indexSize > 100 * 1024 * 1024) {
		logDebug("Index size too large: " + std::to_string(indexSize));
		return E_FAIL;
	}

	const uint8_t* compressedData = data + offset;

	ByteVector* output = bytevector_create(indexSize * 4);
	if (!output) {
		logDebug("Failed to allocate buffer for index decompression");
		return E_FAIL;
	}

	size_t bytes_consumed = 0;
	int result = zlib_decompress_no_checksum(compressedData, indexSize,
		output, &bytes_consumed);

	if (result < 0 || output->length == 0) {
		logDebug("Failed to decompress index");
		bytevector_free(output);
		return E_FAIL;
	}

#ifdef _DEBUG
	logDebug("Decompressed index: " + std::to_string(output->length) + " bytes");
#endif

	std::vector<uint8_t> decompressed;
	decompressed.reserve(output->length);
	decompressed.assign(output->data, output->data + output->length);
	bytevector_free(output);

	HRESULT hr = parsePickleData(decompressed);

	return hr;
}

HRESULT RPAArchiveHandler::deobfuscateIndexData() {
	if (archiveVersion < RPA::VERSION_RPA_3) {
		return S_OK;
	}

	logDebug("Deobfuscating index data with key: 0x" +
		std::to_string(obfuscationKey));

	for (auto& item : items) {
		for (auto& tuple : item.second.tuples) {
			tuple.second.offset ^= obfuscationKey;
			tuple.second.length ^= obfuscationKey;
		}
	}

	return S_OK;
}

// Main Open implementation
HRESULT RPAArchiveHandler::Open(IInStream* stream, const UInt64* fileSize,
	IArchiveOpenCallback* callback) {

	if (!callback || !stream) {
		logDebug("Error: Invalid stream or callback");
		return S_FALSE;
	}

	HRESULT result = callback->QueryInterface(IID_IArchiveOpenVolumeCallback,
		(void**)&volCallback);
	RINOK(result);

	if (volCallback == nullptr) {
		logDebug("Error: Failed to get volume callback interface");
		return E_FAIL;
	}

	RINOK(readFirstLine(stream));

	archiveVersion = detectVersion(stream);
	if (archiveVersion == RPA::VERSION_UNKNOWN) {
		logDebug("Error: Unknown RPA archive version");
		return E_FAIL;
	}

	logDebug("Detected RPA version: " + std::to_string(archiveVersion));

	if (archiveVersion >= RPA::VERSION_RPA_2) {
		RINOK(parseMetadata());
		offset = calculateOffset();
		obfuscationKey = calculateObfuscationKey();

		logDebug("Index offset: 0x" + std::to_string(offset));
		logDebug("Obfuscation key: 0x" + std::to_string(obfuscationKey));
	}

	RINOK(parseIndex(stream));
	RINOK(deobfuscateIndexData());

	logDebug("Archive opened successfully. Files: " + std::to_string(items.size()));

	return S_OK;
}

// Extract file implementation
HRESULT RPAArchiveHandler::ExtractFile(IInStream* stream, const std::string& fileName,
	std::vector<uint8_t>& output) {

	auto it = items.find(fileName);
	if (it == items.end()) {
		logDebug("File not found: " + fileName);
		return E_FAIL;
	}

	const ArchiveIndex& fileInfo = it->second;
	output.clear();

	logDebug("Extracting: " + fileName);

	for (const auto& tuplePair : fileInfo.tuples) {
		const Tuple& tuple = tuplePair.second;

		logDebug("  Tuple " + std::to_string(tuplePair.first) +
			": offset=" + std::to_string(tuple.offset) +
			", length=" + std::to_string(tuple.length) +
			", prefix=" + std::to_string(tuple.prefix.size()));

		RINOK(stream->Seek(tuple.offset, STREAM_SEEK_SET, nullptr));

		output.insert(output.end(), tuple.prefix.begin(), tuple.prefix.end());

		size_t dataLength = tuple.length - tuple.prefix.size();
		if (dataLength > 0) {
			size_t oldSize = output.size();
			output.resize(oldSize + dataLength);

			UInt32 bytesRead;
			RINOK(stream->Read(&output[oldSize], static_cast<UInt32>(dataLength), &bytesRead));

			if (bytesRead != dataLength) {
				logDebug("  Warning: Read " + std::to_string(bytesRead) +
					" bytes, expected " + std::to_string(dataLength));
			}
		}
	}

	logDebug("  Extracted: " + std::to_string(output.size()) + " bytes");
	return S_OK;
}

HRESULT RPAArchiveHandler::OpenForBatchLoad(const std::wstring& archivePath) {
	logDebug("Opening archive for batch load: " + wideToUtf8(archivePath));

	if (!mmapFile.Open(archivePath)) {
		logDebug("Failed to memory-map archive file");
		return E_FAIL;
	}

	const uint8_t* data = mmapFile.GetData();
	uint64_t size = mmapFile.GetSize();

	RINOK(readFirstLineFromMemory(data, static_cast<size_t>(size)));

	archiveVersion = detectVersion(nullptr);
	if (archiveVersion == RPA::VERSION_UNKNOWN) {
		logDebug("Error: Unknown RPA archive version");
		mmapFile.Close();
		return E_FAIL;
	}

	logDebug("Detected RPA version: " + std::to_string(archiveVersion));

	if (archiveVersion >= RPA::VERSION_RPA_2) {
		RINOK(parseMetadata());
		offset = calculateOffset();
		obfuscationKey = calculateObfuscationKey();

		logDebug("Index offset: 0x" + std::to_string(offset));
		logDebug("Obfuscation key: 0x" + std::to_string(obfuscationKey));
	}

	RINOK(parseIndexFromMemory(data, static_cast<size_t>(size)));
	RINOK(deobfuscateIndexData());

	logDebug("Archive opened for batch load. Files: " + std::to_string(items.size()));

	return S_OK;
}

void RPAArchiveHandler::batchExtractWorker(const std::vector<BatchLoadRequest*>& requests,
	std::atomic<int>& progress) {
	const uint8_t* data = mmapFile.GetData();

	for (auto* request : requests) {
		auto it = items.find(request->fileName);
		if (it == items.end()) {
			request->success = false;
			progress++;
			continue;
		}

		const ArchiveIndex& fileInfo = it->second;
		request->output->clear();

		try {
			for (const auto& tuplePair : fileInfo.tuples) {
				const Tuple& tuple = tuplePair.second;

				// Add prefix
				request->output->insert(request->output->end(),
					tuple.prefix.begin(), tuple.prefix.end());

				// Copy file data directly from memory-mapped file
				size_t dataLength = tuple.length - tuple.prefix.size();
				if (dataLength > 0 && tuple.offset + dataLength <= mmapFile.GetSize()) {
					const uint8_t* fileData = data + tuple.offset;
					request->output->insert(request->output->end(),
						fileData, fileData + dataLength);
				}
			}

			request->success = true;
		}
		catch (...) {
			request->success = false;
		}

		progress++;
	}
}

HRESULT RPAArchiveHandler::BatchExtractFiles(const std::vector<std::string>& fileNames,
	std::vector<std::vector<uint8_t>>& outputs,
	int numThreads) {
	if (!mmapFile.IsOpen()) {
		logDebug("Archive not opened for batch load");
		return E_FAIL;
	}

	if (numThreads <= 0) {
		numThreads = std::max(1, static_cast<int>(std::thread::hardware_concurrency()));
	}

	logDebug("Batch extracting " + std::to_string(fileNames.size()) +
		" files using " + std::to_string(numThreads) + " threads");

	auto startTime = std::chrono::high_resolution_clock::now();

	outputs.resize(fileNames.size());
	std::vector<BatchLoadRequest> requests(fileNames.size());

	for (size_t i = 0; i < fileNames.size(); i++) {
		requests[i].fileName = fileNames[i];
		requests[i].output = &outputs[i];
	}

	// Distribute work across threads
	std::vector<std::thread> threads;
	std::atomic<int> progress(0);

	size_t filesPerThread = (fileNames.size() + numThreads - 1) / numThreads;

	for (int t = 0; t < numThreads; t++) {
		size_t startIdx = t * filesPerThread;
		size_t endIdx = std::min(startIdx + filesPerThread, fileNames.size());

		if (startIdx >= fileNames.size()) break;

		std::vector<BatchLoadRequest*> threadRequests;
		for (size_t i = startIdx; i < endIdx; i++) {
			threadRequests.push_back(&requests[i]);
		}

		threads.emplace_back([this, threadRequests, &progress]() {
			this->batchExtractWorker(threadRequests, progress);
			});
	}

	// Wait for all threads
	for (auto& thread : threads) {
		thread.join();
	}

	auto endTime = std::chrono::high_resolution_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

	logDebug("Batch extraction completed in " + std::to_string(duration.count()) + " ms");

	// Check results
	int successCount = 0;
	for (const auto& req : requests) {
		if (req.success) successCount++;
	}

	logDebug("Successfully extracted " + std::to_string(successCount) + "/" +
		std::to_string(fileNames.size()) + " files");

	return S_OK;
}

void RPAArchiveHandler::CloseBatchLoad() {
	mmapFile.Close();
}