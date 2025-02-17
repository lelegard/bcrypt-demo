//----------------------------------------------------------------------------
// BCryptDemo - Copyright (c) 2025, Thierry Lelegard
// BSD 2-Clause License, see LICENSE file.
//----------------------------------------------------------------------------

// This program demonstrates some features of the Microsoft BCrypt library
// (aka CNG, Cryptographic API New Generation).
//
// The demos are validated using some public test vectors. Each function is
// "complete", meaning that it performs all required calls for the target
// operation. In a real application, you should not reopen algorithms or
// reload key at every operation. Most functions return true on success
// and false on error.

#include <iostream>
#include <sstream>
#include <vector>
#include <cstdlib>
#include <cinttypes>
#include <windows.h>
#include <psapi.h>

using ByteVector = std::vector<uint8_t>;


//----------------------------------------------------------------------------
// Wide strings comparison.
//----------------------------------------------------------------------------

namespace {
    inline bool equal(LPCWSTR s1, LPCWSTR s2)
    {
        return CompareStringW(LOCALE_INVARIANT, 0, s1, -1, s2, -1) == CSTR_EQUAL;
    }
}


//----------------------------------------------------------------------------
// A class to log debug and errors. For demo only.
//----------------------------------------------------------------------------

class Log
{
public:
    // Constructor.
    Log(int argc = 0, char** argv = nullptr);

    // Log a debug or error message.
    void debug(const std::string& msg);
    void error(const std::string& msg);

    // Check a BCrypt status. Log errors and debug. Return true if status is OK.
    bool bcrypt(NTSTATUS status, const std::string& origin = std::string());

    // Format a Windows error message.
    static std::string message(NTSTATUS status, const std::string& origin = std::string());

    // Application exit code.
    int exit_code() const { return _errors ? EXIT_FAILURE : EXIT_SUCCESS; }

private:
    bool _debug = false;
    bool _errors = false;
};


//----------------------------------------------------------------------------
// A class to measure CPU time.
//----------------------------------------------------------------------------

class CpuTime
{
public:
    // Constructor. Initialize the time.
    CpuTime() : _start(cpu_time()) {}

    // Reset the start time, restart measurement.
    void reset() { _start = cpu_time(); }

    // Number of microseconds of CPU time since constructor or reset().
    int64_t usec() const { return cpu_time() - _start; }

private:
    int64_t _start = 0;
    static int64_t cpu_time();
};


//----------------------------------------------------------------------------
// Wrapper for a BCrypt algorithm.
// The destructor enforces the clean termination of resources.
//----------------------------------------------------------------------------

class Algorithm
{
public:
    // Open an algorithm with an optional chaining mode.
    bool open(Log& log, LPCWSTR algo_name, LPCWSTR chain_mode = nullptr);

    // Open a hash algorithm for HMAC usage.
    bool open_hmac(Log& log, LPCWSTR algo_name);

    // Get the algo handle. Don't use it to destroy the key, use free().
    BCRYPT_ALG_HANDLE handle() const { return _handle; }

    // Get a DWORD property of the algorithm.
    bool get_property(Log& log, LPCWSTR property_name, DWORD& value) const;

    // Get the algorithm block size. Return zero on error.
    size_t block_size(Log& log) const;

    // Get the initialization vector size for the chaining mode.
    size_t iv_size() const { return _iv_size; }

    // Free the algo resources, silently or with log.
    void close();
    bool close(Log& log);

    // Destructor.
    ~Algorithm();

private:
    BCRYPT_ALG_HANDLE _handle = nullptr;
    size_t _iv_size = 0;
};


//----------------------------------------------------------------------------
// Wrapper for a BCrypt symmetric key.
// The destructor enforces the clean termination of resources.
//----------------------------------------------------------------------------

class Key
{
public:
    // Load a key value.
    bool load(Log& log, Algorithm& algo, const ByteVector& key);

    // Get the key handle. Don't use it to destroy the key, use free().
    BCRYPT_KEY_HANDLE handle() const { return _handle; }

    // Set the initialization vector for the next chain of operations.
    bool set_iv(Log& log, const ByteVector& iv);

    // Encrypt a chunk of data. Plain size must be a multiple of block size, unless pad_final is true.
    bool encrypt(Log& log, const ByteVector& plain, ByteVector& cipher, bool pad_final = false);

    // Decrypt a chunk of data. Cipher size must be a multiple of block size.
    // Pad_final must be set exactly if it was used during production of the last cipher block.
    bool decrypt(Log& log, const ByteVector& cipher, ByteVector& plain, bool pad_final = false);

    // Free the key resources, silently or with log.
    void close();
    bool close(Log& log);

    // Destructor.
    ~Key();

private:
    BCRYPT_KEY_HANDLE _handle = nullptr;
    size_t _block_size = 0;
    size_t _iv_size = 0;
    ByteVector _iv {};
    ByteVector _key_object {};
};


//----------------------------------------------------------------------------
// CpuTime implementation: A class to measure CPU time.
//----------------------------------------------------------------------------

// Get current CPU time resource usage in microseconds in current process.
int64_t CpuTime::cpu_time()
{
    FILETIME creation_time, exit_time, kernel_time, user_time;
    if (GetProcessTimes(GetCurrentProcess(), &creation_time, &exit_time, &kernel_time, &user_time) == 0) {
        std::cerr << "GetProcessTimes error 0x" << std::hex << GetLastError() << std::endl;
        std::exit(EXIT_FAILURE);
    }
    // A FILETIME is a 64-bit value in 100-nanosecond units (10 microseconds).
    const int64_t ktime = (int64_t(kernel_time.dwHighDateTime) << 32) | kernel_time.dwLowDateTime;
    const int64_t utime = (int64_t(user_time.dwHighDateTime) << 32) | user_time.dwLowDateTime;
    return (ktime + utime) / 10;
}


//----------------------------------------------------------------------------
// Log implementation: A class to log debug and errors.
//----------------------------------------------------------------------------

// Constructor.
Log::Log(int argc, char** argv)
{
    if (argc > 1 && argv != nullptr) {
        for (int i = 1; i < argc; ++i) {
            const std::string arg(argv[i]);
            if (arg == "--debug" || arg == "-d") {
                _debug = true;
            }
        }
    }
}

// Log a debug message.
void Log::debug(const std::string& msg)
{
    if (_debug && !msg.empty()) {
        std::cout << "Debug: " << msg << std::endl;
    }
}

// Log an error message.
void Log::error(const std::string& msg)
{
    _errors = true;
    std::cout << "**** Error: " << msg << std::endl;
}

// Check a BCrypt status. Log errors and debug. Return true if status is OK.
bool Log::bcrypt(NTSTATUS status, const std::string& origin)
{
    if (BCRYPT_SUCCESS(status)) {
        debug(origin);
        return true;
    }
    else {
        error(message(status, origin));
        return false;
    }
}

// Format a Windows error message.
std::string Log::message(NTSTATUS status, const std::string& origin)
{
    // Try system message.
    std::string buffer(1024, 0);
    DWORD length = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, nullptr, status, 0, &buffer[0], DWORD(buffer.size()), nullptr);

    // Try all loaded modules in the process.
    if (length <= 0) {
        DWORD retsize = 0;
        std::vector<HMODULE> hmods(512);
        if (EnumProcessModules(GetCurrentProcess(), hmods.data(), DWORD(hmods.size() * sizeof(HMODULE)), &retsize)) {
            hmods.resize(std::min<size_t>(hmods.size(), retsize / sizeof(HMODULE)));
            for (size_t i = 0; length <= 0 && i < hmods.size(); ++i) {
                length = FormatMessageA(FORMAT_MESSAGE_FROM_HMODULE, hmods[i], status, 0, &buffer[0], DWORD(buffer.size()), nullptr);
            }
        }
    }
    buffer.resize(std::min<size_t>(buffer.size(), length));

    // Format hexadecimal status.
    if (buffer.empty()) {
        std::ostringstream out;
        out << "status 0x" << std::hex << std::uppercase << status << std::nouppercase << std::dec;
        buffer = out.str();
    }

    return origin.empty() ? buffer : origin + ": " + buffer;
}


//----------------------------------------------------------------------------
// Compute a derived key using PBKDF2.
//----------------------------------------------------------------------------

bool pbkdf2(Log& log, ByteVector& derived_key, LPCWSTR hash_algo, const std::string& password, const std::string& salt, size_t iterations, size_t key_size)
{
    // Open the hash algorithm.
    Algorithm algo;
    if (!algo.open_hmac(log, hash_algo)) {
        return false;
    }

    // Compute the derived key.
    derived_key.resize(key_size);
    NTSTATUS status = BCryptDeriveKeyPBKDF2(algo.handle(),
                                            PUCHAR(password.data()), ULONG(password.size()),
                                            PUCHAR(salt.data()), ULONG(salt.size()),
                                            iterations,
                                            PUCHAR(derived_key.data()), ULONG(derived_key.size()),
                                            0);

    return log.bcrypt(status, "BCryptDeriveKeyPBKDF2");
}


//----------------------------------------------------------------------------
// AlgoWrapper implementation: Wrapper for a BCrypt algorithm.
//----------------------------------------------------------------------------

// Open an algorithm with an optional chaining mode.
bool Algorithm::open(Log& log, LPCWSTR algo_name, LPCWSTR chain_mode)
{
    // Close previous handle.
    close();

    // Open the algorithm.
    NTSTATUS status = BCryptOpenAlgorithmProvider(&_handle, algo_name, nullptr, 0);
    if (!log.bcrypt(status, "BCryptOpenAlgorithmProvider")) {
        return false;
    }

    // Set chaining mode.
    if (chain_mode != nullptr) {
        status = BCryptSetProperty(_handle, BCRYPT_CHAINING_MODE, PUCHAR(chain_mode), sizeof(chain_mode), 0);
        if (!log.bcrypt(status, "BCryptSetProperty(BCRYPT_CHAINING_MODE)")) {
            return false;
        }
        // Get the expected IV size. There is no property for that, we need to check known modes.
        if (equal(chain_mode, BCRYPT_CHAIN_MODE_CBC)) {
            _iv_size = block_size(log);
        }
        // TODO: BCRYPT_CHAIN_MODE_CCM, BCRYPT_CHAIN_MODE_CFB, BCRYPT_CHAIN_MODE_GCM
    }
    return true;
}

// Open a hash algorithm for HMAC usage.
bool Algorithm::open_hmac(Log& log, LPCWSTR algo_name)
{
    close();
    NTSTATUS status = BCryptOpenAlgorithmProvider(&_handle, algo_name, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    return log.bcrypt(status, "BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE_HMAC_FLAG)");
}

// Get a DWORD property of the algorithm.
bool Algorithm::get_property(Log& log, LPCWSTR property_name, DWORD& value) const
{
    value = 0;
    ULONG retsize = 0;
    NTSTATUS status = BCryptGetProperty(_handle, property_name, PUCHAR(&value), sizeof(value), &retsize, 0);
    return log.bcrypt(status, "BCryptGetProperty");
}

// Get the algorithm block size. Return zero on error.
size_t Algorithm::block_size(Log& log) const
{
    DWORD bsize = 0;
    return get_property(log, BCRYPT_BLOCK_LENGTH, bsize) ? bsize : 0;
}

// Free the algo resources.
bool Algorithm::close(Log& log)
{
    if (_handle == nullptr) {
        return true;
    }
    else {
        NTSTATUS status = BCryptCloseAlgorithmProvider(_handle, 0);
        _handle = nullptr;
        _iv_size = 0;
        return log.bcrypt(status, "BCryptCloseAlgorithmProvider");        
    }
}

// Silently free the algo resources.
void Algorithm::close()
{
    if (_handle != nullptr) {
        BCryptCloseAlgorithmProvider(_handle, 0);
        _handle = nullptr;
        _iv_size = 0;
    }
}

// Destructor.
Algorithm::~Algorithm()
{
    close();
}


//----------------------------------------------------------------------------
// KeyWrapper implementation: Wrapper for a BCrypt symmetric key.
//----------------------------------------------------------------------------

// Load a key value.
bool Key::load(Log& log, Algorithm& algo, const ByteVector& key)
{
    // Close previous key handle.
    close();

    _block_size = algo.block_size(log);
    _iv_size = algo.iv_size();
    _iv.clear();

    // Get the size of the "key object" for that algo.
    DWORD objlength = 0;
    if (!algo.get_property(log, BCRYPT_OBJECT_LENGTH, objlength)) {
        return false;
    }
    _key_object.resize(objlength);

    // Build a key data blob (header, followed by key value).
    ByteVector key_data(sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + key.size());
    BCRYPT_KEY_DATA_BLOB_HEADER* header = reinterpret_cast<BCRYPT_KEY_DATA_BLOB_HEADER*>(key_data.data());
    header->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    header->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    header->cbKeyData = ULONG(key.size());
    memcpy(key_data.data() + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER), key.data(), key.size());

    // Create a new key handle.
    NTSTATUS status = BCryptImportKey(algo.handle(), nullptr, BCRYPT_KEY_DATA_BLOB, &_handle,
                                      PUCHAR(_key_object.data()), ULONG(_key_object.size()),
                                      PUCHAR(key_data.data()), ULONG(key_data.size()), 0);

    return log.bcrypt(status, "BCryptImportKey");
}

// Set the initialization vector for the next chain of operations.
bool Key::set_iv(Log& log, const ByteVector& iv)
{
    if (iv.size() == _iv_size) {
        _iv = iv;
        return true;
    }
    else {
        log.error("invalid IV size");
        return false;
    }
}

// Encrypt a chunk of data. Plain size must be a multiple of block size, unless pad_final is true.
bool Key::encrypt(Log& log, const ByteVector& plain, ByteVector& cipher, bool pad_final)
{
    if (!pad_final && _block_size != 0 && plain.size() % _block_size != 0) {
        log.debug("encrypt: plain size is not a multiple of the block size");
    }

    cipher.resize(plain.size() + _block_size);
    ULONG retsize = 0;
    NTSTATUS status = BCryptEncrypt(_handle, PUCHAR(plain.data()), ULONG(plain.size()), nullptr,
                                    _iv.empty() ? nullptr : PUCHAR(_iv.data()), ULONG(_iv.size()),
                                    PUCHAR(cipher.data()), ULONG(cipher.size()), &retsize,
                                    pad_final ? BCRYPT_BLOCK_PADDING : 0);
    cipher.resize(std::min<size_t>(cipher.size(), retsize));
    return log.bcrypt(status, "BCryptEncrypt");
}

// Decrypt a chunk of data. Cipher size must be a multiple of block size.
// Pad_final must be set exactly if it was used during production of the last cipher block.
bool Key::decrypt(Log& log, const ByteVector& cipher, ByteVector& plain, bool pad_final)
{
    if (_block_size != 0 && cipher.size() % _block_size != 0) {
        log.debug("decrypt: cipher size is not a multiple of the block size");
    }

    plain.resize(cipher.size());
    ULONG retsize = 0;
    NTSTATUS status = BCryptDecrypt(_handle, PUCHAR(cipher.data()), ULONG(cipher.size()), nullptr,
                                    _iv.empty() ? nullptr : PUCHAR(_iv.data()), ULONG(_iv.size()),
                                    PUCHAR(plain.data()), ULONG(plain.size()), &retsize,
                                    pad_final ? BCRYPT_BLOCK_PADDING : 0);
    plain.resize(std::min<size_t>(plain.size(), retsize));
    return log.bcrypt(status, "BCryptDecrypt");
}

// Free the key resources.
bool Key::close(Log& log)
{
    if (_handle == nullptr) {
        return true;
    }
    else {
        NTSTATUS status = BCryptDestroyKey(_handle);
        _handle = nullptr;
        _key_object.clear();
        return log.bcrypt(status, "BCryptDestroyKey");        
    }
}

// Silently free the key resources.
void Key::close()
{
    if (_handle != nullptr) {
        BCryptDestroyKey(_handle);
        _handle = nullptr;
    }
}

// Destructor.
Key::~Key()
{
    close();
}



#if 0

void one_test_gcm(const char* algo_name, size_t key_bits)
{
    // Open algorithm provider (AES).
    BCRYPT_ALG_HANDLE algo = nullptr;
    check("BCryptOpenAlgorithmProvider",
        BCryptOpenAlgorithmProvider(&algo, BCRYPT_AES_ALGORITHM, nullptr, 0));

    // Set chaining mode.
    const LPCWSTR chain_mode = BCRYPT_CHAIN_MODE_GCM;
    check("BCryptSetProperty(BCRYPT_CHAINING_MODE)",
        BCryptSetProperty(algo, BCRYPT_CHAINING_MODE, PUCHAR(chain_mode), sizeof(chain_mode), 0));

    // Get the size of the "key object" for that algo.
    DWORD objlength = 0;
    ULONG retsize = 0;
    check("BCryptGetProperty(BCRYPT_OBJECT_LENGTH)",
        BCryptGetProperty(algo, BCRYPT_OBJECT_LENGTH, PUCHAR(&objlength), sizeof(objlength), &retsize, 0));

    // Get the block size. Just a test, should be AES block size.
    DWORD block_size = 0;
    check("BCryptGetProperty(BCRYPT_BLOCK_LENGTH)",
        BCryptGetProperty(algo, BCRYPT_BLOCK_LENGTH, PUCHAR(&block_size), sizeof(block_size), &retsize, 0));

    // Get the authentication tag length.
    BCRYPT_AUTH_TAG_LENGTHS_STRUCT tags {0, 0, 0};
    check("BCryptGetProperty(BCRYPT_AUTH_TAG_LENGTH)",
        BCryptGetProperty(algo, BCRYPT_AUTH_TAG_LENGTH, PUCHAR(&tags), sizeof(tags), &retsize, 0));

    ByteVector key(key_bits / 8, 0);
    ByteVector key_object(objlength, 0);
    ByteVector iv(block_size, 0x47);
    ByteVector nonce(GCM_NONCE_SIZE, 0xA4);
    ByteVector auth_tag(tags.dwMinLength, 0x6D);
    ByteVector input(BLOCK_COUNT * block_size, 0xA5);
    ByteVector output(input.size() + block_size, 0);

    // Enforce different bytes in key.
    uint8_t byte = 0x23;
    for (auto& kbyte : key) {
        kbyte = byte++;
    }

    // Build a key data blob (header, followed by key).
    ByteVector key_data(sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + key.size());
    BCRYPT_KEY_DATA_BLOB_HEADER* header = reinterpret_cast<BCRYPT_KEY_DATA_BLOB_HEADER*>(key_data.data());
    header->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    header->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    header->cbKeyData = ULONG(key.size());
    memcpy(key_data.data() + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER), key.data(), key.size());

    // Create a new key handle.
    BCRYPT_KEY_HANDLE hkey = nullptr;
    check("BCryptImportKey",
        BCryptImportKey(algo, nullptr, BCRYPT_KEY_DATA_BLOB, &hkey,
            key_object.data(), ULONG(key_object.size()),
            PUCHAR(key_data.data()), ULONG(key_data.size()), 0));

    // GCM authentication info.
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    ByteVector mac_context(tags.dwMaxLength, 0);
    auth_info.pbNonce = PUCHAR(nonce.data());
    auth_info.cbNonce = ULONG(nonce.size());
    auth_info.pbTag   = PUCHAR(auth_tag.data());
    auth_info.cbTag   = ULONG(auth_tag.size());
    auth_info.pbMacContext = PUCHAR(mac_context.data());
    auth_info.cbMacContext = ULONG(mac_context.size());

    std::cout << "algo: " << algo_name << std::endl;
    std::cout << "key-size: " << key.size() << std::endl;
    std::cout << "iv-size: " << iv.size() << std::endl;
    std::cout << "block-size: " << block_size << std::endl;
    std::cout << "data-size: " << input.size() << std::endl;
    std::cout << "auth-tag-size: min: " << tags.dwMinLength << ", max: " << tags.dwMaxLength << ", incr: " << tags.dwIncrement << std::endl;

    int output_len = 0;
    uint64_t start = 0;
    uint64_t duration = 0;
    uint64_t size = 0;

    // Encryption test.
    size = 0;
    start = cpu_time_usec();
    do {
        auth_info.dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
        for (size_t i = 0; i < INNER_LOOP_COUNT; i++) {
            check("BCryptEncrypt",
                BCryptEncrypt(hkey, PUCHAR(input.data()), ULONG(input.size()), &auth_info,
                    PUCHAR(iv.data()), ULONG(iv.size()),
                    PUCHAR(output.data()), ULONG(output.size()),
                    &retsize, 0));
            size += input.size();
        }
        duration = cpu_time_usec() - start;
    } while (duration < MIN_CPU_TIME);
    // Ignore last block, check performance only.
    std::cout << "encrypt-microsec: " << duration << std::endl;
    std::cout << "encrypt-size: " << size << std::endl;
    std::cout << "encrypt-bitrate: " << ((USECPERSEC * 8 * size) / duration) << std::endl;

    // Decryption test.
    size = 0;
    start = cpu_time_usec();
    do {
        auth_info.dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
        for (size_t i = 0; i < INNER_LOOP_COUNT; i++) {
            check("BCryptDecrypt",
                BCryptDecrypt(hkey, PUCHAR(input.data()), ULONG(input.size()), &auth_info,
                    PUCHAR(iv.data()), ULONG(iv.size()),
                    PUCHAR(output.data()), ULONG(output.size()),
                    &retsize, 0));
            size += input.size();
        }
        duration = cpu_time_usec() - start;
    } while (duration < MIN_CPU_TIME);
    // Ignore last block, check performance only.
    std::cout << "decrypt-microsec: " << duration << std::endl;
    std::cout << "decrypt-size: " << size << std::endl;
    std::cout << "decrypt-bitrate: " << ((USECPERSEC * 8 * size) / duration) << std::endl;

    check("BCryptDestroyKey", BCryptDestroyKey(hkey));
    check("BCryptCloseAlgorithmProvider", BCryptCloseAlgorithmProvider(algo, 0));
}

#endif

//----------------------------------------------------------------------------
// Run test vectors for PBKDF2
//----------------------------------------------------------------------------

void test_pbkdf2(Log& log)
{
    struct test_vector {
        LPCWSTR     hash_algo;
        const char* password;
        const char* salt;
        int         iterations;
        ByteVector  key;
    };

    static const std::vector<test_vector> tests{
        // https://www.rfc-editor.org/rfc/rfc6070
        {
            BCRYPT_SHA1_ALGORITHM, "password", "salt", 2,
            {0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0,
             0xd8, 0xde, 0x89, 0x57}
        },
        {
            BCRYPT_SHA1_ALGORITHM, "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096,
            {0x3D, 0x2E, 0xEC, 0x4F, 0xE4, 0x1C, 0x84, 0x9B, 0x80, 0xC8, 0xD8, 0x36, 0x62, 0xC0, 0xE4, 0x4A,
             0x8B, 0x29, 0x1A, 0x96, 0x4C, 0xF2, 0xF0, 0x70, 0x38}
        },
        // https://github.com/brycx/Test-Vector-Generation/blob/master/PBKDF2/pbkdf2-hmac-sha2-test-vectors.md
        {
            BCRYPT_SHA256_ALGORITHM, "Password", "NaCl", 80000,
            {0x4D, 0xDC, 0xD8, 0xF6, 0x0B, 0x98, 0xBE, 0x21, 0x83, 0x0C, 0xEE, 0x5E, 0xF2, 0x27, 0x01, 0xF9,
             0x64, 0x1A, 0x44, 0x18, 0xD0, 0x4C, 0x04, 0x14, 0xAE, 0xFF, 0x08, 0x87, 0x6B, 0x34, 0xAB, 0x56,
             0xA1, 0xD4, 0x25, 0xA1, 0x22, 0x58, 0x33, 0x54, 0x9A, 0xDB, 0x84, 0x1B, 0x51, 0xC9, 0xB3, 0x17,
             0x6A, 0x27, 0x2B, 0xDE, 0xBB, 0xA1, 0xD0, 0x78, 0x47, 0x8F, 0x62, 0xB3, 0x97, 0xF3, 0x3C, 0x8D,
             0x62, 0xAA, 0xE8, 0x5A, 0x11, 0xCD, 0xDE, 0x82, 0x9D, 0x89, 0xCB, 0x6F, 0xFD, 0x1A, 0xB0, 0xE6,
             0x3A, 0x98, 0x1F, 0x87, 0x47, 0xD2, 0xF2, 0xF9, 0xFE, 0x58, 0x74, 0x16, 0x5C, 0x83, 0xC1, 0x68,
             0xD2, 0xEE, 0xD1, 0xD2, 0xD5, 0xCA, 0x40, 0x52, 0xDE, 0xC2, 0xBE, 0x57, 0x15, 0x62, 0x3D, 0xA0,
             0x19, 0xB8, 0xC0, 0xEC, 0x87, 0xDC, 0x36, 0xAA, 0x75, 0x1C, 0x38, 0xF9, 0x89, 0x3D, 0x15, 0xC3}
        },
        {
            BCRYPT_SHA384_ALGORITHM, "Password", "NaCl", 80000,
            {0x11, 0xC1, 0x98, 0x98, 0x77, 0x30, 0xFA, 0x11, 0x34, 0x58, 0x05, 0x3C, 0xD5, 0xCC, 0x9B, 0x51,
             0xD7, 0x02, 0x4A, 0x35, 0xF9, 0x13, 0x4F, 0x1E, 0xE8, 0x74, 0x09, 0x23, 0xC9, 0x01, 0xAA, 0xB2,
             0x3B, 0xBA, 0xEA, 0x43, 0x68, 0x69, 0x81, 0xB6, 0xE6, 0xA9, 0xF4, 0x13, 0x0A, 0x14, 0x01, 0xDA,
             0xEE, 0xEC, 0x74, 0x06, 0x02, 0x46, 0xEB, 0xAC, 0x95, 0x8F, 0x3C, 0xFC, 0x3C, 0x65, 0x57, 0x9B,
             0x6E, 0x3D, 0x08, 0xB9, 0x4A, 0xDE, 0x5F, 0xC2, 0x57, 0xA6, 0x90, 0x2A, 0x0A, 0x16, 0x64, 0xB8,
             0xDB, 0xD5, 0xA8, 0xAE, 0x2A, 0xF7, 0x04, 0x38, 0x93, 0x1D, 0x3F, 0x36, 0x79, 0xAB, 0xFF, 0xC7,
             0xA1, 0x77, 0x70, 0x58, 0x2F, 0x1E, 0xE4, 0x13, 0xCC, 0x0D, 0x99, 0x14, 0xCE, 0x5F, 0x81, 0x43,
             0xC8, 0xA7, 0xDC, 0x9C, 0x43, 0xFB, 0xC3, 0x1E, 0x3D, 0x41, 0xB2, 0x03, 0x0F, 0xB7, 0x3C, 0x02}
        },
        {
            BCRYPT_SHA512_ALGORITHM, "Password", "NaCl", 80000,
            {0xe6, 0x33, 0x7d, 0x6f, 0xbe, 0xb6, 0x45, 0xc7, 0x94, 0xd4, 0xa9, 0xb5, 0xb7, 0x5b, 0x7b, 0x30,
             0xda, 0xc9, 0xac, 0x50, 0x37, 0x6a, 0x91, 0xdf, 0x1f, 0x44, 0x60, 0xf6, 0x06, 0x0d, 0x5a, 0xdd,
             0xb2, 0xc1, 0xfd, 0x1f, 0x84, 0x40, 0x9a, 0xba, 0xcc, 0x67, 0xde, 0x7e, 0xb4, 0x05, 0x6e, 0x6b,
             0xb0, 0x6c, 0x2d, 0x82, 0xc3, 0xef, 0x4c, 0xcd, 0x1b, 0xde, 0xd0, 0xf6, 0x75, 0xed, 0x97, 0xc6,
             0x5c, 0x33, 0xd3, 0x9f, 0x81, 0x24, 0x84, 0x54, 0x32, 0x7a, 0xa6, 0xd0, 0x3f, 0xd0, 0x49, 0xfc,
             0x5c, 0xbb, 0x2b, 0x5e, 0x6d, 0xac, 0x08, 0xe8, 0xac, 0xe9, 0x96, 0xcd, 0xc9, 0x60, 0xb1, 0xbd,
             0x45, 0x30, 0xb7, 0xe7, 0x54, 0x77, 0x3d, 0x75, 0xf6, 0x7a, 0x73, 0x3f, 0xdb, 0x99, 0xba, 0xf6,
             0x47, 0x0e, 0x42, 0xff, 0xcb, 0x75, 0x3c, 0x15, 0xc3, 0x52, 0xd4, 0x80, 0x0f, 0xb6, 0xf9, 0xd6}
        },
    };

    for (const auto& test : tests) {
        ByteVector key;
        if (pbkdf2(log, key, test.hash_algo, test.password, test.salt, test.iterations, test.key.size())) {
            if (key != test.key) {
                log.error("PBKDF2 test failed, invalid derived key");
            }
        }
    }
}


//----------------------------------------------------------------------------
// Run test vectors for ECB and CBC chaining modes.
//----------------------------------------------------------------------------

void test_ecb_cbc(Log& log)
{
    struct test_vector {
        LPCWSTR    algo;
        LPCWSTR    mode;
        ByteVector key;
        ByteVector iv;
        ByteVector plain;
        ByteVector cipher;
    };

    // Test vectors were generated using openssl command lines and data from /dev/random.
    static const std::vector<test_vector> tests{
        {
            BCRYPT_AES_ALGORITHM, BCRYPT_CHAIN_MODE_ECB,
            {0x7E, 0x85, 0xC1, 0x73, 0x7D, 0xDD, 0xA0, 0x92, 0x41, 0x30, 0xDF, 0xA3, 0xF7, 0x3D, 0x88, 0x13},
            {},
            {0xAC, 0xF3, 0x58, 0xF5, 0x14, 0x67, 0xD5, 0x54, 0xB2, 0x20, 0x20, 0x03, 0x64, 0xC1, 0x09, 0x30,
             0xA7, 0x91, 0x69, 0x5C, 0x2E, 0x78, 0x7C, 0x10, 0xBB, 0xC9, 0xD6, 0xB0, 0x1D, 0x33, 0x27, 0x50,
             0xFB, 0xC1, 0x51, 0xF3, 0xA2, 0xD5, 0xEC, 0xB7, 0x5B, 0xEF, 0x93, 0x68, 0xD3, 0xBB, 0xEF, 0x3D,
             0x4B, 0x4D, 0x89, 0xB5, 0xB5, 0x67, 0xFC, 0xAA, 0x2A, 0x34, 0xCD, 0x2C, 0x8F, 0x96, 0x9B, 0xE0},
            {0x4F, 0x36, 0x7D, 0x8A, 0xAD, 0xFA, 0x7D, 0xF1, 0x1B, 0xFF, 0x80, 0x1C, 0xA4, 0x73, 0x20, 0x66,
             0xC3, 0x61, 0xEA, 0x65, 0x1C, 0x6E, 0x2A, 0xC7, 0x8C, 0x02, 0x62, 0x0B, 0x71, 0x52, 0x7D, 0xF5,
             0x66, 0xA7, 0x45, 0xC5, 0x06, 0xBA, 0xC5, 0xD2, 0x41, 0x82, 0x3E, 0xB2, 0x16, 0xEE, 0xE5, 0xB7,
             0x55, 0xC0, 0xB9, 0x0D, 0xAC, 0xEC, 0x55, 0xD3, 0xE7, 0x71, 0x98, 0x71, 0x32, 0xCB, 0x11, 0x7C},
        },
        {
            BCRYPT_AES_ALGORITHM, BCRYPT_CHAIN_MODE_ECB,
            {0x41, 0x09, 0x45, 0xC5, 0x5C, 0x09, 0x30, 0x18, 0x77, 0x99, 0x54, 0xBC, 0x8F, 0x12, 0xF5, 0xAF,
             0x65, 0x16, 0x7C, 0x32, 0xBD, 0xE4, 0xDA, 0xC3, 0x23, 0x5D, 0x16, 0x84, 0xEF, 0xB6, 0x63, 0x8A},
            {},
            {0xAC, 0xF3, 0x58, 0xF5, 0x14, 0x67, 0xD5, 0x54, 0xB2, 0x20, 0x20, 0x03, 0x64, 0xC1, 0x09, 0x30,
             0xA7, 0x91, 0x69, 0x5C, 0x2E, 0x78, 0x7C, 0x10, 0xBB, 0xC9, 0xD6, 0xB0, 0x1D, 0x33, 0x27, 0x50,
             0xFB, 0xC1, 0x51, 0xF3, 0xA2, 0xD5, 0xEC, 0xB7, 0x5B, 0xEF, 0x93, 0x68, 0xD3, 0xBB, 0xEF, 0x3D,
             0x4B, 0x4D, 0x89, 0xB5, 0xB5, 0x67, 0xFC, 0xAA, 0x2A, 0x34, 0xCD, 0x2C, 0x8F, 0x96, 0x9B, 0xE0},
            {0xDB, 0x10, 0xD1, 0x20, 0x55, 0x42, 0x4A, 0x01, 0x64, 0x00, 0xBC, 0x40, 0xF8, 0xFA, 0x80, 0x24,
             0x5C, 0x81, 0xC2, 0x00, 0x00, 0x5C, 0xE1, 0x39, 0x7E, 0xA8, 0xAE, 0x2E, 0xA6, 0x9B, 0x74, 0x8C,
             0x22, 0x50, 0x04, 0x04, 0x03, 0x9F, 0xBE, 0xBF, 0xED, 0x9E, 0x8D, 0xFC, 0xA4, 0x61, 0x2E, 0x67,
             0xFF, 0x39, 0x5F, 0xD1, 0x97, 0x84, 0xE2, 0x85, 0x4B, 0x30, 0x67, 0xCF, 0xC7, 0xF2, 0xCD, 0xEA},
        },
        {
            BCRYPT_AES_ALGORITHM, BCRYPT_CHAIN_MODE_CBC,
            {0x7E, 0x85, 0xC1, 0x73, 0x7D, 0xDD, 0xA0, 0x92, 0x41, 0x30, 0xDF, 0xA3, 0xF7, 0x3D, 0x88, 0x13},
            {0xF5, 0x64, 0xE3, 0x92, 0xFB, 0x60, 0x39, 0x60, 0xD4, 0x9B, 0x98, 0x95, 0x42, 0xE5, 0x77, 0x56},
            {0xAC, 0xF3, 0x58, 0xF5, 0x14, 0x67, 0xD5, 0x54, 0xB2, 0x20, 0x20, 0x03, 0x64, 0xC1, 0x09, 0x30,
             0xA7, 0x91, 0x69, 0x5C, 0x2E, 0x78, 0x7C, 0x10, 0xBB, 0xC9, 0xD6, 0xB0, 0x1D, 0x33, 0x27, 0x50,
             0xFB, 0xC1, 0x51, 0xF3, 0xA2, 0xD5, 0xEC, 0xB7, 0x5B, 0xEF, 0x93, 0x68, 0xD3, 0xBB, 0xEF, 0x3D,
             0x4B, 0x4D, 0x89, 0xB5, 0xB5, 0x67, 0xFC, 0xAA, 0x2A, 0x34, 0xCD, 0x2C, 0x8F, 0x96, 0x9B, 0xE0},
            {0x7A, 0x9E, 0xB3, 0x5D, 0xD8, 0x6B, 0xC0, 0xBB, 0x40, 0xE2, 0x8C, 0xCE, 0x53, 0x47, 0x5F, 0x42,
             0x92, 0x62, 0x64, 0xA4, 0xE3, 0x4D, 0xBA, 0x24, 0x47, 0xFC, 0x60, 0x37, 0xED, 0x15, 0x85, 0x67,
             0x16, 0x50, 0xCD, 0x28, 0x11, 0xCF, 0xA5, 0x4F, 0x3F, 0x5A, 0xE4, 0x4F, 0x47, 0xFA, 0x80, 0xFD,
             0x4C, 0x74, 0x4F, 0x56, 0x6F, 0x5A, 0x8E, 0xF3, 0xE3, 0x71, 0xCA, 0x15, 0xBD, 0x9C, 0xD8, 0x4B},
        },
        {
            BCRYPT_AES_ALGORITHM, BCRYPT_CHAIN_MODE_CBC,
            {0x41, 0x09, 0x45, 0xC5, 0x5C, 0x09, 0x30, 0x18, 0x77, 0x99, 0x54, 0xBC, 0x8F, 0x12, 0xF5, 0xAF,
             0x65, 0x16, 0x7C, 0x32, 0xBD, 0xE4, 0xDA, 0xC3, 0x23, 0x5D, 0x16, 0x84, 0xEF, 0xB6, 0x63, 0x8A},
            {0xF5, 0x64, 0xE3, 0x92, 0xFB, 0x60, 0x39, 0x60, 0xD4, 0x9B, 0x98, 0x95, 0x42, 0xE5, 0x77, 0x56},
            {0xAC, 0xF3, 0x58, 0xF5, 0x14, 0x67, 0xD5, 0x54, 0xB2, 0x20, 0x20, 0x03, 0x64, 0xC1, 0x09, 0x30,
             0xA7, 0x91, 0x69, 0x5C, 0x2E, 0x78, 0x7C, 0x10, 0xBB, 0xC9, 0xD6, 0xB0, 0x1D, 0x33, 0x27, 0x50,
             0xFB, 0xC1, 0x51, 0xF3, 0xA2, 0xD5, 0xEC, 0xB7, 0x5B, 0xEF, 0x93, 0x68, 0xD3, 0xBB, 0xEF, 0x3D,
             0x4B, 0x4D, 0x89, 0xB5, 0xB5, 0x67, 0xFC, 0xAA, 0x2A, 0x34, 0xCD, 0x2C, 0x8F, 0x96, 0x9B, 0xE0},
            {0xCF, 0x08, 0x6E, 0x9A, 0xFB, 0xB3, 0x19, 0x24, 0x1C, 0x32, 0xE6, 0x2D, 0xD5, 0x9A, 0x99, 0x48,
             0xA9, 0xA5, 0x19, 0x67, 0x8E, 0x85, 0xE4, 0xDE, 0xAA, 0xAD, 0xB5, 0x2A, 0xDC, 0xF0, 0xBE, 0x75,
             0x03, 0x51, 0xE7, 0x96, 0xA7, 0xF2, 0x6A, 0x32, 0x61, 0x7C, 0xF8, 0x03, 0x80, 0x2F, 0x4D, 0x12,
             0x5F, 0x2D, 0xE8, 0x03, 0x71, 0x10, 0x9A, 0xC7, 0x51, 0x38, 0x18, 0x5B, 0xC6, 0x14, 0x12, 0xD6},
        },
    };

    for (const auto& test : tests) {

        Algorithm algo;
        Key key;
        if (!algo.open(log, test.algo, test.mode) || !key.load(log, algo, test.key)) {
            continue;
        }

        // One-pass encryption/decryption.
        ByteVector encrypted;
        if (!key.set_iv(log, test.iv) || !key.encrypt(log, test.plain, encrypted)) {
            continue;
        }
        if (encrypted != test.cipher) {
            log.error("Encryption vector test failed, invalid encrypted data");
        }
        ByteVector decrypted;
        if (!key.set_iv(log, test.iv) || !key.decrypt(log, encrypted, decrypted)) {
            continue;
        }
        if (decrypted != test.plain) {
            log.error("Decryption vector test failed, invalid encrypted data");
        }
    }
}


//----------------------------------------------------------------------------
// Application entry point
//----------------------------------------------------------------------------

int main(int argc, char* argv[])
{
    Log log(argc, argv);

    test_pbkdf2(log);
    test_ecb_cbc(log);

    return log.exit_code();
}
