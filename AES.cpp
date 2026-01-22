
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//
// =================================================================================
// MIT License
//
// Copyright (c) 2026 oiko-nomikos
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// =================================================================================
//
// IMPORTANT SECURITY & LEGAL NOTICES
//
// This program contains independent, from-scratch re-implementations of the
// following cryptographic algorithms, based solely on their public specifications:
//
//   • AES (Advanced Encryption Standard) — NIST FIPS 197
//   • SHA-256                            — NIST FIPS 180-4
//   • HMAC                               — NIST FIPS 198
//   • PBKDF                              — NIST SP 800-132
//
// No third-party copyrighted code is included for these primitives.
// They are educational/reference implementations only.
//
// All other parts of this program — including:
//
//   • PBKDF-style key derivation (HKDF-like construction)
//   • Timing-based entropy collection & randomness pool
//   • HMAC wrapper logic
//   • File encryption/decryption wrapper
//   • Command-line interface & I/O
//
//   — are original work by oiko-nomikos.
//
// CRITICAL WARNING:
// ---------------------------------------------------------------------------------
// THIS IS NOT PRODUCTION-GRADE CRYPTOGRAPHY.
// These implementations have NOT been audited, formally verified, side-channel
// protected, or tested against real-world attacks.
// Using this code for anything security-sensitive (real passwords, real data,
// financial information, etc.) is extremely dangerous and strongly discouraged.
//
// Use only for learning, experimentation, or CTF-style challenges.
// For anything important, use well-audited libraries such as:
//   OpenSSL, libsodium, cryptography (Python), Bouncy Castle, etc.
//
// If you find a bug or weakness — please report it responsibly.
// ---------------------------------------------------------------------------------
//
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

#include <vector>
#include <string>
#include <cstring>
#include <sstream>
#include <cstdint>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <deque>
#include <mutex>
#include <chrono>
#include <fstream>
#include <limits>
#include <filesystem>
#include <stdexcept>

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

namespace fs = std::filesystem;
const fs::path APP_DIR = "program_data";

void ensureAppDirectory() {
    if (!fs::exists(APP_DIR)) {
        fs::create_directory(APP_DIR);
    }
}

const fs::path file_1 = APP_DIR / "btc_history.txt";
const fs::path file_2 = APP_DIR / "open_positions.txt";
const fs::path file_3 = APP_DIR / "calendar_pnl.txt";
const fs::path file_4 = APP_DIR / "twitter_config.txt";
const fs::path file_5 = APP_DIR / "debug_file.log";

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class SystemClock {
  public:
    inline long long getSeconds() {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    }

    inline long long getMilliseconds() {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    }

    inline long long getMicroseconds() {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    }

    inline long long getNanoseconds() {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
    }
};

// Global Instance
SystemClock systemClock;

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

namespace CRYPTO {
class SHA256 {
  public:
    SHA256() { reset(); }

    void update(const uint8_t *data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            buffer[bufferLen++] = data[i];
            if (bufferLen == 64) {
                transform(buffer);
                bitlen += 512;
                bufferLen = 0;
            }
        }
    }

    void update(const std::string &data) { update(reinterpret_cast<const uint8_t *>(data.c_str()), data.size()); }

    std::string digest() {
        uint64_t totalBits = bitlen + bufferLen * 8;

        buffer[bufferLen++] = 0x80;
        if (bufferLen > 56) {
            while (bufferLen < 64)
                buffer[bufferLen++] = 0x00;
            transform(buffer);
            bufferLen = 0;
        }

        while (bufferLen < 56)
            buffer[bufferLen++] = 0x00;

        for (int i = 7; i >= 0; --i)
            buffer[bufferLen++] = (totalBits >> (i * 8)) & 0xFF;

        transform(buffer);

        std::ostringstream oss;
        for (int i = 0; i < 8; ++i)
            oss << std::hex << std::setw(8) << std::setfill('0') << h[i];

        reset(); // reset internal state after digest
        return oss.str();
    }

    std::string digestBinary() {
        std::string hex = digest();
        std::string binary;
        for (char c : hex) {
            uint8_t val = (c <= '9') ? c - '0' : 10 + (std::tolower(c) - 'a');
            for (int i = 3; i >= 0; --i)
                binary += ((val >> i) & 1) ? '1' : '0';
        }
        return binary;
    }

    void reset() {
        h[0] = 0x6a09e667;
        h[1] = 0xbb67ae85;
        h[2] = 0x3c6ef372;
        h[3] = 0xa54ff53a;
        h[4] = 0x510e527f;
        h[5] = 0x9b05688c;
        h[6] = 0x1f83d9ab;
        h[7] = 0x5be0cd19;
        bitlen = 0;
        bufferLen = 0;
    }

  private:
    uint32_t h[8];
    uint64_t bitlen;
    uint8_t buffer[64];
    size_t bufferLen;

    void transform(const uint8_t block[64]) {
        uint32_t w[64];

        for (int i = 0; i < 16; ++i) {
            w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | (block[i * 4 + 3]);
        }

        for (int i = 16; i < 64; ++i) {
            w[i] = theta1(w[i - 2]) + w[i - 7] + theta0(w[i - 15]) + w[i - 16];
        }

        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];
        uint32_t f = h[5];
        uint32_t g = h[6];
        uint32_t h_val = h[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t temp1 = h_val + sig1(e) + choose(e, f, g) + K[i] + w[i];
            uint32_t temp2 = sig0(a) + majority(a, b, c);
            h_val = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += h_val;
    }

    static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    static uint32_t choose(uint32_t e, uint32_t f, uint32_t g) { return (e & f) ^ (~e & g); }
    static uint32_t majority(uint32_t a, uint32_t b, uint32_t c) { return (a & b) ^ (a & c) ^ (b & c); }
    static uint32_t sig0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    static uint32_t sig1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    static uint32_t theta0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    static uint32_t theta1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    const uint32_t K[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
                            0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
                            0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
                            0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
                            0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
};
} // namespace CRYPTO

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class RandomNumberGenerator {
  public:
    inline std::string run() {
        std::string result;
        result.reserve((totalIterations - localBufferSize) * 256);

        for (int i = 0; i < totalIterations; ++i) {

            long long duration = countdown();
            ++count;
            globalSum += duration;
            globalAvg = globalSum / count;

            int bit = duration < globalAvg ? 0 : 1;

            if (localBits.size() >= localBufferSize)
                localBits.pop_front();

            localBits.push_back(bit);

            if (localBits.size() == localBufferSize) {
                // 32 raw bytes → 256 bit string
                std::string hashBits = hashLocalBits();
                result += hashBits;
            }
        }

        return result;
    }

  private:
    CRYPTO::SHA256 sha;
    std::deque<int> localBits;
    const int totalIterations = 1000;
    const size_t localBufferSize = 512;
    long long globalSum = 0;
    long long globalAvg = 0;
    int count = 0;

    inline long long countdown() {
        int x = 10;
        auto start = systemClock.getNanoseconds();
        while (x > 0)
            x--;
        auto end = systemClock.getNanoseconds();
        return end - start;
    }

    inline std::string hashLocalBits() {
        // Build 64-byte block
        uint8_t bytes[64] = {0};
        for (size_t i = 0; i < localBits.size(); ++i) {
            if (localBits[i]) {
                bytes[i / 8] |= (1 << (7 - (i % 8)));
            }
        }

        sha.update(bytes, 64);

        // Return 256-bit binary string using fast helper
        return sha.digestBinary();
    }
};

inline std::string sha256Binary(const std::string &data) {
    CRYPTO::SHA256 sha;
    sha.update(data);
    return sha.digestBinary(); // directly returns 256-bit binary string
}

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class BinaryEntropyPool {
  public:
    inline std::string get(size_t bitsNeeded) {
        std::lock_guard<std::mutex> lock(poolMutex);

        // Refill the pool until we have enough bits
        while (bitPool.size() < bitsNeeded) {
            bitPool += rng.run(); // rng.run() now returns a bit string
        }

        // Extract exactly the number of bits requested
        std::string result = bitPool.substr(0, bitsNeeded);
        bitPool.erase(0, bitsNeeded); // remove consumed bits

        return result;
    }

  private:
    std::string bitPool; // bit string directly
    RandomNumberGenerator rng;
    mutable std::mutex poolMutex;
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class HMAC {
  public:
    static std::string compute(const std::string &key, const std::string &message) {
        // Step 1: Normalize key to 64 bytes
        std::string K = normalizeKey(key);

        // Step 2: Create inner and outer padded keys
        std::string ipad(BLOCK_SIZE, 0x36);
        std::string opad(BLOCK_SIZE, 0x5c);

        for (size_t i = 0; i < BLOCK_SIZE; ++i) {
            ipad[i] ^= K[i];
            opad[i] ^= K[i];
        }

        // Step 3: Inner hash
        std::string inner = sha256Binary(ipad + message);

        // Step 4: Outer hash
        return sha256Binary(opad + inner);
    }

  private:
    static constexpr size_t BLOCK_SIZE = 64; // SHA-256 block size
    static constexpr size_t HASH_SIZE = 32;  // SHA-256 output size

    static std::string normalizeKey(const std::string &key) {
        if (key.size() > BLOCK_SIZE) {
            return sha256Binary(key);
        }

        std::string out = key;
        out.resize(BLOCK_SIZE, 0x00);
        return out;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class KeyDerivation {
  public:
    struct DerivedKey {
        std::vector<uint8_t> salt; // 16 bytes
        std::string key;           // 32 bytes of binary data (for AES-256)
    };

    DerivedKey deriveKey() {
        DerivedKey out{};

        std::string password = getPassword();
        std::cout << "Password created, generating salt...\n\n";

        out.salt = generateSalt(); // now returns vector<uint8_t>

        // Convert binary salt → string for HMAC (zero-cost view in real code, copy here for simplicity)
        std::string salt_str(reinterpret_cast<const char *>(out.salt.data()), out.salt.size());

        std::string U = HMAC::compute(password, salt_str);
        std::string T = U;

        for (uint32_t i = 1; i < ITERATIONS; ++i) {
            U = HMAC::compute(password, U);
            xorInPlace(T, U);
        }

        out.key = T;

        wipeString(password);
        wipeString(U);

        return out;
    }

    DerivedKey deriveKeyFromPassword(const std::string &password, const std::vector<uint8_t> &salt) {
        DerivedKey out{};
        out.salt = salt;

        std::string salt_str(reinterpret_cast<const char *>(salt.data()), salt.size());

        std::string U = HMAC::compute(password, salt_str);
        std::string T = U;

        for (uint32_t i = 1; i < ITERATIONS; ++i) {
            U = HMAC::compute(password, U);
            xorInPlace(T, U);
        }

        out.key = T;

        return out;
    }

    // Convert bit string "101010..." → 16 actual bytes
    std::vector<uint8_t> bitStringToBytes(const std::string &bits, size_t wanted_bytes) {
        if (bits.size() < wanted_bytes * 8) {
            throw std::runtime_error("Not enough bits for requested byte length");
        }
        std::vector<uint8_t> result(wanted_bytes, 0);
        for (size_t i = 0; i < wanted_bytes * 8; ++i) {
            if (bits[i] == '1') {
                size_t byte_idx = i / 8;
                int bit_pos = 7 - static_cast<int>(i % 8); // MSB first
                result[byte_idx] |= (1u << bit_pos);
            }
        }
        return result;
    }

  private:
    static constexpr uint32_t ITERATIONS = 100'000;
    static constexpr size_t SALT_BYTES = 16;

    std::string getPassword() {
        std::string password;
        std::cout << "Enter password: ";
        std::cin >> password;
        return password;
    }

    std::vector<uint8_t> generateSalt() {
        BinaryEntropyPool bep;
        std::string bitString = bep.get(SALT_BYTES * 8); // get 128 bits as "1010..."
        return bitStringToBytes(bitString, SALT_BYTES);
    }

    void xorInPlace(std::string &a, const std::string &b) {
        if (a.size() != b.size()) {
            throw std::runtime_error("XOR size mismatch");
        }
        for (size_t i = 0; i < a.size(); ++i) {
            a[i] ^= b[i];
        }
    }

    void wipeString(std::string &s) {
        if (!s.empty()) {
            wipeWithEntropy(s.data(), s.size());
            s.clear();
            s.shrink_to_fit();
        }
    }

    void wipeWithEntropy(void *ptr, size_t len) {
        BinaryEntropyPool bep;
        std::string entropy = bep.get(len * 8);

        volatile uint8_t *p = static_cast<volatile uint8_t *>(ptr);
        for (size_t i = 0; i < len; ++i) {
            p[i] = static_cast<uint8_t>(entropy[i]);
        }
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class AES {
  public:
    using byte = uint8_t;

    // ===== Public CBC entry points =====
    std::vector<byte> encryptCBC128(const std::vector<byte> &plaintext, const byte key[16], const byte iv[16]) { return encryptCBC(plaintext, key, 4, 10, iv); }
    std::vector<byte> encryptCBC192(const std::vector<byte> &plaintext, const byte key[24], const byte iv[16]) { return encryptCBC(plaintext, key, 6, 12, iv); }
    std::vector<byte> encryptCBC256(const std::vector<byte> &plaintext, const byte key[32], const byte iv[16]) { return encryptCBC(plaintext, key, 8, 14, iv); }

    std::vector<byte> decryptCBC128(const std::vector<byte> &plaintext, const byte key[16], const byte iv[16]) { return decryptCBC(plaintext, key, 4, 10, iv); }
    std::vector<byte> decryptCBC192(const std::vector<byte> &plaintext, const byte key[24], const byte iv[16]) { return decryptCBC(plaintext, key, 6, 12, iv); }
    std::vector<byte> decryptCBC256(const std::vector<byte> &plaintext, const byte key[32], const byte iv[16]) { return decryptCBC(plaintext, key, 8, 14, iv); }

    // Generate random IV (16 bytes) using entropy pool
    std::array<AES::byte, 16> generateIV(BinaryEntropyPool &bep) {
        std::string ivBits = bep.get(128); // 128 bits = 16 bytes
        std::vector<uint8_t> ivBytes = kd.bitStringToBytes(ivBits, 16);
        std::array<AES::byte, 16> iv{};
        std::copy(ivBytes.begin(), ivBytes.end(), iv.begin());
        return iv;
    }

  private:
    KeyDerivation kd;
    static constexpr int BLOCK_SIZE = 16;

    // ===== Core AES operations =====
    byte gmul(byte a, byte b) {
        // std::cout << "doing gmul...\n";
        byte p = 0;
        while (b) {
            if (b & 1)
                p ^= a;
            a = (a << 1) ^ ((a & 0x80) ? 0x1B : 0);
            b >>= 1;
        }
        return p;
    }

    void AddRoundKey(byte *s, const byte *rk) {
        std::cout << "doing AddRoundKey...\n";
        for (int i = 0; i < 16; i++)
            s[i] ^= rk[i];
    }

    void SubBytes(byte *s) {
        std::cout << "doing SubBytes...\n";
        for (int i = 0; i < 16; i++)
            s[i] = sbox[s[i]];
    }

    void InvSubBytes(byte *s) {
        std::cout << "doing InvSubBytes...\n";
        for (int i = 0; i < 16; i++)
            s[i] = inv_sbox[s[i]];
    }

    void ShiftRows(byte *s) {
        std::cout << "doing ShiftRows...\n";
        byte t[16];
        memcpy(t, s, 16);

        // Row 0 (no shift)
        s[0] = t[0];
        s[4] = t[4];
        s[8] = t[8];
        s[12] = t[12];

        // Row 1 (left shift by 1)
        s[1] = t[5];
        s[5] = t[9];
        s[9] = t[13];
        s[13] = t[1];

        // Row 2 (left shift by 2)
        s[2] = t[10];
        s[6] = t[14];
        s[10] = t[2];
        s[14] = t[6];

        // Row 3 (left shift by 3)
        s[3] = t[15];
        s[7] = t[3];
        s[11] = t[7];
        s[15] = t[11];
    }

    void InvShiftRows(byte *s) {
        std::cout << "doing InvShiftRows...\n";
        byte t[16];
        memcpy(t, s, 16);

        // Row 0 (unchanged)
        s[0] = t[0];
        s[4] = t[4];
        s[8] = t[8];
        s[12] = t[12];

        // Row 1 (right shift by 1)
        s[1] = t[13];
        s[5] = t[1];
        s[9] = t[5];
        s[13] = t[9];

        // Row 2 (right shift by 2)
        s[2] = t[10];
        s[6] = t[14];
        s[10] = t[2];
        s[14] = t[6];

        // Row 3 (right shift by 3)
        s[3] = t[7];
        s[7] = t[11];
        s[11] = t[15];
        s[15] = t[3];
    }

    void MixColumns(byte *s) {
        for (int c = 0; c < 4; c++) {
            int i = c * 4;
            byte a = s[i];
            byte b = s[i + 1];
            byte c_ = s[i + 2];
            byte d = s[i + 3];

            s[i] = gmul(a, 2) ^ gmul(b, 3) ^ c_ ^ d;
            s[i + 1] = a ^ gmul(b, 2) ^ gmul(c_, 3) ^ d;
            s[i + 2] = a ^ b ^ gmul(c_, 2) ^ gmul(d, 3);
            s[i + 3] = gmul(a, 3) ^ b ^ c_ ^ gmul(d, 2);
        }
    }

    void InvMixColumns(byte *s) {
        for (int c = 0; c < 4; c++) {
            int i = c * 4;
            byte a = s[i];
            byte b = s[i + 1];
            byte c_ = s[i + 2];
            byte d = s[i + 3];

            s[i] = gmul(a, 0x0e) ^ gmul(b, 0x0b) ^ gmul(c_, 0x0d) ^ gmul(d, 0x09);
            s[i + 1] = gmul(a, 0x09) ^ gmul(b, 0x0e) ^ gmul(c_, 0x0b) ^ gmul(d, 0x0d);
            s[i + 2] = gmul(a, 0x0d) ^ gmul(b, 0x09) ^ gmul(c_, 0x0e) ^ gmul(d, 0x0b);
            s[i + 3] = gmul(a, 0x0b) ^ gmul(b, 0x0d) ^ gmul(c_, 0x09) ^ gmul(d, 0x0e);
        }
    }

    // ===== Key expansion (generic) =====
    void KeyExpansion(const byte *key, int Nk, int Nr, byte *roundKeys) {
        std::cout << "doing KeyExpansion...\n";
        constexpr int Nb = 4;
        int totalWords = Nb * (Nr + 1);

        memcpy(roundKeys, key, Nk * 4);

        byte temp[4];

        for (int i = Nk; i < totalWords; i++) {
            memcpy(temp, &roundKeys[4 * (i - 1)], 4);

            if (i % Nk == 0) {
                byte t = temp[0];
                temp[0] = sbox[temp[1]] ^ Rcon[i / Nk];
                temp[1] = sbox[temp[2]];
                temp[2] = sbox[temp[3]];
                temp[3] = sbox[t];
            } else if (Nk > 6 && i % Nk == 4) {
                for (int j = 0; j < 4; j++)
                    temp[j] = sbox[temp[j]];
            }

            for (int j = 0; j < 4; j++)
                roundKeys[4 * i + j] = roundKeys[4 * (i - Nk) + j] ^ temp[j];
        }
    }

    // ===== Block encryption (generic) =====
    void EncryptBlock(byte *block, const byte *rk, int Nr) {
        std::cout << "doing EncryptBlock...\n";
        AddRoundKey(block, rk);

        for (int r = 1; r < Nr; r++) {
            SubBytes(block);
            ShiftRows(block);
            MixColumns(block);
            AddRoundKey(block, rk + 16 * r);
        }

        SubBytes(block);
        ShiftRows(block);
        AddRoundKey(block, rk + 16 * Nr);
    }

    void DecryptBlock(byte *block, const byte *rk, int Nr) {
        std::cout << "doing DecryptBlock...\n";
        AddRoundKey(block, rk + 16 * Nr);
        for (int r = Nr - 1; r >= 1; r--) {
            InvShiftRows(block);
            InvSubBytes(block);
            AddRoundKey(block, rk + 16 * r);
            InvMixColumns(block);
        }
        InvShiftRows(block);
        InvSubBytes(block);
        AddRoundKey(block, rk);
    }

    // ===== CBC mode (generic) =====
    std::vector<byte> encryptCBC(const std::vector<byte> &plaintext, const byte *key, int Nk, int Nr, const byte iv[16]) {
        std::cout << "doing encryptCBC...\n";
        byte roundKeys[240];
        KeyExpansion(key, Nk, Nr, roundKeys);

        std::vector<byte> data = pkcs7_pad(plaintext);
        std::vector<byte> out(data.size());

        byte prev[16];
        memcpy(prev, iv, 16);

        for (size_t i = 0; i < data.size(); i += 16) {
            byte block[16];
            for (int j = 0; j < 16; j++)
                block[j] = data[i + j] ^ prev[j];

            EncryptBlock(block, roundKeys, Nr);
            memcpy(&out[i], block, 16);
            memcpy(prev, block, 16);
        }

        return out;
    }

    std::vector<byte> decryptCBC(const std::vector<byte> &ciphertext, const byte *key, int Nk, int Nr, const byte iv[16]) {
        std::cout << "doing decryptCBC...\n";
        byte roundKeys[240];
        KeyExpansion(key, Nk, Nr, roundKeys);

        if (ciphertext.size() % 16 != 0)
            throw std::runtime_error("Ciphertext not multiple of 16 bytes");

        std::vector<byte> out(ciphertext.size());
        byte prev[16];
        memcpy(prev, iv, 16);

        for (size_t i = 0; i < ciphertext.size(); i += 16) {
            byte block[16];
            memcpy(block, &ciphertext[i], 16);

            DecryptBlock(block, roundKeys, Nr);

            // XOR with previous ciphertext (or IV)
            for (int j = 0; j < 16; j++)
                block[j] ^= prev[j];

            memcpy(&out[i], block, 16);
            memcpy(prev, &ciphertext[i], 16);
        }

        // Remove PKCS#7 padding
        pkcs7_unpad(out);

        return out;
    }

    // ===== PKCS#7 Padding =====
    std::vector<byte> pkcs7_pad(const std::vector<byte> &in) {
        std::cout << "doing pkcs7_pad...\n";
        size_t pad = BLOCK_SIZE - (in.size() % BLOCK_SIZE);
        if (pad == 0)
            pad = BLOCK_SIZE;

        std::vector<byte> out = in;
        out.insert(out.end(), pad, static_cast<byte>(pad));
        return out;
    }

    // ===== PKCS#7 Unpadding =====
    void pkcs7_unpad(std::vector<byte> &data) {
        std::cout << "doing pkcs7_unpad...\n";
        if (data.empty() || data.size() % BLOCK_SIZE != 0)
            throw std::runtime_error("Invalid padded data size");

        byte pad = data.back();
        if (pad < 1 || pad > BLOCK_SIZE)
            throw std::runtime_error("Invalid PKCS#7 padding");

        for (size_t i = 0; i < pad; i++) {
            if (data[data.size() - 1 - i] != pad)
                throw std::runtime_error("Invalid PKCS#7 padding");
        }

        data.resize(data.size() - pad);
    }

    static inline constexpr byte inv_sbox[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e,
        0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66,
        0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65,
        0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
        0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91,
        0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
        0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2,
        0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb,
        0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

    // === Constants ===
    static inline constexpr byte sbox[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4,
        0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3,
        0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3,
        0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
        0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c,
        0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
        0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
        0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
        0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

    static inline constexpr byte Rcon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class FileStorage {
  public:
    void encryptAppFiles() {
        // --- Derive New key ---
        std::cout << "Creating new key for AES encryption\n\n";
        KeyDerivation kd;
        KeyDerivation::DerivedKey dk = kd.deriveKey(); // dk.key (32 bytes), dk.salt (16 bytes)
        std::cout << "Using derived key for AES encryption\n\n";

        // --- Prepare AES key (256-bit) ---
        uint8_t aesKey[32];
        memcpy(aesKey, dk.key.data(), 32);

        // --- Wait for Enter ---
        std::cout << "\nPress Enter to continue...";
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cin.get();

        std::vector<fs::path> files = {file_1, file_2, file_3, file_4, file_5};

        for (const auto &srcPath : files) {
            if (!fs::exists(srcPath)) {
                std::cout << "Skipping missing file: " << srcPath << "\n";
                continue;
            }

            auto plaintext = readFile(srcPath);
            auto iv = aes.generateIV(bep);

            uint8_t key[32];
            std::copy(dk.key.begin(), dk.key.end(), key);

            auto ciphertext = aes.encryptCBC256(plaintext, key, iv.data());

            // Save format: salt (16) + iv (16) + ciphertext
            fs::path encPath = srcPath.string() + ".enc";
            std::ofstream out(encPath, std::ios::binary);
            out.write(reinterpret_cast<const char *>(dk.salt.data()), dk.salt.size());
            out.write(reinterpret_cast<const char *>(iv.data()), 16);
            out.write(reinterpret_cast<const char *>(ciphertext.data()), ciphertext.size());

            std::cout << "Encrypted: " << srcPath << " → " << encPath << "\n";
        }
    }

    void decryptAppFiles() {
        std::vector<fs::path> encFiles;
        for (const auto &entry : fs::directory_iterator(APP_DIR)) {
            if (entry.path().extension() == ".enc") {
                encFiles.push_back(entry.path());
            }
        }

        if (encFiles.empty()) {
            std::cout << "No encrypted files found.\n";
            return;
        }

        std::string password;
        std::cout << "Enter password: ";
        std::getline(std::cin, password);

        for (const auto &encPath : encFiles) {
            std::ifstream in(encPath, std::ios::binary);
            if (!in) {
                std::cout << "Failed to open: " << encPath << "\n";
                continue;
            }

            // --- Read salt ---
            std::vector<uint8_t> salt(16);
            in.read(reinterpret_cast<char *>(salt.data()), 16);

            // --- Read IV ---
            std::array<uint8_t, 16> iv{};
            in.read(reinterpret_cast<char *>(iv.data()), 16);

            // --- Read ciphertext ---
            std::vector<uint8_t> ciphertext((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

            // --- Derive key ---
            auto dk = kd.deriveKeyFromPassword(password, salt);

            uint8_t key[32];
            std::copy(dk.key.begin(), dk.key.end(), key);

            // --- Decrypt ---
            auto plaintextBytes = aes.decryptCBC256(ciphertext, key, iv.data());

            fs::path origPath = encPath;
            origPath.replace_extension("");
            writeFile(origPath, plaintextBytes);

            std::cout << "Decrypted: " << encPath << " → " << origPath << "\n";
        }
    }

  private:
    KeyDerivation kd;
    AES aes;
    BinaryEntropyPool bep;

    // Helper: read entire file into vector<byte>
    std::vector<AES::byte> readFile(const fs::path &path) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file)
            throw std::runtime_error("Cannot open file: " + path.string());

        auto size = file.tellg();
        std::vector<AES::byte> buffer(size);

        file.seekg(0, std::ios::beg);
        file.read(reinterpret_cast<char *>(buffer.data()), size);
        return buffer;
    }

    // Helper: write vector<byte> to file
    void writeFile(const fs::path &path, const std::vector<AES::byte> &data) {
        std::ofstream file(path, std::ios::binary);
        if (!file)
            throw std::runtime_error("Cannot write file: " + path.string());

        file.write(reinterpret_cast<const char *>(data.data()), data.size());
    }
};

int main() {
    ensureAppDirectory(); // Create program_data if missing

    FileStorage storage;
    storage.encryptAppFiles();
    storage.decryptAppFiles();

    std::cout << "\nPress Enter to exit...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();

    return 0;
}
