// Should be reviewed

#include "utils.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <stdexcept>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <sys/random.h>
#endif

namespace vhsm::utils {

// ===========================================================================
// UUID v4
// ===========================================================================

namespace {
// Pseudo Random Number Generator 
// Simple implementation
void csprng_fill(std::span<std::byte> buf) {
#ifdef _WIN32
    const NTSTATUS s = ::BCryptGenRandom(
        nullptr,
        reinterpret_cast<PUCHAR>(buf.data()),
        static_cast<ULONG>(buf.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(s))
        throw std::runtime_error("BCryptGenRandom failed");
#else
    const ssize_t n = ::getrandom(buf.data(), buf.size(), 0);
    if (n < 0 || static_cast<std::size_t>(n) != buf.size())
        throw std::runtime_error("getrandom failed");
#endif
}

} // namespace

std::string uuid_v4() {
    std::array<std::byte, 16> rnd{};
    csprng_fill(rnd);

    // RFC 4122 §4.4 — set version and variant bits.
    rnd[6] = static_cast<std::byte>((static_cast<uint8_t>(rnd[6]) & 0x0f) | 0x40); // version 4
    rnd[8] = static_cast<std::byte>((static_cast<uint8_t>(rnd[8]) & 0x3f) | 0x80); // variant 10xx

    char buf[37];
    const auto* b = reinterpret_cast<const uint8_t*>(rnd.data());
    std::snprintf(buf, sizeof(buf),
        "%02x%02x%02x%02x-"
        "%02x%02x-"
        "%02x%02x-"
        "%02x%02x-"
        "%02x%02x%02x%02x%02x%02x",
        b[0],  b[1],  b[2],  b[3],
        b[4],  b[5],
        b[6],  b[7],
        b[8],  b[9],
        b[10], b[11], b[12], b[13], b[14], b[15]);
    return buf;
}

// Base64
static constexpr std::string_view kB64Chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(std::span<const std::byte> data) {
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);

    for (std::size_t i = 0; i < data.size(); i += 3) {
        const auto b0 = static_cast<uint8_t>(data[i]);
        const auto b1 = (i + 1 < data.size()) ? static_cast<uint8_t>(data[i + 1]) : 0u;
        const auto b2 = (i + 2 < data.size()) ? static_cast<uint8_t>(data[i + 2]) : 0u;

        out += kB64Chars[ b0 >> 2];
        out += kB64Chars[(b0 & 0x03) << 4 | b1 >> 4];
        out += (i + 1 < data.size()) ? kB64Chars[(b1 & 0x0f) << 2 | b2 >> 6] : '=';
        out += (i + 2 < data.size()) ? kB64Chars[ b2 & 0x3f] : '=';
    }
    return out;
}

// 0xFF = invalid character, 0xFE = padding ('=')
static constexpr auto make_b64_decode_table() {
    std::array<uint8_t, 256> t{};
    t.fill(0xFF);
    for (uint8_t i = 0; i < 64; ++i) {
        t[static_cast<uint8_t>(kB64Chars[i])] = i;
    }
    t[static_cast<uint8_t>('=')] = 0xFE;
    return t;
}

static constexpr auto kB64Decode = make_b64_decode_table();

std::optional<std::vector<std::byte>> base64_decode(std::string_view s) {
    if (s.size() % 4 != 0) return std::nullopt;

    std::vector<std::byte> out;
    out.reserve((s.size() / 4) * 3);

    for (std::size_t i = 0; i < s.size(); i += 4) {
        const uint8_t c0 = kB64Decode[static_cast<uint8_t>(s[i])];
        const uint8_t c1 = kB64Decode[static_cast<uint8_t>(s[i + 1])];
        const uint8_t c2 = kB64Decode[static_cast<uint8_t>(s[i + 2])];
        const uint8_t c3 = kB64Decode[static_cast<uint8_t>(s[i + 3])];

        if (c0 == 0xFF || c0 == 0xFE) return std::nullopt; // c0 must be a real digit
        if (c1 == 0xFF || c1 == 0xFE) return std::nullopt; // c1 must be a real digit
        if (c2 == 0xFF || c3 == 0xFF) return std::nullopt; // invalid character

        const bool pad2 = (c2 == 0xFE);                    // "xx==" — 1 output byte
        const bool pad1 = (c3 == 0xFE);                    // "xxx=" — 2 output bytes

        if (pad2 && !pad1)                    return std::nullopt; // "xx=x" is invalid
        if ((pad2 || pad1) && i + 4 != s.size()) return std::nullopt; // padding mid-string

        out.push_back(static_cast<std::byte>( (c0 << 2)         | (c1 >> 4)));
        if (!pad2) out.push_back(static_cast<std::byte>((c1 << 4) | (c2 >> 2)));
        if (!pad2 && !pad1) out.push_back(static_cast<std::byte>((c2 << 6) | c3));
    }
    return out;
}

// Hex
static constexpr std::string_view kHexChars = "0123456789abcdef";

std::string hex_encode(std::span<const std::byte> data) {
    std::string out;
    out.resize(data.size() * 2);
    for (std::size_t i = 0; i < data.size(); ++i) {
        const auto b   = static_cast<uint8_t>(data[i]);
        out[i * 2]     = kHexChars[b >> 4];
        out[i * 2 + 1] = kHexChars[b & 0x0f];
    }
    return out;
}

static constexpr uint8_t hex_val(char c) noexcept {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    return 0xFF;
}

std::optional<std::vector<std::byte>> hex_decode(std::string_view s) {
    if (s.size() % 2 != 0) return std::nullopt;

    std::vector<std::byte> out;
    out.reserve(s.size() / 2);

    for (std::size_t i = 0; i < s.size(); i += 2) {
        const uint8_t hi = hex_val(s[i]);
        const uint8_t lo = hex_val(s[i + 1]);
        if (hi == 0xFF || lo == 0xFF) return std::nullopt;
        out.push_back(static_cast<std::byte>((hi << 4) | lo));
    }
    return out;
}

} // namespace vhsm::utils