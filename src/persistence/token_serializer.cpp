#include "token_serializer.h"

#include <cstring>
#include <stdexcept>

#include "../core/error.h"

// Serialization layout (all multi-byte integers little-endian):
//
//   u32  magic  = 0x5648534D ("VHSM")
//   u32  version = 1
//   u8   label len            -> u8[len] label
//   u8   id len               -> u8[len] id
//   u64  max_session_count
//   u64  session_count
//   u64  max_rw_session_count
//   u64  rw_session_count
//   u8   flags bitmask        (token_initialized, user_pin_set, so_pin_set,
//                              user_login_required, so_login_required,
//                              user_pin_locked, so_pin_locked)
//   u32  max_failed_attempts
//   u32  user_failed_attempts
//   u32  so_failed_attempts
//   u64  kek len              -> u8[len] kek
//
// Lengths are stored as u8 for label/id (they are short strings, max 255),
// u64 for kek (arbitrary bytes).  Booleans are packed into one flags octet to
// keep the record compact on disk.

namespace {

using std::uint8_t;

enum : uint8_t {
    KTokenInit      = 1 << 0,
    KUserPinSet     = 1 << 1,
    KSoPinSet       = 1 << 2,
    KUserLoginReq   = 1 << 3,
    KSoLoginReq     = 1 << 4,
    KUserPinLocked  = 1 << 5,
    KSoPinLocked    = 1 << 6,
};

constexpr std::uint32_t KMagic   = 0x5648534DU; // "VHSM"
constexpr std::uint32_t KVersion = 1;

void put_le32(std::vector<u8>& out, std::uint32_t v) {
    out.push_back(static_cast<u8>(v & 0xFF));
    out.push_back(static_cast<u8>((v >> 8) & 0xFF));
    out.push_back(static_cast<u8>((v >> 16) & 0xFF));
    out.push_back(static_cast<u8>((v >> 24) & 0xFF));
}

std::uint32_t get_le32(const u8* p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

void put_le64(std::vector<u8>& out, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<u8>((v >> (8 * i)) & 0xFF));
    }
}

std::uint64_t get_le64(const u8* p) {
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
        v = (v << 8) | p[i];
    }
    return v;
}

} // namespace

namespace vhsm::persistence {

std::vector<u8> serialize_token_snapshot(const TokenSnapshot& snap) {
    VHSM_CHECK_MSG(snap.label.size() <= 255, "serialize_token_snapshot: label too long");
    VHSM_CHECK_MSG(snap.id.size() <= 255, "serialize_token_snapshot: id too long");

    std::vector<u8> out;
    out.reserve(64 + snap.label.size() + snap.id.size() + snap.kek.size());

    put_le32(out, KMagic);
    put_le32(out, KVersion);

    out.push_back(static_cast<u8>(snap.label.size()));
    out.insert(out.end(), snap.label.begin(), snap.label.end());

    out.push_back(static_cast<u8>(snap.id.size()));
    out.insert(out.end(), snap.id.begin(), snap.id.end());

    put_le64(out, static_cast<std::uint64_t>(snap.max_session_count));
    put_le64(out, static_cast<std::uint64_t>(snap.session_count));
    put_le64(out, static_cast<std::uint64_t>(snap.max_rw_session_count));
    put_le64(out, static_cast<std::uint64_t>(snap.rw_session_count));

    u8 flags = 0;
    if (snap.token_initialized)  flags |= KTokenInit;
    if (snap.user_pin_set)       flags |= KUserPinSet;
    if (snap.so_pin_set)         flags |= KSoPinSet;
    if (snap.user_login_required) flags |= KUserLoginReq;
    if (snap.so_login_required)  flags |= KSoLoginReq;
    if (snap.user_pin_locked)    flags |= KUserPinLocked;
    if (snap.so_pin_locked)      flags |= KSoPinLocked;
    out.push_back(flags);

    put_le32(out, snap.max_failed_attempts);
    put_le32(out, snap.user_failed_attempts);
    put_le32(out, snap.so_failed_attempts);

    put_le64(out, static_cast<std::uint64_t>(snap.kek.size()));
    out.insert(out.end(), snap.kek.begin(), snap.kek.end());

    return out;
}

TokenSnapshot deserialize_token_snapshot(const std::vector<u8>& data) {
    VHSM_CHECK_MSG(data.size() >= 8 + 2, "deserialize_token_snapshot: data too short");
    const u8* p = data.data();

    const std::uint32_t magic = get_le32(p);
    VHSM_CHECK_MSG(magic == KMagic, "deserialize_token_snapshot: bad magic");
    const std::uint32_t version = get_le32(p + 4);
    VHSM_CHECK_MSG(version == KVersion, "deserialize_token_snapshot: unsupported version");

    std::size_t off = 8;

    const auto read_string = [&]() -> std::string {
        VHSM_CHECK_MSG(off < data.size(), "deserialize_token_snapshot: truncated string length");
        const std::size_t len = data[off++];
        VHSM_CHECK_MSG(len <= data.size() - off, "deserialize_token_snapshot: truncated string");
        std::string s(reinterpret_cast<const char*>(data.data() + off), len);
        off += len;
        return s;
    };

    TokenSnapshot snap;
    snap.label = read_string();
    snap.id    = read_string();

    VHSM_CHECK_MSG(data.size() - off >= 8 + 8 + 8 + 8 + 1 + 4 + 4 + 4 + 8,
                   "deserialize_token_snapshot: truncated numeric fields");
    snap.max_session_count   = static_cast<CK_ULONG>(get_le64(p + off)); off += 8;
    snap.session_count       = static_cast<CK_ULONG>(get_le64(p + off)); off += 8;
    snap.max_rw_session_count= static_cast<CK_ULONG>(get_le64(p + off)); off += 8;
    snap.rw_session_count    = static_cast<CK_ULONG>(get_le64(p + off)); off += 8;

    const u8 flags = data[off++];
    snap.token_initialized   = (flags & KTokenInit) != 0;
    snap.user_pin_set        = (flags & KUserPinSet) != 0;
    snap.so_pin_set          = (flags & KSoPinSet) != 0;
    snap.user_login_required = (flags & KUserLoginReq) != 0;
    snap.so_login_required   = (flags & KSoLoginReq) != 0;
    snap.user_pin_locked     = (flags & KUserPinLocked) != 0;
    snap.so_pin_locked       = (flags & KSoPinLocked) != 0;

    snap.max_failed_attempts = get_le32(p + off); off += 4;
    snap.user_failed_attempts= get_le32(p + off); off += 4;
    snap.so_failed_attempts  = get_le32(p + off); off += 4;

    const std::uint64_t kek_len = get_le64(p + off); off += 8;
    VHSM_CHECK_MSG(kek_len <= data.size() - off, "deserialize_token_snapshot: truncated KEK");
    snap.kek.assign(data.begin() + static_cast<std::ptrdiff_t>(off),
                    data.begin() + static_cast<std::ptrdiff_t>(off + kek_len));

    return snap;
}

TokenSnapshot snapshot_from_token(const vhsm::keystore::Token& token) {
    TokenSnapshot snap;
    snap.label                 = token.get_label();
    snap.id                    = token.get_id();
    snap.max_session_count     = token.get_max_session_count();
    snap.session_count         = token.get_session_count();
    snap.max_rw_session_count  = token.get_max_rw_session_count();
    snap.rw_session_count      = token.get_rw_session_count();
    snap.token_initialized     = token.is_token_initialized();
    snap.user_pin_set          = token.is_user_pin_set();
    snap.so_pin_set            = token.is_so_pin_set();
    snap.user_login_required   = token.is_user_login_required();
    snap.so_login_required     = token.is_so_login_required();
    snap.user_failed_attempts  = token.user_pin_failed_attempts();
    snap.so_failed_attempts    = token.so_pin_failed_attempts();
    snap.max_failed_attempts   = token.max_pin_attempts();
    snap.user_pin_locked       = token.is_user_pin_locked();
    snap.so_pin_locked         = token.is_so_pin_locked();
    snap.kek                   = token.get_kek();
    return snap;
}

} // namespace vhsm::persistence