#ifndef VHSM_CORE_CLOCK_UTILS 
#define VHSM_CORE_CLOCK_UTILS
#include <optional>
#include <stdexcept>

#include "hsm_clock.h"

namespace vhsm {

struct ClockUtils {

    // Epoch-milliseconds

    // Convert a HsmTimePoint to a signed 64-bit epoch-millisecond value
    // (as used by SQLite, JavaScript Date, and most REST APIs).
    // Valid for dates between roughly year 292 million BCE and 292 million CE.
    [[nodiscard]]
    static int64_t to_epoch_ms(HsmTimePoint tp) noexcept {
        return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
        // HsmTimePoint's period IS milliseconds, so .count() is already ms, 
        // but it is safer to cast to milliseconds.
    }

    /// Reconstruct a HsmTimePoint from a stored epoch-millisecond value.
    [[nodiscard]]
    static HsmTimePoint from_epoch_ms(int64_t ms) noexcept {
        return HsmTimePoint(std::chrono::milliseconds(ms));
    }

    // ISO-8601
    // Format as "YYYY-MM-DDTHH:MM:SS.mmmZ" (UTC, millisecond precision).
    // Example: "2025-06-10T13:42:00.123Z"
    //
    // Uses C's gmtime_r (POSIX) / gmtime_s (MSVC) rather than
    // std::format("{:%FT%T}Z", ...) because the latter requires C++20's
    // calendar support to be fully implemented, which is still patchy on
    // some toolchains as of 2025.
    [[nodiscard]]
    static std::string to_iso8601(HsmTimePoint tp) {
        const int64_t total_ms  = to_epoch_ms(tp);
        const int64_t seconds   = total_ms / 1000;
        const int64_t ms_part   = total_ms % 1000;

        // Normalise: negative modulo result means we're before Unix epoch.
        const int64_t ms_norm   = (ms_part >= 0) ? ms_part : ms_part + 1000;
        const int64_t sec_norm  = (ms_part >= 0) ? seconds : seconds - 1;

        const std::time_t t = static_cast<std::time_t>(sec_norm);
        std::tm utc_tm{};

#ifdef _WIN32
        gmtime_s(&utc_tm, &t);
#else
        if (::gmtime_r(&t, &utc_tm) == nullptr) {
            throw std::invalid_argument("gmtime_r got an invalid argument");
        }
#endif

        char buf[32];
        // "2025-06-10T13:42:00" — 19 chars
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &utc_tm);

        // Append ".mmmZ"
        char result[32];
        std::snprintf(result, sizeof(result), "%s.%03dZ",
            buf, static_cast<int>(ms_norm));
        return result;
    }

    /// Parse "YYYY-MM-DDTHH:MM:SS[.mmm]Z" back to HsmTimePoint.
    /// Returns nullopt if the string is malformed.
    /// Only the 'Z' (UTC) suffix is accepted; local-time offsets are rejected.
    [[nodiscard]]
    static std::optional<HsmTimePoint> from_iso8601(const std::string& s) {
        // Minimum valid form: "YYYY-MM-DDTHH:MM:SSZ" = 20 chars
        if (s.size() < 20 || s.back() != 'Z') return std::nullopt;

        std::tm utc_tm{};
        int ms = 0;

        // Try with milliseconds first: "YYYY-MM-DDTHH:MM:SS.mmmZ"
        if (s.size() == 24) {
            if (std::sscanf(s.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d.%3dZ",
                            &utc_tm.tm_year, &utc_tm.tm_mon, &utc_tm.tm_mday,
                            &utc_tm.tm_hour, &utc_tm.tm_min, &utc_tm.tm_sec,
                            &ms) != 7) return std::nullopt;
        } else if (s.size() == 20) {
            if (std::sscanf(s.c_str(), "%4d-%2d-%2dT%2d:%2d:%2dZ",
                            &utc_tm.tm_year, &utc_tm.tm_mon, &utc_tm.tm_mday,
                            &utc_tm.tm_hour, &utc_tm.tm_min, &utc_tm.tm_sec)
                            != 6) return std::nullopt;
        } else {
            return std::nullopt;
        }

        utc_tm.tm_year -= 1900;
        utc_tm.tm_mon  -= 1;
        utc_tm.tm_isdst = 0;

        if (utc_tm.tm_mon  < 0 || utc_tm.tm_mon  > 11) return std::nullopt;
        if (utc_tm.tm_mday < 1 || utc_tm.tm_mday > 31) return std::nullopt;
        if (utc_tm.tm_hour > 23) return std::nullopt;
        if (utc_tm.tm_min  > 59) return std::nullopt;
        if (utc_tm.tm_sec  > 60) return std::nullopt; // 60 = leap second
        if (ms < 0  || ms > 999) return std::nullopt;

#ifdef _WIN32
        const std::time_t t = _mkgmtime(&utc_tm);
#else
        const std::time_t t = ::timegm(&utc_tm);
#endif
        if (t == static_cast<std::time_t>(-1)) return std::nullopt;

        const int64_t epoch_ms = static_cast<int64_t>(t) * 1000 + ms;
        return from_epoch_ms(epoch_ms);
    }
};

} // namespace vhsm

#endif // VHSM_CORE_CLOCK_UTILS