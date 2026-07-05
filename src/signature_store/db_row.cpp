#include "db_row.h"

namespace vhsm::signature_store {
namespace db {
DbRow::DbRow(std::vector<std::string> column_values)
    : values_(std::move(column_values)) {}

size_t DbRow::column_count() const { return values_.size(); }

std::optional<std::string> DbRow::get_string(size_t column_index) const {
    if (column_index >= values_.size()) {
        return std::nullopt;
    }

    return values_[column_index];
}

std::optional<i64> DbRow::get_i64(size_t column_index) const {
    if (column_index >= values_.size()) {
        return std::nullopt;
    }

    const std::string& str = values_[column_index];
    i64 value = 0;
    auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), value);
    
    if (ec == std::errc() && ptr == str.data() + str.size()) {
        return value;
    }

    return std::nullopt;
}

std::optional<double> DbRow::get_double(size_t column_index) const {
    if (column_index >= values_.size()) {
        return std::nullopt;
    }

    const std::string& str = values_[column_index];
    double value = 0.0;
    auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), value);
    if (ec == std::errc() && ptr == str.data() + str.size()) {
        return value;
    }
    return std::nullopt;
}

std::optional<bool> DbRow::get_bool(size_t column_index) const {
    if (column_index >= values_.size()) {
        return std::nullopt;
    }

    const std::string& str = values_[column_index];
    if (str == "0" || str == "false" || str == "FALSE") {
        return false;
    } else if (str == "1" || str == "true" || str == "TRUE") {
        return true;
    }
    return std::nullopt;
}
}
}