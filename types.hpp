#pragma once

#include <cstdint>
#include <string>
#include <sstream>
#include <unordered_map>

namespace simba {

struct Decimal5 {
  int64_t mantissa;
};

struct Decimal5Null {
  int64_t mantissa;
};

struct Int64Null {
  int64_t value;
};

enum class MdUpdateAction : uint8_t {
  New = 0,
  Change = 1,
  Delete = 2
};

inline std::string to_string(Decimal5 decimal) {
  std::stringstream ss;
  constexpr int64_t exponent = 100'000;
  ss << (decimal.mantissa / exponent) << "." << decimal.mantissa % exponent;
  return ss.str();
}

inline std::string to_string(Decimal5Null decimal) {
  constexpr int64_t null_value = std::numeric_limits<int64_t>::max();
  if (decimal.mantissa == null_value) {
    return "null";
  }
  return to_string(Decimal5{decimal.mantissa});
}

inline std::string to_string(Int64Null num) {
  constexpr int64_t null_value = std::numeric_limits<int64_t>::min();
  if (num.value == null_value) {
    return "null";
  }
  return std::to_string(num.value);
}

inline std::string to_string(MdUpdateAction action) {
  static const std::unordered_map<MdUpdateAction, std::string> names = {
    {MdUpdateAction::New, "New"},
    {MdUpdateAction::Delete, "Delete"},
    {MdUpdateAction::Change, "Change"}
  };

  return names.at(action);
}


}  // namespace simba
