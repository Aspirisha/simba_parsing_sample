#pragma once

#include <sstream>

namespace util {

template<class... Args>
void throw_runtime_exception(Args&&... args) {
  std::stringstream ss;
  (ss << ... << args);
  throw std::runtime_error(ss.str());
}

}  // namespace util