#include "pcap_parser.hpp"

#include <istream>
#include <sstream>

namespace pcap {

namespace {
constexpr uint32_t kMagicNumberMicroseconds = 0xA1B2C3D4;
constexpr uint32_t kMagicNumberNanoseconds = 0xA1B23C4D;
constexpr uint16_t kExpectedMajorVersion = 2;
constexpr uint16_t kExpectedMinorVersion = 4;

template<class... Args>
void throw_runtime_exception(Args&&... args) {
  std::stringstream ss;
  (ss << ... << args);
  throw std::runtime_error(ss.str());
}

}  // namespace

PcapParser::PcapParser(std::unique_ptr<std::istream> input) : input_(std::move(input)) {
  if (!*input_) {
    throw_runtime_exception("Bad input stream");
  }

  input_->read(reinterpret_cast<char*>(&file_header_), sizeof(FileHeader));
  if (file_header_.magic_number != kMagicNumberMicroseconds && 
    file_header_.magic_number != kMagicNumberNanoseconds) {
    throw_runtime_exception("Not a PCAP file: magic number is ", file_header_.magic_number);
  }

  if (file_header_.version_major != kExpectedMajorVersion) {
    throw_runtime_exception("Unsupported protocol major version: ", file_header_.version_major,
    ", while supported is ", kExpectedMajorVersion);
  }

  if (file_header_.version_minor > kExpectedMajorVersion) {
    throw_runtime_exception("Unsupported protocol minor version: ", file_header_.version_minor,
    ", while supported is at most ", kExpectedMinorVersion);
  }
}

}  // namespace pcap
