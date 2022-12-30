#include "pcap_parser.hpp"

#include <istream>
#include <sstream>

#include "exception_helpers.hpp"

namespace pcap {

namespace {
constexpr uint32_t kMagicNumberMicroseconds = 0xA1B2C3D4;
constexpr uint32_t kMagicNumberNanoseconds = 0xA1B23C4D;
constexpr uint16_t kExpectedMajorVersion = 2;
constexpr uint16_t kExpectedMinorVersion = 4;

}  // namespace

PcapParser::PcapParser(std::unique_ptr<std::istream> input) : input_(std::move(input)) {
  if (!*input_) {
    util::throw_runtime_exception("Bad input stream");
  }

  static_assert(sizeof(FileHeader) == 24);

  input_->read(reinterpret_cast<char*>(&file_header_), sizeof(FileHeader));
  if (file_header_.magic_number != kMagicNumberMicroseconds && 
    file_header_.magic_number != kMagicNumberNanoseconds) {
    util::throw_runtime_exception(
      "Not a PCAP file: magic number is ", file_header_.magic_number);
  }

  if (file_header_.version_major != kExpectedMajorVersion) {
    util::throw_runtime_exception(
      "Unsupported protocol major version: ", file_header_.version_major,
      ", while supported is ", kExpectedMajorVersion);
  }

  if (file_header_.version_minor > kExpectedMinorVersion) {
    util::throw_runtime_exception(
      "Unsupported protocol minor version: ", file_header_.version_minor,
      ", while supported is at most ", kExpectedMinorVersion);
  }

  input_->read(reinterpret_cast<char*>(&next_packet_header_), sizeof(PacketHeader));
}

bool PcapParser::HasNextPacket() const {
  return !input_->eof();
}

PcapPacket PcapParser::NextPacket() {
  if (!HasNextPacket()) {
    util::throw_runtime_exception("Packets stream exhausted");
  }

  std::vector<uint8_t> data(next_packet_header_.captured_packet_length);
  input_->read(reinterpret_cast<char*>(data.data()), next_packet_header_.captured_packet_length);

  PcapPacket result{
    .header = next_packet_header_,
    .data = data
  };

  input_->read(reinterpret_cast<char*>(&next_packet_header_), sizeof(PacketHeader));

  return result;
}

PcapLinkType PcapParser::LinkType() const {
  return static_cast<PcapLinkType>(file_header_.link_type);
}

}  // namespace pcap
