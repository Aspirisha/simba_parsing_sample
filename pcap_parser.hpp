#pragma once

#include <string>
#include <cstddef>
#include <vector>
#include <memory>
#include <iosfwd>

// https://datatracker.ietf.org/doc/id/draft-gharris-opsawg-pcap-00.html

namespace pcap {

struct FileHeader {
  uint32_t magic_number;
  uint16_t version_major;
  uint16_t version_minor;
  uint32_t reserved1;
  uint32_t reserved2;
  uint32_t snap_len;
  uint32_t link_type;
};

struct PacketHeader {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t captured_packet_length;
  uint32_t original_packet_length;
};

struct Packet {
  PacketHeader header;
  std::vector<uint8_t> data;
};


class PcapParser {
 public:
  explicit PcapParser(std::unique_ptr<std::istream> input);

  bool HasNextPacket() const;

  Packet NextPacket();
 private:
  FileHeader file_header_;
  PacketHeader next_packet_header_;
  std::unique_ptr<std::istream> input_;
};

}  // namespace pcap