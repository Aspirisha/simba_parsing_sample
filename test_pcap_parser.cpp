#include "pcap_parser.hpp"

#include <fstream>
#include <iostream>

static constexpr char filename[] = "Corvil-13052-1636559040000000000-1636560600000000000.pcap";

int main() {
  pcap::PcapParser parser(std::make_unique<std::ifstream>(filename, std::ios::binary));

  int packets_num = 0;
  while (parser.HasNextPacket()) {
    auto packet = parser.NextPacket();

    if (packet.header.captured_packet_length != packet.header.original_packet_length) {
      std::cout << packets_num << ": " << packet.header.original_packet_length 
        << ", " << packet.header.captured_packet_length << std::endl;
    }
    packets_num++;
  }

  std::cout << packets_num << std::endl;
    
  return 0;
}