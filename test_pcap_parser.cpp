#include "pcap_parser.hpp"

#include <fstream>
#include <iostream>

static constexpr char filename[] = "../Corvil-13052-1636559040000000000-1636560600000000000.pcap";

int main() {
  pcap::PcapParser parser(std::make_unique<std::ifstream>(filename, std::ios::binary));

  int packets_num = 0;
  while (parser.HasNextPacket()) {
    pcap::Packet packet = parser.NextPacket();
    packets_num++;
  }

  std::cout << packets_num << std::endl;
    
  return 0;
}