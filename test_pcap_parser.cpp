#include "pcap_parser.hpp"

#include <fstream>

int main() {
    pcap::PcapParser parser(std::make_unique<std::ifstream>(
        "../Corvil-13052-1636559040000000000-1636560600000000000.pcap", std::ios::binary));
    return 0;
}