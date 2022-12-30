#include "simba_parser.hpp"

#include "pcap_parser.hpp"
#include <arpa/inet.h>

#include "exception_helpers.hpp"

#include <boost/log/trivial.hpp>

namespace simba {

namespace {

template<class... Args>
constexpr void apply_ntoh(Args&... args);

template<>
constexpr void apply_ntoh() {}

template<class T, class... Args>
constexpr void apply_ntoh(T& t, Args&... args) {
  static_assert(std::is_same_v<T, uint16_t> || std::is_same_v<T, uint32_t>);
  if constexpr (std::is_same_v<T, uint16_t>) {
    t = ntohs(t);
  }
  if constexpr (std::is_same_v<T, uint32_t>) {
    t = ntohl(t);
  }
  return apply_ntoh(args...);
}

constexpr uint16_t kIpv4EtherType = 0x0800;
constexpr uint16_t kIpv4Version = 4;
constexpr uint16_t kOctetSize = 4;

enum class IpProtocol {
  HOPOPT = 0,
  UDP = 17,
  MAX_PROTOCOL = 0xFF
};

constexpr uint64_t MarketDataFlagFragmentation = 0x1;
constexpr uint64_t MarketDataFlagSnapshotStart = 0x2;
constexpr uint64_t MarketDataFlagSnapshotEnd = 0x4;
constexpr uint64_t MarketDataFlagIncrementalPacket = 0x8;
constexpr uint64_t MarketDataFlagPossDupFlag = 0x10;

}  // namespace

void SimbaParser::FeedPcapPacket(const pcap::PcapPacket& packet) {
  if (packet.header.captured_packet_length != packet.header.original_packet_length) {
    BOOST_LOG_TRIVIAL(debug) << "Truncated package";
  }
  switch (link_type_) {
    case pcap::PcapLinkType::DLT_EN10MB: {
      EthernetHeader header;
      memcpy(&header, packet.data.data(), sizeof(EthernetHeader));
      header.ether_type = ntohs(header.ether_type);
      if (header.ether_type != kIpv4EtherType) {
        util::throw_runtime_exception("Unsupported ether type: ", std::hex, header.ether_type);
      }
      ParseIpPacket(packet.data.data() + sizeof(EthernetHeader), header);
      break;
    }
    default:
      util::throw_runtime_exception("Unsupported link type: ", static_cast<int>(link_type_));
  }
}

void SimbaParser::RegisterIncrementalCallback(
    IncrementalMessage msg_id, 
    const MessageCallback &callback) {
  incremental_callbacks_[msg_id].push_back(callback);
}

void SimbaParser::RegisterSnapshotCallback(
    SnapshotMessage msg_id, 
    const MessageCallback &callback) {
  snapshot_callbacks_[msg_id].push_back(callback);
}

void SimbaParser::ParseIpPacket(const uint8_t* ip_packet_start, 
                                const EthernetHeader& ether_header) {
  Ipv4Header ip_header;
  memcpy(&ip_header, ip_packet_start, sizeof(Ipv4Header));
  apply_ntoh(ip_header.total_length, ip_header.identification, ip_header.header_checksum);

  uint8_t ip_header_size = ip_header.ihl * kOctetSize;
  assert(ip_header_size >= sizeof(Ipv4Header));
  assert(ip_header.version == kIpv4Version);

  auto underlying_packet_start = ip_packet_start + ip_header_size;
  switch (static_cast<IpProtocol>(ip_header.protocol)) {
    case IpProtocol::UDP: {
      ParseUdpPacket(underlying_packet_start, ip_header);
      break;
    }
    default:
      util::throw_runtime_exception("Unsupported ip protocol: ", ip_header.protocol);
  }
}

void SimbaParser::ParseUdpPacket(const uint8_t *udp_packet_start, const Ipv4Header &ip_header) {
  UdpHeader udp_header;
  memcpy(&udp_header, udp_packet_start, sizeof(UdpHeader));
  apply_ntoh(
    udp_header.checksum, 
    udp_header.destination_port,
    udp_header.length, 
    udp_header.source_port);
  ParseSimbaPacket(udp_packet_start + sizeof(UdpHeader), udp_header);
}

void SimbaParser::ParseSimbaPacket(const uint8_t *simba_packet_start, const UdpHeader &udp_header) {
  MarketDataPacketHeader market_data_packet_header;
  memcpy(&market_data_packet_header, simba_packet_start, sizeof(MarketDataPacketHeader));
  assert(udp_header.length == market_data_packet_header.msg_size + sizeof(UdpHeader));

  BOOST_LOG_TRIVIAL(debug) << "Received data packet #" << market_data_packet_header.msg_seq_num;
  auto underlying_packet = simba_packet_start + sizeof(MarketDataPacketHeader);
  if (market_data_packet_header.msg_flags & MarketDataFlagIncrementalPacket) {
    ParseIncrementalPacket(
      underlying_packet,
      market_data_packet_header);
  } else {
    ParseSnapshotPacket(
      underlying_packet,
      market_data_packet_header);
  }
}

void SimbaParser::ParseIncrementalPacket(
    const uint8_t *incremental_packet_start, 
    const MarketDataPacketHeader &header) {
  IncrementalPacketHeader incremental_header;
  memcpy(&incremental_header, incremental_packet_start, sizeof(IncrementalPacketHeader));
  size_t offset = sizeof(IncrementalPacketHeader);

  if (!(header.msg_flags & MarketDataFlagFragmentation)) {
    BOOST_LOG_TRIVIAL(debug) << "Got fragmented message";
  }

  auto message_size = header.msg_size - sizeof(MarketDataPacketHeader);
  while (offset < message_size) {
    SbeHeader sbe_header;
    memcpy(&sbe_header, incremental_packet_start + offset, sizeof(SbeHeader));
    offset += sizeof(SbeHeader);

    switch (static_cast<IncrementalMessage>(sbe_header.template_id)) {
    case IncrementalMessage::OrderUpdate: {
      OrderUpdateMessage message;
      if (sbe_header.block_length != sizeof(OrderUpdateMessage)) {
        BOOST_LOG_TRIVIAL(debug) << "Unexpected size of OrderUpdateMessage";
      }
      assert(sbe_header.block_length == sizeof(OrderUpdateMessage));
      memcpy(&message, incremental_packet_start + offset, sbe_header.block_length);
      break;
    }
    case IncrementalMessage::OrderExecution: {
      OrderExecutionMessage message;
      if (sbe_header.block_length != sizeof(OrderExecutionMessage)) {
        BOOST_LOG_TRIVIAL(debug) << "Unexpected size of OrderExecutionMessage";
      }
      assert(sbe_header.block_length == sizeof(OrderExecutionMessage));
      memcpy(&message, incremental_packet_start + offset, sbe_header.block_length);
      break;
    }
    case IncrementalMessage::BestPrices: {
      BOOST_LOG_TRIVIAL(debug) << "Received BestPrices message";
      return;
    }
    case IncrementalMessage::EmptyBook: {
      BOOST_LOG_TRIVIAL(debug) << "Received EmptyBook message";
      break;
    }
    default:
      if (sbe_header.template_id > 20) {
        BOOST_LOG_TRIVIAL(debug) << "Unsupported incremental message id " << sbe_header.template_id;
      } else {
        BOOST_LOG_TRIVIAL(debug) << "Received unsupported incremental message " << sbe_header.template_id;
      }
      break;
    }
    offset += sbe_header.block_length;
  }

  if (offset > header.msg_size) {
    BOOST_LOG_TRIVIAL(debug) << "ops!";
  }
}

void SimbaParser::ParseSnapshotPacket(
  const uint8_t *snapshot_packet_start, 
  const MarketDataPacketHeader &header) {
    SbeHeader sbe_header;
    memcpy(&sbe_header, snapshot_packet_start, sizeof(SbeHeader));
    switch (static_cast<SnapshotMessage>(sbe_header.template_id)) {
      case SnapshotMessage::OrderBookSnapshot:
        BOOST_LOG_TRIVIAL(debug) << "Received snapshot message id " << sbe_header.template_id;
      break;

      default:
        BOOST_LOG_TRIVIAL(debug) << "Unsupported snapshot message id " << sbe_header.template_id;
    }
}

}  // namespace simba