#pragma once

#include <any>
#include <bit>
#include <cstdint>
#include <functional>
#include <unordered_map>
#include <vector>

#include "types.hpp"

static_assert(std::endian::native == std::endian::little,
              "This library is currently supported only for little-endian machines");

namespace pcap {
  class PcapPacket;
  enum class PcapLinkType;
}

namespace simba {

struct EthernetHeader {
  uint8_t destination_mac[6];
  uint8_t source_mac[6];
  uint16_t ether_type;
};

struct Ipv4Header {
  uint8_t ihl : 4;
  uint8_t version : 4;
  uint8_t ecn : 2;
  uint8_t dscp : 6;
  uint16_t total_length;
  uint16_t identification;
  uint16_t fragment_offset : 13;
  uint16_t flags : 3;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t header_checksum;
  uint32_t source_ip;
  uint32_t destination_ip;
};

struct UdpHeader {
  uint16_t source_port;
  uint16_t destination_port;
  uint16_t length;
  uint16_t checksum;
};

struct MarketDataPacketHeader {
  uint32_t msg_seq_num;
  uint16_t msg_size;
  uint16_t msg_flags;
  uint64_t sending_time;
};

struct __attribute__ ((packed)) IncrementalPacketHeader {
  uint64_t transact_time;
  uint32_t exchange_trading_session_id;
};

struct SbeHeader {
  uint16_t block_length;
  uint16_t template_id;
  uint16_t schema_id;
  uint16_t version;
};

struct __attribute__ ((packed)) SbeRepeatingGroup {
  uint16_t block_length;
  uint8_t num_in_group;
};

enum class PacketType {
  Incremental,
  Snapshot
};

enum class IncrementalMessage : uint16_t {
  BestPrices = 3,
  EmptyBook = 4,
  OrderUpdate = 5,
  OrderExecution = 6,
};

enum class SnapshotMessage {
  OrderBookSnapshot = 7,
};

struct __attribute__ ((packed)) OrderUpdateMessage {
  int64_t md_entry_id;
  Decimal5 md_entry_px;
  int64_t md_entry_size;
  uint64_t md_flags;
  int32_t security_id;
  uint32_t rpt_seq;
  MdUpdateAction md_update_action;
  char md_entry_type;
};

struct __attribute__ ((packed)) OrderExecutionMessage {
  int64_t md_entry_id;
  Decimal5Null md_entry_px;
  Int64Null md_entry_size;
  Decimal5 last_px;
  int64_t last_qty;
  int64_t trade_id;
  uint64_t md_flags;
  int32_t security_id;
  uint32_t rpt_seq;
  MdUpdateAction md_update_action;
  char md_entry_type;
};

struct __attribute__ ((packed)) OrderBookSnapshotHeader {
  int32_t security_id;
  uint32_t last_msg_seq_num_processed;
  uint32_t rpt_seq;
  uint32_t exchange_trading_session_id;
  SbeRepeatingGroup no_md_entries;
};

struct __attribute__ ((packed)) OrderBookSnapshotEntry {
  Int64Null md_entry_id;
  uint64_t transact_time;
  Decimal5Null md_entry_px;
  Int64Null md_entry_size;
  Int64Null trade_id;
  uint64_t md_flags_set;
  char md_entry_type;
};

struct OrderBookSnapshotMessage {
  OrderBookSnapshotHeader header;
  std::vector<OrderBookSnapshotEntry> md_entries;
};

class SimbaParser {
 public:
  using MessageCallback = std::function<void(std::any)>;

  explicit SimbaParser(pcap::PcapLinkType link_type) : link_type_(link_type) {}
  void FeedPcapPacket(const pcap::PcapPacket& packet);

  void RegisterIncrementalCallback(IncrementalMessage msg_id, const MessageCallback& callback);
  void RegisterSnapshotCallback(SnapshotMessage msg_id, const MessageCallback& callback);

 private:
  void ParseIpPacket(const uint8_t* ip_packet_start, const EthernetHeader& ether_header);
  void ParseUdpPacket(const uint8_t* udp_packet_start, const Ipv4Header& ip_header);
  void ParseSimbaPacket(const uint8_t* simba_packet_start, const UdpHeader& udp_header);
  void ParseIncrementalPacket(
    const uint8_t* incremental_packet_start,
    const MarketDataPacketHeader& header);
  void ParseSnapshotPacket(
    const uint8_t* snapshot_packet_start,
    const MarketDataPacketHeader& header);

  std::unordered_map<IncrementalMessage, std::vector<MessageCallback>> incremental_callbacks_;
  std::unordered_map<SnapshotMessage, std::vector<MessageCallback>> snapshot_callbacks_;
  pcap::PcapLinkType link_type_;
};

}  // namespace simba

