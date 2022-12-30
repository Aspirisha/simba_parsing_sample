#include <fstream>
#include <iostream>

#include <boost/program_options.hpp>

#include "pcap_parser.hpp"
#include "simba_parser.hpp"

namespace po = boost::program_options;

namespace {
  void InitOrderUpdateSink(
      std::ofstream& sink,
      simba::SimbaParser& simba_parser) {
    sink
        << "md_entry_id" << ", "
        << "md_entry_px" << ", "
        << "md_entry_size" << ", "
        << "md_flags" << ", "
        << "security_id" << ", "
        << "rpt_seq" << ", "
        << "md_update_action" << ", "
        << "md_entry_type" << "\n";

    simba_parser.RegisterIncrementalCallback(
      simba::IncrementalMessage::OrderUpdate, 
      [&sink](const std::any& msg_holder) {
        auto msg = std::any_cast<simba::OrderUpdateMessage>(msg_holder);
        sink
          << msg.md_entry_id << ", "
          << simba::to_string(msg.md_entry_px) << ", "
          << msg.md_entry_size << ", "
          << msg.md_flags << ", "
          << msg.security_id << ", "
          << msg.rpt_seq << ", "
          << simba::to_string(msg.md_update_action) << ", "
          << msg.md_entry_type << "\n";
    });
  }

  void InitOrderExecutionSink(
      std::ofstream& sink,
      simba::SimbaParser& simba_parser) {
    sink
        << "md_entry_id" << ", "
        << "md_entry_px" << ", "
        << "md_entry_size" << ", "
        << "last_px" << ","
        << "last_qty" << ", "
        << "trade_id" << ", "
        << "md_flags" << ", "
        << "security_id" << ", "
        << "rpt_seq" << ", "
        << "md_update_action" << ", "
        << "md_entry_type" << "\n";

    simba_parser.RegisterIncrementalCallback(
      simba::IncrementalMessage::OrderExecution, 
      [&sink](const std::any& msg_holder) {
        auto msg = std::any_cast<simba::OrderExecutionMessage>(msg_holder);
        sink
          << msg.md_entry_id << ", "
          << simba::to_string(msg.md_entry_px) << ", "
          << simba::to_string(msg.md_entry_size) << ", "
          << simba::to_string(msg.last_px) << ", "
          << msg.last_qty << ", "
          << msg.trade_id << ", "
          << msg.md_flags << ", "
          << msg.security_id << ", "
          << msg.rpt_seq << ", "
          << simba::to_string(msg.md_update_action) << ", "
          << msg.md_entry_type << "\n";
    });
  }

  void InitOrderBookSnapshotSink(
      std::ofstream& sink,
      simba::SimbaParser& simba_parser) {
    sink
        << "security_id" << ", "
        << "last_msg_seq_num_processed" << ", "
        << "rpt_seq" << ", "
        << "exchange_trading_session_id" << ","
        << "md_entry_id" << ", "
        << "transact_time" << ", "
        << "md_entry_px" << ", "
        << "md_entry_size" << ", "
        << "trade_id" << ", "
        << "md_flags_set" << ", "
        << "md_entry_type" << "\n";

    simba_parser.RegisterSnapshotCallback(
      simba::SnapshotMessage::OrderBookSnapshot, 
      [&sink](const std::any& msg_holder) {
        auto msg = std::any_cast<simba::OrderBookSnapshotMessage>(msg_holder);
        for (size_t i = 0; i < msg.md_entries.size(); i++) {
          if (i == 0) {
            sink
              << msg.header.security_id << ", "
              << msg.header.last_msg_seq_num_processed << ", "
              << msg.header.rpt_seq << ", "
              << msg.header.exchange_trading_session_id << ", ";
          } else {
            sink << "~, ~, ~, ~, ";  // not to copy the same values
          }
          sink
            << simba::to_string(msg.md_entries[i].md_entry_id) << ", "
            << msg.md_entries[i].transact_time << ", "
            << simba::to_string(msg.md_entries[i].md_entry_px) << ", "
            << simba::to_string(msg.md_entries[i].md_entry_size) << ", "
            << simba::to_string(msg.md_entries[i].trade_id) << ", "
            << msg.md_entries[i].md_flags_set << ", "
            << msg.md_entries[i].md_entry_type << "\n";
        }
    });
  }
}

int main(int argc, char** argv) {
  po::options_description desc("Allowed options");
  desc.add_options()
      ("help", "produce help message")
      ("input-file,i", po::value<std::string>()->required(), "Input pcap file")
      ("output-order-update-file",
      po::value<std::string>()->default_value("update_messages.csv"),
      "output csv file to store decoded order update messages")
      ("output-order-execution-file",
      po::value<std::string>()->default_value("execution_messages.csv"),
      "output csv file to store decoded order execution messages")
      ("output-book-snapshot-file",
      po::value<std::string>()->default_value("book_snapshot_messages.csv"),
      "output csv file to store decoded book snapshot messages")
      ("limit-packets-number,n",
      po::value<size_t>(),
      "Number of packets to process; if negative, process all messages")
  ;

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);

  if (vm.count("help")) {
    std::cout << desc << "\n";
    return 1;
  }
  
  try {
    po::notify(vm);
  } catch (po::required_option& exc) {
    std::cerr << exc.what() << std::endl;
    std::cerr << desc << "\n";
    return 1;
  }

  pcap::PcapParser parser(std::make_unique<std::ifstream>(
    vm["input-file"].as<std::string>(),
    std::ios::binary));

  std::ofstream update_messages_sink(vm["output-order-update-file"].as<std::string>());
  std::ofstream execution_messages_sink(vm["output-order-execution-file"].as<std::string>());
  std::ofstream book_snapshot_messages_sink(vm["output-book-snapshot-file"].as<std::string>());
  simba::SimbaParser simba_parser(parser.LinkType());
  InitOrderUpdateSink(update_messages_sink, simba_parser);
  InitOrderExecutionSink(execution_messages_sink, simba_parser);
  InitOrderBookSnapshotSink(book_snapshot_messages_sink, simba_parser);

  size_t max_packet = std::numeric_limits<size_t>::max();
  if (vm.count("limit-packets-number")) {
    max_packet = vm["limit-packets-number"].as<size_t>();
  }

  size_t packets_num = 0;
  for (; parser.HasNextPacket() && packets_num < max_packet; packets_num++) {
    auto packet = parser.NextPacket();
    simba_parser.FeedPcapPacket(packet);
  }

  std::cout << "processed " << packets_num << " packets" << std::endl;
    
  return 0;
}