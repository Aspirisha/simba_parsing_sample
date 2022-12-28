project(cpp_junk)

set(CMAKE_MINIMUM_REQUIRED_VERSION 3.23)

set(CMAKE_CXX_STANDARD 17)

add_library(pcap_parser pcap_parser.cpp)
add_executable(pcap_parser_test test_pcap_parser.cpp)
target_link_libraries(pcap_parser_test pcap_parser)
