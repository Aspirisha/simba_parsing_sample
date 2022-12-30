project(cpp_junk)

cmake_minimum_required(VERSION 3.23)

set(CMAKE_CXX_STANDARD 17)

#SET(Boost_USE_STATIC_LIBS ON)
FIND_PACKAGE(Boost 1.54 COMPONENTS log REQUIRED)

add_library(pcap_parser pcap_parser.cpp)
add_library(simba_parser simba_parser.cpp)

target_link_libraries(simba_parser Boost::log)

add_executable(pcap_parser_test test_pcap_parser.cpp)
target_link_libraries(pcap_parser_test pcap_parser)

add_executable(simba_parser_test test_simba_parser.cpp)
target_link_libraries(simba_parser_test pcap_parser simba_parser)
