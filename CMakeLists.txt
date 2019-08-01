cmake_minimum_required(VERSION 3.14)
project(ESP_Russian_GOST_Test C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -DLIBAKRYPT_HAVE_SYSTYPES_H -pedantic-errors")
message("Compiler options are ${CMAKE_C_FLAGS}")

include_directories(/usr/local/include /usr/local/lib)
find_library(LIBAKRYPT akrypt REQUIRED)
find_library(PCAP pcap REQUIRED)
message("Included libraries are ${LIBAKRYPT} and ${PCAP}")

add_executable(ESP_Russian_GOST_Test main.c ESP.h ESP.c sniffer.c sniffer.h)
target_link_libraries(ESP_Russian_GOST_Test ${LIBAKRYPT} ${PCAP})
