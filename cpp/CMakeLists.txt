# CMakeLists.txt
cmake_minimum_required(VERSION 3.4.1)

add_library(
  aesmodule
  SHARED
  aes.cpp
)

find_library(
  log-lib
  log
)

target_link_libraries(
  aesmodule
  ${log-lib}
  crypto
)