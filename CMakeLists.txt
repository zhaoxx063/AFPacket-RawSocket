cmake_minimum_required(VERSION 3.6)
project(AFPacket_RawSocket)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES main.cpp)
add_executable(AFPacket_RawSocket ${SOURCE_FILES})