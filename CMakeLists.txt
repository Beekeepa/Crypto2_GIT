cmake_minimum_required(VERSION 3.8)
project(Crypto2_GIT)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES FEAL.cpp FEAL.h main.cpp)
add_executable(Crypto2_GIT ${SOURCE_FILES})