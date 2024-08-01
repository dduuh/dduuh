cmake_minimum_required(VERSION 3.29.2)
project(HELLO_WORLD)

include_directories(/usr/include)

add_executable(${PROJECT_NAME} main.cpp)