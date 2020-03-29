cmake_minimum_required(VERSION 3.0)
project(canaryscan)
add_executable(canaryscan main.c)
set_property(TARGET canaryscan PROPERTY C_STANDARD 11)
set(CMAKE_C_FLAGS_RELEASE "-fstack-protector-all -O0 -DNDEBUG")

