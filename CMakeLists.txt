cmake_minimum_required(VERSION 3.14)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(-Wall -Wextra -Wpedantic -Werror)

project(jwevans_crypto
        VERSION 0.0.1
        LANGUAGES C CXX)

include_directories(AFTER include)


####################################################################
# Set Up Google Test
####################################################################
add_subdirectory(googletest)
enable_testing()
include(GoogleTest)
include_directories(${googletest_SOURCE_DIR}/include ${googletest_SOURCE_DIR})

#####################################################################
# Source and Test Directories
#####################################################################
add_subdirectory(src)
add_subdirectory(test)