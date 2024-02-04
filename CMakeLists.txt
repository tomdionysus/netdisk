cmake_minimum_required(VERSION 3.12)

set(CMAKE_TRY_COMPILE_TARGET_TYPE "STATIC_LIBRARY")

project(netdisk C ASM)

# Includes
include_directories (
	${CMAKE_SOURCE_DIR}/src/libnetdisk
	${CMAKE_SOURCE_DIR}/deps
)

file(GLOB libnetdisk_SOURCES ${CMAKE_SOURCE_DIR}/src/libnetdisk/*.c)
file(GLOB netdisk_mod_SOURCES ${CMAKE_SOURCE_DIR}/src/netdisk_module/*.c)
file(GLOB netdiskd_SOURCES ${CMAKE_SOURCE_DIR}/src/netdiskd/*.c)
file(GLOB netdisk_testclient_SOURCES ${CMAKE_SOURCE_DIR}/src/netdisk_testclient/*.c)

# Dependencies
find_package(Threads REQUIRED)
include(${CMAKE_SOURCE_DIR}/deps/tiny-AES-c/CMakeLists.txt)

# libnetdisk
add_library(
	netdisk SHARED 
	${libnetdisk_SOURCES}
)

target_link_libraries(
	netdisk 
	tiny-aes
)

# Server
add_executable(
	netdiskd
	${netdiskd_SOURCES}
)

target_link_libraries(
	netdiskd 
	netdisk
	Threads::Threads
)

# Linux Module
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
add_custom_target(
    netdisk_module ALL
    COMMAND make
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/netdisk_module
)
endif()

# Test Client
add_executable(
	netdisk_testclient
	${netdisk_testclient_SOURCES}
)

target_link_libraries(
	netdisk_testclient 
	netdisk
)

# Client Driver
# project(netdisk_module C ASM)

# add_executable(
# 	netdiskd
# 	${netdisk_mod_SOURCES}
# )
# target_link_libraries(netdiskd 
# 	netdisk
# )


# # Testing
# FetchContent_Declare(
#   googletest
#   URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
# )
# # For Windows: Prevent overriding the parent project's compiler/linker settings
# set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
# FetchContent_MakeAvailable(googletest)
# enable_testing()

# file(GLOB TEST_SOURCES test/*.cpp)

# add_executable(
#   kapua_test
# 	${TEST_SOURCES}
# )
# target_link_libraries(
#   kapua_test
#   kapua
#   GTest::gtest_main
#   GTest::gmock_main
# )
# include(GoogleTest)
# gtest_discover_tests(kapua_test)
