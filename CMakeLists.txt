cmake_minimum_required (VERSION 2.6)
project (L1)

set (L1_VERSION_MAJOR 1)
set (L1_VERSION_MINOR 0)

if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Release)
endif()


set(CMAKE_C_FLAGS "-Wall -Wextra")
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -fsanitize=address -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS_RELEASE "-Ofast -s -fno-ident  -march=native -flto -DNDEBUG")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_LIST_DIR}")

add_definitions(-D_POSIX_C_SOURCE=200809L)
add_definitions(-D_DEFAULT_SOURCE)

include_directories(src deps/wrappers)

SET(SOURCES
    "src/addr.c"
    "src/filter.c"
    "src/poison.c"
    "src/main.c"
    )

add_executable(L1 ${SOURCES})

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

target_link_libraries(L1 rt Threads::Threads)
