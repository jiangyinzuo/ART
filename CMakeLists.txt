cmake_minimum_required(VERSION 3.16)
project(ART)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20")

set(ART_BUILD_TESTS "Build ${PROJECT_NAME}'s unit tests" ON)

set(GIT_REPO_PREFIX "https://github.com" CACHE STRING "git repository url prefix")

if (ART_BUILD_TESTS)
    add_definitions(-D ART_BUILD_TESTS)
    add_subdirectory(test)
endif (ART_BUILD_TESTS)

if (MSVC)
else ()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mbmi ")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mbmi ")
endif ()

file(GLOB ART_SRC src/*.c)
add_library(${PROJECT_NAME} STATIC ${ART_SRC})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Reference: https://github.com/codecov/example-cpp11-cmake/blob/master/CMakeLists.txt
option(CODE_COVERAGE "Enable coverage reporting" OFF)
if (CODE_COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -fprofile-arcs -ftest-coverage")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -fprofile-arcs -ftest-coverage")
    target_link_libraries(${PROJECT_NAME} gcov)
endif (CODE_COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
