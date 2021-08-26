cmake_minimum_required(VERSION 3.16)
project(ART)

set(CMAKE_CXX_STANDARD 20)

set(ART_BUILD_TESTS "Build ${PROJECT_NAME}'s unit tests" ON)

if (ART_BUILD_TESTS)
    add_definitions(-D ART_BUILD_TESTS)
    add_subdirectory(test)
endif (ART_BUILD_TESTS)

if (MSVC)
else ()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mbmi ")
endif ()

file(GLOB ART_SRC src/*.cpp)
add_library(${PROJECT_NAME} STATIC ${ART_SRC})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)