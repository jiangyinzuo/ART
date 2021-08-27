cmake_minimum_required(VERSION 3.16)
project(ART)

set(CMAKE_CXX_STANDARD 20)

set(ART_BUILD_TESTS "Build ${PROJECT_NAME}'s unit tests" ON)

set(GIT_REPO_PREFIX "https://github.com" CACHE STRING "git repository url prefix")

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

# Reference: https://github.com/codecov/example-cpp11-cmake/blob/master/CMakeLists.txt
option(CODE_COVERAGE "Enable coverage reporting" OFF)
if (CODE_COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # Add required flags (GCC & LLVM/Clang)
    target_compile_options(${PROJECT_NAME} INTERFACE
            -O0        # no optimization
            -g         # generate debug info
            --coverage # sets all required flags
            )
    if (CMAKE_VERSION VERSION_GREATER_EQUAL 3.13)
        target_link_options(${PROJECT_NAME} INTERFACE --coverage)
    else ()
        target_link_libraries(${PROJECT_NAME} INTERFACE --coverage)
    endif ()
endif (CODE_COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
