enable_testing()
include(CTest)
include(FetchContent)

FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com.cnpmjs.org/google/googletest.git
        GIT_TAG release-1.10.0
        GIT_SHALLOW TRUE
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(install_gtest OFF)
set(install_gmock OFF)

FetchContent_MakeAvailable(googletest)

# Add test executables
file(GLOB ART_TEST_SOURCES "${PROJECT_SOURCE_DIR}/test/*test.cpp")

foreach (art_test_source ${ART_TEST_SOURCES})
    # Create a human readable name.
    get_filename_component(art_test_filename ${art_test_source} NAME)
    string(REPLACE ".cpp" "" art_test_name ${art_test_filename})

    add_executable(${art_test_name} ${art_test_source})
    target_link_libraries(${art_test_name} ${PROJECT_NAME} gtest_main)
    target_include_directories(${art_test_name} PRIVATE ${PROJECT_SOURCE_DIR}/src)

    add_test(NAME ${art_test_name} COMMAND ${art_test_name})
endforeach (art_test_source ${ART_TEST_SOURCES})