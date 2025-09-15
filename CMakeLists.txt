cmake_minimum_required(VERSION 3.10)

project(afp VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -O2")

# Include directories
include_directories(include)

# Find source files
file(GLOB_RECURSE SOURCES "src/*.cpp")

# Find required packages
find_package(Threads REQUIRED)

# Create executable
add_executable(afp ${SOURCES})

# Link libraries
target_link_libraries(afp Threads::Threads)

# Install target
install(TARGETS afp DESTINATION bin)

# Custom target for running with usage info
add_custom_target(run
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/afp --help
    DEPENDS afp
    COMMENT "Running afp with --help to show usage"
)
