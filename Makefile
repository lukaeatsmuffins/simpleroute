# Makefile wrapper for CMake build system
# This provides convenient targets for common build operations

BUILD_DIR = build
CMAKE_BUILD_TYPE ?= Release

.PHONY: all clean install run help

# Default target
all: $(BUILD_DIR)
	@echo "Building AFP..."
	@cd $(BUILD_DIR) && make

# Create build directory and configure CMake
$(BUILD_DIR):
	@echo "Configuring CMake..."
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE) ..

# Build the project
build: all

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -f afp

# Install the executable
install: all
	@echo "Installing AFP..."
	@cd $(BUILD_DIR) && sudo make install

# Run the executable with usage information
run: all
	@echo "Running AFP with usage information..."
	@cd $(BUILD_DIR) && make run

# Debug build
debug:
	@echo "Building debug version..."
	@$(MAKE) CMAKE_BUILD_TYPE=Debug

# Show help
help:
	@echo "Available targets:"
	@echo "  all/build    - Build the project (default)"
	@echo "  clean        - Remove build artifacts"
	@echo "  install      - Install the executable (requires sudo)"
	@echo "  run          - Build and run with usage information"
	@echo "  debug        - Build debug version"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Environment variables:"
	@echo "  CMAKE_BUILD_TYPE - Build type (Release, Debug, RelWithDebInfo, MinSizeRel)"
	@echo "                     Default: Release"
