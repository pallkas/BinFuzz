#!/bin/bash
# Installation script for MARL Vulnerability Forecasting Framework
# Author: Pallase Kasdorf
# Date: February 2026

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                              ║"
echo "║      MARL Vulnerability Forecasting Framework - Installation                ║"
echo "║                                                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "ℹ $1"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    print_warning "Running as root. This is not recommended."
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check OS
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    print_error "This script is designed for Linux systems"
    print_info "You may need to manually install dependencies on other systems"
    exit 1
fi

print_info "Checking system requirements..."

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
REQUIRED_VERSION="3.8"
if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then 
    print_error "Python 3.8+ required. Found: $PYTHON_VERSION"
    exit 1
else
    print_success "Python version: $PYTHON_VERSION"
fi

# Check available memory
TOTAL_MEM=$(free -g | awk '/^Mem:/{print $2}')
if [ "$TOTAL_MEM" -lt 8 ]; then
    print_warning "Less than 8GB RAM detected. 16GB+ recommended for fuzzing"
else
    print_success "System memory: ${TOTAL_MEM}GB"
fi

# Check available disk space
AVAILABLE_SPACE=$(df -BG "$SCRIPT_DIR" | awk 'NR==2 {print $4}' | sed 's/G//')
if [ "$AVAILABLE_SPACE" -lt 20 ]; then
    print_warning "Less than 20GB free disk space. More space recommended for fuzzing corpus and results"
else
    print_success "Available disk space: ${AVAILABLE_SPACE}GB"
fi

echo ""
print_info "Installing Python dependencies..."

# Create virtual environment
if [ ! -d "venv" ]; then
    python3 -m venv venv
    print_success "Virtual environment created"
else
    print_info "Virtual environment already exists"
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip > /dev/null 2>&1
print_success "pip upgraded"

# Install Python requirements
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    print_success "Python dependencies installed"
else
    print_warning "requirements.txt not found, installing core dependencies..."
    pip install numpy scipy
fi

echo ""
print_info "Checking for optional binary analysis tools..."

# Check for AFL++
if command -v afl-fuzz &> /dev/null; then
    AFL_VERSION=$(afl-fuzz --version 2>&1 | head -n1)
    print_success "AFL++ found: $AFL_VERSION"
else
    print_warning "AFL++ not found"
    print_info "To install AFL++:"
    echo "    sudo apt-get install afl++"
    echo "    or visit: https://github.com/AFLplusplus/AFLplusplus"
fi

# Check for radare2
if command -v r2 &> /dev/null; then
    R2_VERSION=$(r2 -v 2>&1 | head -n1)
    print_success "radare2 found: $R2_VERSION"
else
    print_warning "radare2 not found"
    print_info "To install radare2:"
    echo "    sudo apt-get install radare2"
fi

# Check for BinDiff
if [ -f "/opt/bindiff/bin/bindiff" ]; then
    print_success "Google BinDiff found at /opt/bindiff"
elif [ -f "/usr/bin/bindiff" ]; then
    print_success "Google BinDiff found at /usr/bin"
else
    print_warning "Google BinDiff not found (optional, has fallback)"
    print_info "Download from: https://www.zynamics.com/bindiff.html"
fi

# Check for IDA Pro
if [ -f "/opt/ida/idat64" ]; then
    print_success "IDA Pro found at /opt/ida"
else
    print_warning "IDA Pro not found (optional, has fallback)"
fi

echo ""
print_info "Creating directory structure..."

# Create necessary directories
mkdir -p corpus/llama_models
mkdir -p corpus/onnx_models
mkdir -p test_binaries
mkdir -p workspaces
mkdir -p models

print_success "Directory structure created"

echo ""
print_info "Setting up configuration..."

# Create default config if it doesn't exist
if [ ! -f "config.json" ]; then
    print_warning "config.json not found, using template"
    # Config should already exist from our creation
else
    print_success "Configuration file ready"
fi

# Make scripts executable
chmod +x marl_vuln_forecast.py 2>/dev/null || true
chmod +x example_runner.py 2>/dev/null || true
chmod +x afl_integration.py 2>/dev/null || true
chmod +x bindiff_integration.py 2>/dev/null || true
print_success "Scripts made executable"

echo ""
print_info "Downloading sample corpus (optional)..."

# Function to download sample models
download_samples() {
    print_info "This will download ~500MB of sample GGUF models for testing"
    read -p "Download samples? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        mkdir -p corpus/llama_models/samples
        # Note: These are example URLs - replace with actual model URLs
        print_info "Please manually download sample models from:"
        echo "    - https://huggingface.co/models (GGUF format)"
        echo "    - Place them in: $SCRIPT_DIR/corpus/llama_models/"
    fi
}

# Uncomment to enable sample download prompt
# download_samples

echo ""
print_info "Running verification tests..."

# Test Python imports
python3 -c "
import numpy
import sys
print('NumPy import: OK')
" && print_success "Python imports verified" || print_error "Python import failed"

# Test script syntax
python3 -m py_compile marl_vuln_forecast.py 2>/dev/null && \
    print_success "Main script syntax verified" || \
    print_warning "Main script syntax check failed"

echo ""
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                              ║"
echo "║                          Installation Complete!                             ║"
echo "║                                                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

print_info "Next steps:"
echo ""
echo "  1. Activate the virtual environment:"
echo "     $ source venv/bin/activate"
echo ""
echo "  2. Edit config.json to set your paths"
echo ""
echo "  3. Run example scenarios:"
echo "     $ python3 example_runner.py"
echo ""
echo "  4. Or run a basic analysis:"
echo "     $ python3 marl_vuln_forecast.py --baseline <old> --updated <new> --corpus <dir>"
echo ""
echo "  5. View documentation:"
echo "     $ cat README.md"
echo ""

print_info "For questions or issues, refer to README.md"
echo ""

# Optional: Run a quick test
read -p "Run a quick system test? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_info "Running quick test..."
    python3 << 'EOF'
from marl_vuln_forecast import MARLVulnerabilityForecaster
import os
from pathlib import Path

# Create minimal test setup
os.makedirs("./test_setup", exist_ok=True)
Path("./test_setup/baseline").touch()
Path("./test_setup/updated").touch()
os.makedirs("./test_setup/corpus", exist_ok=True)
Path("./test_setup/corpus/test.bin").touch()

print("✓ Test files created")

# Test forecaster initialization
forecaster = MARLVulnerabilityForecaster(workspace_dir="./test_setup/workspace")
print("✓ Forecaster initialized")

print("\n✓ Quick test passed!")
print("  Remove test files with: rm -rf ./test_setup")
EOF
fi

print_success "Setup complete! Happy vulnerability forecasting! 🔍🐛"
