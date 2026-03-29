#!/bin/bash
# MARLFuzz Directory Structure Setup Script
# Automatically creates the required directory structure for your project

set -e  # Exit on error

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }
print_info() { echo -e "ℹ $1"; }

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                              ║"
echo "║                    MARLFuzz Directory Setup Script                           ║"
echo "║                                                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Configuration
BASE_DIR="/MARLFuzz"

print_info "This script will create the following structure:"
echo ""
echo "  /MARLFuzz/"
echo "  ├── Linux_bin/V1/        (Baseline binaries)"
echo "  ├── Linux_bin/V2/        (Updated binaries)"
echo "  ├── corpus/              (Fuzzing inputs)"
echo "  ├── dictionaries/        (AFL++ dictionaries)"
echo "  ├── workspaces/          (Analysis outputs)"
echo "  └── models/              (RL agent models)"
echo ""

# Check if directory exists
if [ -d "$BASE_DIR" ]; then
    print_warning "Directory $BASE_DIR already exists"
    read -p "Do you want to continue and potentially overwrite? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Setup cancelled"
        exit 0
    fi
fi

# Check permissions
if [ ! -w "$(dirname $BASE_DIR 2>/dev/null || echo '/')" ]; then
    print_error "No write permission to create $BASE_DIR"
    print_info "You may need to run with sudo or choose a different location"
    exit 1
fi

print_info "Creating directory structure..."
echo ""

# Create main directory
mkdir -p "$BASE_DIR"
print_success "Created: $BASE_DIR"

# Create binary directories
mkdir -p "$BASE_DIR/Linux_bin/V1"
mkdir -p "$BASE_DIR/Linux_bin/V2"
print_success "Created: $BASE_DIR/Linux_bin/V1"
print_success "Created: $BASE_DIR/Linux_bin/V2"

# Create corpus directories
mkdir -p "$BASE_DIR/corpus/llama_models/edge-cases"
mkdir -p "$BASE_DIR/corpus/onnx_models/edge-cases"
print_success "Created: $BASE_DIR/corpus/llama_models"
print_success "Created: $BASE_DIR/corpus/onnx_models"

# Create dictionary directory
mkdir -p "$BASE_DIR/dictionaries"
print_success "Created: $BASE_DIR/dictionaries"

# Create workspace directory
mkdir -p "$BASE_DIR/workspaces"
print_success "Created: $BASE_DIR/workspaces"

# Create models directory
mkdir -p "$BASE_DIR/models"
print_success "Created: $BASE_DIR/models"

echo ""
print_info "Creating fuzzing dictionaries..."

# Create Llama dictionary
cat > "$BASE_DIR/dictionaries/llama.dict" << 'EOF'
# Llama/GGML Fuzzing Dictionary
# Magic numbers and headers
ggml="GGML"
gguf="GGUF"
ggjt="GGJT"
ggla="GGLA"

# Tensor data types
f32="\x00\x00\x00\x00"
f16="\x01\x00\x00\x00"
q4_0="\x02\x00\x00\x00"
q4_1="\x03\x00\x00\x00"
q5_0="\x06\x00\x00\x00"
q5_1="\x07\x00\x00\x00"
q8_0="\x08\x00\x00\x00"

# Model architecture strings
llama="llama"
attention="attention"
feed_forward="feed_forward"
embedding="embedding"
norm="norm"
rope="rope"
tensor="tensor"

# Common patterns
version="\x00\x00\x00\x01"
magic="\x67\x67\x6d\x6c"
EOF
print_success "Created: $BASE_DIR/dictionaries/llama.dict"

# Create ONNX dictionary
cat > "$BASE_DIR/dictionaries/onnx.dict" << 'EOF'
# ONNX Fuzzing Dictionary
# Protobuf markers
onnx_model="\x08\x03"
pb_wire="\x0a"

# ONNX keywords
ir_version="ir_version"
opset="opset_import"
graph="graph"
node="node"
initializer="initializer"

# Node types
conv="Conv"
relu="Relu"
matmul="MatMul"
gemm="Gemm"
reshape="Reshape"
softmax="Softmax"
batchnorm="BatchNormalization"

# Data types
float="\x01"
uint8="\x02"
int8="\x03"
uint16="\x04"
int16="\x05"
int32="\x06"
int64="\x07"
string="\x08"
bool="\x09"

# Common values
zero="\x00\x00\x00\x00"
one="\x01\x00\x00\x00"
EOF
print_success "Created: $BASE_DIR/dictionaries/onnx.dict"

echo ""
print_info "Creating placeholder files..."

# Create README files in each directory
cat > "$BASE_DIR/Linux_bin/V1/README.md" << 'EOF'
# V1 - Baseline Binaries

Place your **older/baseline** version binaries here:

- llama-cli
- llama-server
- llama-bench
- libllama.so.0
- libggml.so.0
- libggml-base.so.0
- onnxruntime
- libonnxruntime.so

Make sure all executables have execute permissions:
```bash
chmod +x llama-cli llama-server llama-bench onnxruntime
```
EOF

cat > "$BASE_DIR/Linux_bin/V2/README.md" << 'EOF'
# V2 - Updated Binaries

Place your **newer/updated** version binaries here:

- llama-cli
- llama-server
- llama-bench
- libllama.so.0
- libggml.so.0
- libggml-base.so.0
- onnxruntime
- libonnxruntime.so

Make sure all executables have execute permissions:
```bash
chmod +x llama-cli llama-server llama-bench onnxruntime
```
EOF

cat > "$BASE_DIR/corpus/llama_models/README.md" << 'EOF'
# Llama Models Corpus

Place your GGUF/GGML model files here for fuzzing:

Recommended corpus:
- 10-20 diverse model files
- Various sizes (tiny, small, medium, large)
- Different quantization types (F32, F16, Q4, Q8, etc.)
- Edge cases in the `edge-cases/` subdirectory

Example:
```bash
wget https://huggingface.co/.../tiny-model.gguf
wget https://huggingface.co/.../small-model.gguf
```

Edge cases to include:
- Truncated files
- Invalid headers
- Oversized tensors
- Malformed metadata
EOF

cat > "$BASE_DIR/corpus/onnx_models/README.md" << 'EOF'
# ONNX Models Corpus

Place your ONNX model files here for fuzzing:

Recommended corpus:
- 10-20 diverse ONNX models
- Various architectures (CNN, RNN, Transformer)
- Different opsets
- Edge cases in the `edge-cases/` subdirectory

Example:
```bash
# Download sample models from ONNX Model Zoo
wget https://github.com/onnx/models/raw/main/.../model.onnx
```
EOF

print_success "Created README files in all directories"

# Set permissions
chmod -R 755 "$BASE_DIR"
print_success "Set directory permissions (755)"

echo ""
print_info "Creating helper scripts..."

# Create a helper script for copying binaries
cat > "$BASE_DIR/copy_binaries.sh" << 'EOF'
#!/bin/bash
# Helper script to copy binaries to MARLFuzz structure

echo "Copying binaries to MARLFuzz directory structure..."

# Example usage (modify paths as needed):
# V1_SOURCE="/path/to/old/build"
# V2_SOURCE="/path/to/new/build"

# Uncomment and modify these lines:
# cp "$V1_SOURCE"/llama-* /MARLFuzz/Linux_bin/V1/
# cp "$V1_SOURCE"/lib*.so* /MARLFuzz/Linux_bin/V1/
# cp "$V2_SOURCE"/llama-* /MARLFuzz/Linux_bin/V2/
# cp "$V2_SOURCE"/lib*.so* /MARLFuzz/Linux_bin/V2/

echo "Please edit this script with your actual source paths"
echo "Then uncomment the cp commands and run again"
EOF
chmod +x "$BASE_DIR/copy_binaries.sh"
print_success "Created: $BASE_DIR/copy_binaries.sh"

# Create verification script
cat > "$BASE_DIR/verify_setup.sh" << 'EOF'
#!/bin/bash
# Verify MARLFuzz setup

echo "Verifying MARLFuzz directory structure..."
echo ""

check_dir() {
    if [ -d "$1" ]; then
        echo "✓ $1 exists"
        return 0
    else
        echo "✗ $1 missing"
        return 1
    fi
}

check_file() {
    if [ -f "$1" ]; then
        echo "✓ $1 exists"
        return 0
    else
        echo "✗ $1 missing"
        return 1
    fi
}

# Check directories
check_dir "/MARLFuzz/Linux_bin/V1"
check_dir "/MARLFuzz/Linux_bin/V2"
check_dir "/MARLFuzz/corpus/llama_models"
check_dir "/MARLFuzz/corpus/onnx_models"
check_dir "/MARLFuzz/dictionaries"
check_dir "/MARLFuzz/workspaces"
check_dir "/MARLFuzz/models"

echo ""
echo "Checking for binaries in V1..."
ls -lh /MARLFuzz/Linux_bin/V1/

echo ""
echo "Checking for binaries in V2..."
ls -lh /MARLFuzz/Linux_bin/V2/

echo ""
echo "Checking corpus files..."
echo "Llama models: $(ls /MARLFuzz/corpus/llama_models/*.gguf 2>/dev/null | wc -l) files"
echo "ONNX models: $(ls /MARLFuzz/corpus/onnx_models/*.onnx 2>/dev/null | wc -l) files"

echo ""
if [ -f "/MARLFuzz/Linux_bin/V1/llama-cli" ]; then
    echo "Testing V1 llama-cli..."
    /MARLFuzz/Linux_bin/V1/llama-cli --help >/dev/null 2>&1 && echo "✓ V1 llama-cli executable" || echo "✗ V1 llama-cli not executable"
fi

if [ -f "/MARLFuzz/Linux_bin/V2/llama-cli" ]; then
    echo "Testing V2 llama-cli..."
    /MARLFuzz/Linux_bin/V2/llama-cli --help >/dev/null 2>&1 && echo "✓ V2 llama-cli executable" || echo "✗ V2 llama-cli not executable"
fi
EOF
chmod +x "$BASE_DIR/verify_setup.sh"
print_success "Created: $BASE_DIR/verify_setup.sh"

echo ""
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                              ║"
echo "║                        Setup Complete! ✓                                     ║"
echo "║                                                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

print_info "Directory structure created at: $BASE_DIR"
echo ""

print_info "Next steps:"
echo ""
echo "  1. Copy your binaries:"
echo "     V1 (baseline) → $BASE_DIR/Linux_bin/V1/"
echo "     V2 (updated)  → $BASE_DIR/Linux_bin/V2/"
echo ""
echo "  2. Add fuzzing corpus:"
echo "     GGUF models → $BASE_DIR/corpus/llama_models/"
echo "     ONNX models → $BASE_DIR/corpus/onnx_models/"
echo ""
echo "  3. Verify setup:"
echo "     $ $BASE_DIR/verify_setup.sh"
echo ""
echo "  4. Run your first analysis:"
echo "     $ python3 marl_vuln_forecast.py \\"
echo "         --baseline $BASE_DIR/Linux_bin/V1/llama-cli \\"
echo "         --updated $BASE_DIR/Linux_bin/V2/llama-cli \\"
echo "         --corpus $BASE_DIR/corpus/llama_models"
echo ""

print_info "Helper scripts created:"
echo "  - $BASE_DIR/copy_binaries.sh  (template for copying binaries)"
echo "  - $BASE_DIR/verify_setup.sh   (verify directory structure)"
echo ""

print_success "MARLFuzz is ready for binary vulnerability forecasting! 🚀"
