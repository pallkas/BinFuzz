# Multi-Agent Reinforcement Learning Vulnerability Forecasting

**AI Runtime Binary Security Analysis Framework**

A sophisticated framework that combines Multi-Agent Reinforcement Learning (MARL), Google BinDiff, and AFL++ coverage-guided fuzzing to forecast vulnerability risks in AI runtime binaries (Llama, ONNX Runtime, etc.).

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Key Features](#key-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Detailed Usage](#detailed-usage)
- [Configuration](#configuration)
- [Examples](#examples)
- [API Reference](#api-reference)
- [Research Background](#research-background)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

This framework addresses the critical challenge of predicting regression vulnerabilities in AI runtime systems when binaries are updated. Unlike traditional post-disclosure analysis, our approach enables **proactive security assessment** before vulnerabilities are exploited.

### The Problem

AI inference engines (Llama, ONNX Runtime) are:
- Written in C/C++ with complex memory management
- Frequently updated for performance and security
- Often deployed as precompiled binaries without source access
- Updates frequently introduce regression vulnerabilities

### The Solution

Our MARL-based framework:
1. **Analyzes structural changes** using Google BinDiff
2. **Measures behavioral differences** with AFL++ fuzzing
3. **Maps dependency risks** across shared library updates
4. **Learns optimal analysis strategies** through reinforcement learning
5. **Generates actionable forecasts** with risk scores and recommendations

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  MARL Vulnerability Forecaster                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   BinDiff    │  │   Fuzzing    │  │  Dependency  │          │
│  │   Analyzer   │  │ Coordinator  │  │    Mapper    │          │
│  │    Agent     │  │    Agent     │  │    Agent     │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                  │                  │                  │
│         └──────────────────┴──────────────────┘                  │
│                            │                                     │
│                   ┌────────▼────────┐                            │
│                   │  Risk Evaluator │                            │
│                   │     Agent       │                            │
│                   └────────┬────────┘                            │
│                            │                                     │
│                   ┌────────▼────────┐                            │
│                   │  Vulnerability  │                            │
│                   │    Forecast     │                            │
│                   └─────────────────┘                            │
└─────────────────────────────────────────────────────────────────┘
```

### Agent Roles

1. **BinDiff Analyzer Agent**
   - Compares baseline and updated binaries
   - Identifies structural changes in functions
   - Learns optimal analysis depth based on binary characteristics

2. **Fuzzing Coordinator Agent**
   - Manages AFL++ fuzzing campaigns
   - Selects fuzzing strategies (aggressive, coverage-focused, etc.)
   - Learns which strategies find the most vulnerabilities

3. **Dependency Mapper Agent**
   - Maps shared library dependencies
   - Simulates mixed update scenarios
   - Identifies dependency-induced risks

4. **Risk Evaluator Agent**
   - Synthesizes all analysis results
   - Calculates comprehensive risk scores
   - Generates actionable recommendations

## ✨ Key Features

### 🤖 Multi-Agent Reinforcement Learning
- **Q-learning** based agents that improve over time
- **Experience replay** for efficient learning
- **Model persistence** for continuous improvement
- **Epsilon-greedy exploration** balancing exploration vs. exploitation

### 🔍 Binary Structural Analysis
- **Google BinDiff integration** for precise function matching
- **CFG complexity analysis** to detect control flow changes
- **Memory and parsing function detection** for high-risk areas
- **Fallback analysis** using radare2 when BinDiff unavailable

### 🐛 Coverage-Guided Fuzzing
- **AFL++ integration** with advanced features (CMPLOG, LAF-Intel, RedQueen)
- **Parallel fuzzing** with multiple strategies
- **Custom dictionaries** for Llama (GGML/GGUF) and ONNX formats
- **Coverage comparison** to detect behavioral divergence

### 📊 Comprehensive Risk Scoring
- **Multi-dimensional scoring**: Structural + Behavioral + Dependency
- **Weighted risk categories**: Low, Medium, High, Critical
- **Actionable recommendations** for each risk level
- **Detailed reports** in JSON format

### 🔄 Dependency Analysis
- **Shared library mapping** using ldd
- **Update propagation analysis** across dependency graphs
- **Mixed version simulation** (e.g., old lib + new lib combinations)

## 📦 Installation

### Prerequisites

```bash
# System requirements
- Ubuntu 20.04+ or similar Linux distribution
- Python 3.8+
- 16GB+ RAM recommended
- Multi-core CPU for parallel fuzzing

# Required tools
- AFL++ (fuzzing)
- Google BinDiff (binary diffing) - Optional, has fallback
- IDA Pro (disassembly) - Optional, has fallback with radare2
- radare2 (alternative disassembler) - Optional fallback
```

### Step 1: Install System Dependencies

```bash
# Install AFL++
sudo apt-get update
sudo apt-get install -y afl++ build-essential

# Install radare2 (fallback disassembler)
sudo apt-get install -y radare2

# Optional: Install Google BinDiff
# Download from: https://www.zynamics.com/bindiff.html
# Follow installation instructions
```

### Step 2: Install Python Dependencies

```bash
pip install numpy scipy pandas matplotlib
pip install logging pathlib dataclasses
```

### Step 3: Clone and Setup

```bash
# Clone the repository (or copy files)
git clone <your-repo-url>
cd marl-vuln-forecast

# Make scripts executable
chmod +x marl_vuln_forecast.py
chmod +x example_runner.py

# Verify installation
python3 marl_vuln_forecast.py --help
```

### Step 4: Configure Paths

Edit `config.json` to set paths for your environment:

```json
{
  "bindiff": {
    "bindiff_path": "/opt/bindiff/bin/bindiff",
    "ida_path": "/opt/ida/idat64"
  },
  "fuzzing": {
    "corpus_directories": {
      "llama": "/path/to/your/llama/models",
      "onnx": "/path/to/your/onnx/models"
    }
  }
}
```

## 🚀 Quick Start

### Basic Usage

```bash
python3 marl_vuln_forecast.py \
    --baseline /path/to/old/llama-cli \
    --updated /path/to/new/llama-cli \
    --corpus /path/to/fuzzing/corpus \
    --workspace ./my_analysis
```

### With Options

```bash
python3 marl_vuln_forecast.py \
    --baseline /path/to/old/binary \
    --updated /path/to/new/binary \
    --corpus /path/to/corpus \
    --workspace ./workspace \
    --fuzz-timeout 7200 \
    --load-models \
    --save-models
```

### Example Output

```
================================================================================
Starting Multi-Agent Vulnerability Forecast
Baseline: /path/to/old/llama-cli
Updated:  /path/to/new/llama-cli
================================================================================

[STAGE 1] Dependency Mapping
Baseline dependencies: 5
Updated dependencies: 5
Dependency risk score: 2.50

[STAGE 2] BinDiff Structural Analysis
Detected 47 structural changes
  - Memory-related: 8
  - Parsing-related: 12

[STAGE 3] Fuzzing Baseline Binary
Baseline fuzzing: 3 crashes, 87.45% coverage

[STAGE 4] Fuzzing Updated Binary
Updated fuzzing: 12 crashes, 89.23% coverage

[STAGE 5] Comprehensive Risk Evaluation

FINAL FORECAST:
  Risk Category: HIGH
  Combined Risk Score: 78.45/100
  Structural Risk: 72.30
  Behavioral Risk: 85.60
  Dependency Risk: 15.00

Recommendations:
  1. CRITICAL: 8 memory-related functions modified. Conduct thorough memory 
     safety audit with AddressSanitizer.
  2. WARNING: 9 new unique crashes detected. Review crash dumps and consider 
     rolling back update.
  3. Review 12 parsing function changes. Test with malformed model files and 
     edge cases.
```

## 📚 Detailed Usage

### 1. Analyzing Llama Binaries

```python
from marl_vuln_forecast import MARLVulnerabilityForecaster

forecaster = MARLVulnerabilityForecaster(workspace_dir="./llama_analysis")

forecast = forecaster.forecast_vulnerability(
    baseline_binary="./llama-v1.0/llama-cli",
    updated_binary="./llama-v1.1/llama-cli",
    corpus_dir="./corpus/gguf_models",
    config={
        'fuzz_timeout': 3600,  # 1 hour
    }
)

print(f"Risk: {forecast.risk_category}")
print(f"Score: {forecast.combined_risk_score}/100")
```

### 2. Analyzing Shared Libraries

```python
# Analyze libllama.so
forecast_libllama = forecaster.forecast_vulnerability(
    "./v1.0/libllama.so.0",
    "./v1.1/libllama.so.0",
    "./corpus/gguf_models"
)

# Analyze libggml.so
forecast_libggml = forecaster.forecast_vulnerability(
    "./v1.0/libggml.so.0",
    "./v1.1/libggml.so.0",
    "./corpus/gguf_models"
)
```

### 3. Custom AFL++ Configuration

```python
from afl_integration import AFLPlusPlusManager, AFLConfig

manager = AFLPlusPlusManager()

# Create custom config
config = AFLConfig(
    timeout=5000,           # 5 seconds per execution
    memory_limit=16384,     # 16GB
    cores=8,
    power_schedule="explore",
    use_cmplog=True,
    use_laf=True
)

# Create dictionary for Llama
dict_path = manager.create_fuzzing_dictionary("llama")

# Start fuzzing
processes = manager.parallel_fuzzing(
    binary_path="./llama-cli",
    corpus_dir="./corpus",
    output_dir="./afl_output",
    config=config,
    num_instances=4
)
```

### 4. Standalone BinDiff Analysis

```python
from bindiff_integration import BinDiffAnalyzer

analyzer = BinDiffAnalyzer()

# Create diff database
db_path = analyzer.create_bindiff_database(
    "baseline.so",
    "updated.so",
    "./bindiff_output"
)

# Parse results
matches, diffs = analyzer.parse_bindiff_results(db_path)

# Identify high-risk changes
high_risk = analyzer.identify_high_risk_changes(diffs, similarity_threshold=0.8)

# Generate report
analyzer.generate_diff_report(matches, diffs, "./report.json")
```

### 5. Continuous Learning

```python
# Initialize with model loading
forecaster = MARLVulnerabilityForecaster(workspace_dir="./workspace")
forecaster.load_models()  # Load pre-trained Q-tables

# Run multiple analyses
for baseline, updated in binary_pairs:
    forecast = forecaster.forecast_vulnerability(baseline, updated, corpus)

# Save improved models
forecaster.save_models()
```

## ⚙️ Configuration

### Configuration File Structure

```json
{
  "fuzzing": {
    "afl_config": {
      "timeout": 2000,
      "memory_limit": 8192,
      "cores": 8,
      "power_schedule": "explore",
      "use_cmplog": true,
      "parallel_instances": 4
    }
  },
  "marl_config": {
    "agents": {
      "bindiff_analyzer": {
        "learning_rate": 0.01,
        "discount_factor": 0.95,
        "epsilon": 0.1
      }
    }
  },
  "risk_scoring": {
    "weights": {
      "structural_risk": 0.4,
      "behavioral_risk": 0.4,
      "dependency_risk": 0.2
    }
  }
}
```

### Key Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `fuzz_timeout` | Fuzzing duration per binary (seconds) | 3600 |
| `learning_rate` | RL agent learning rate | 0.01 |
| `epsilon` | Exploration rate for RL | 0.1 |
| `similarity_threshold` | BinDiff similarity threshold for high-risk | 0.8 |
| `power_schedule` | AFL++ power schedule | "explore" |

## 📖 Examples

See `example_runner.py` for 8 comprehensive examples:

1. **Basic Analysis**: Simple binary comparison
2. **Shared Libraries**: Analyze multiple .so files
3. **ONNX Runtime**: ONNX-specific analysis
4. **Dependency Simulation**: Test mixed library versions
5. **Continuous Learning**: Model persistence and improvement
6. **Custom AFL Config**: Advanced fuzzing configurations
7. **Standalone BinDiff**: BinDiff without MARL
8. **Batch Analysis**: Analyze multiple binary pairs

```bash
python3 example_runner.py
```

## 📊 API Reference

### MARLVulnerabilityForecaster

Main orchestrator class for the entire framework.

```python
class MARLVulnerabilityForecaster:
    def __init__(self, workspace_dir: str = "./workspace"):
        """Initialize forecaster with workspace directory"""
    
    def forecast_vulnerability(
        self,
        baseline_binary: str,
        updated_binary: str,
        corpus_dir: str,
        config: Optional[Dict] = None
    ) -> VulnerabilityForecast:
        """Execute complete vulnerability forecasting pipeline"""
    
    def save_models(self):
        """Save all agent Q-tables"""
    
    def load_models(self):
        """Load all agent Q-tables"""
```

### VulnerabilityForecast

Result object containing forecast information.

```python
@dataclass
class VulnerabilityForecast:
    binary_pair: Tuple[str, str]
    structural_risk_score: float
    behavioral_risk_score: float
    dependency_risk_score: float
    combined_risk_score: float
    risk_category: str  # low, medium, high, critical
    changed_functions: List[StructuralChange]
    fuzzing_divergence: Dict
    recommendations: List[str]
```

### AFLPlusPlusManager

Manager for AFL++ fuzzing campaigns.

```python
class AFLPlusPlusManager:
    def prepare_corpus(self, corpus_dir: str, output_dir: str, 
                      binary_path: str) -> str:
        """Prepare and minimize fuzzing corpus"""
    
    def start_fuzzing_campaign(
        self,
        binary_path: str,
        corpus_dir: str,
        output_dir: str,
        config: AFLConfig
    ) -> subprocess.Popen:
        """Start AFL++ fuzzing campaign"""
    
    def parallel_fuzzing(
        self,
        binary_path: str,
        corpus_dir: str,
        output_dir: str,
        config: AFLConfig,
        num_instances: int = 4
    ) -> List[subprocess.Popen]:
        """Launch parallel fuzzing instances"""
```

### BinDiffAnalyzer

Interface to Google BinDiff.

```python
class BinDiffAnalyzer:
    def create_bindiff_database(
        self,
        binary1: str,
        binary2: str,
        output_dir: str
    ) -> str:
        """Create BinDiff database comparing two binaries"""
    
    def parse_bindiff_results(
        self,
        bindiff_db: str
    ) -> Tuple[List[FunctionMatch], List[FunctionDiff]]:
        """Parse BinDiff database"""
    
    def identify_high_risk_changes(
        self,
        diffs: List[FunctionDiff],
        similarity_threshold: float = 0.8
    ) -> List[FunctionDiff]:
        """Filter high-risk function changes"""
```

## 🔬 Research Background

This framework implements concepts from the research proposal:

**"Forecasting Vulnerabilities in AI Runtime Binaries using Google BinDiff and Coverage-Guided Fuzzing"**

### Key Innovations

1. **Binary-Level Analysis**: Operates without source code access
2. **Predictive Assessment**: Forecasts risks before exploitation
3. **Multi-Agent Learning**: Agents improve analysis strategies over time
4. **Dependency-Aware**: Models real-world update scenarios

### References

[1] Larissa Braz et al. "An exploratory study on regression vulnerabilities." ESEM 2022.

[2] Ruyan Lin et al. "Vulnerabilities and security patches detection in OSS: a survey." ACM Computing Surveys 2024.

[3] Sanjay Rawat et al. "VUzzer: Application-aware evolutionary fuzzing." NDSS 2017.

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- Additional RL algorithms (DQN, PPO, A3C)
- More sophisticated reward functions
- Integration with additional binary analysis tools
- Support for more AI runtime formats
- Enhanced crash triage and deduplication
- Web-based visualization dashboard

## 📄 License

This project is provided for research and educational purposes. Please refer to individual tool licenses:
- AFL++: Apache License 2.0
- Google BinDiff: Commercial license required
- IDA Pro: Commercial license required
- radare2: LGPL

## 🙏 Acknowledgments

- AFL++ team for the advanced fuzzing framework
- Google for BinDiff binary analysis tools
- Llama.cpp and ONNX Runtime teams for excellent AI runtimes
- Research community for vulnerability detection insights

## 📞 Contact

For questions or collaboration:
- Author: Pallase Kasdorf
- Project: AI Runtime Vulnerability Forecasting
- Date: February 2026

---

**Built with ❤️ for AI Security Research**
