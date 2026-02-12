# Quick Start Guide
## MARL Vulnerability Forecasting for AI Runtime Binaries

⚡ **Get started in 5 minutes!**

---

## 🚀 Installation (One-Time Setup)

### Option 1: Automated Install (Recommended)
```bash
chmod +x install.sh
./install.sh
source venv/bin/activate
```

### Option 2: Manual Install
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install system tools (Ubuntu/Debian)
sudo apt-get install afl++ radare2
```

---

## 🎯 Your First Analysis (3 Easy Steps)

### Step 1: Prepare Your Binaries
```bash
# You need:
# - Baseline binary (old version)
# - Updated binary (new version)  
# - Fuzzing corpus (test inputs)

# Example structure:
binaries/
  ├── llama-v1.0/
  │   └── llama-cli
  └── llama-v1.1/
      └── llama-cli

corpus/
  └── llama_models/
      ├── model1.gguf
      ├── model2.gguf
      └── model3.gguf
```

### Step 2: Run Analysis
```bash
python3 marl_vuln_forecast.py \
  --baseline binaries/llama-v1.0/llama-cli \
  --updated binaries/llama-v1.1/llama-cli \
  --corpus corpus/llama_models \
  --workspace ./my_analysis
```

### Step 3: View Results
```bash
# Results are in: ./my_analysis/forecast_results.json

cat my_analysis/forecast_results.json | python3 -m json.tool
```

---

## 📊 Understanding Your Results

```json
{
  "risk_category": "high",           // low, medium, high, critical
  "combined_risk_score": 78.45,      // 0-100 scale
  "structural_risk_score": 72.30,    // BinDiff findings
  "behavioral_risk_score": 85.60,    // Fuzzing findings
  "dependency_risk_score": 15.00,    // Library risks
  
  "recommendations": [
    "CRITICAL: 8 memory-related functions modified...",
    "WARNING: 9 new unique crashes detected...",
    "Review 12 parsing function changes..."
  ]
}
```

**Risk Categories:**
- 🟢 **Low (0-30)**: Safe to deploy
- 🟡 **Medium (30-60)**: Review recommended
- 🟠 **High (60-85)**: Extensive testing required
- 🔴 **Critical (85-100)**: Consider rollback

---

## 🔧 Common Use Cases

### Use Case 1: Quick Security Check (30 minutes)
```bash
python3 marl_vuln_forecast.py \
  --baseline old_binary \
  --updated new_binary \
  --corpus test_corpus \
  --fuzz-timeout 1800  # 30 min fuzzing
```

### Use Case 2: Thorough Analysis (2-4 hours)
```bash
python3 marl_vuln_forecast.py \
  --baseline old_binary \
  --updated new_binary \
  --corpus test_corpus \
  --fuzz-timeout 7200 \  # 2 hours fuzzing
  --save-models          # Save learned strategies
```

### Use Case 3: Analyze Shared Library
```bash
python3 marl_vuln_forecast.py \
  --baseline /lib/old/libllama.so.0 \
  --updated /lib/new/libllama.so.0 \
  --corpus corpus/llama_models
```

### Use Case 4: Batch Analysis
```bash
# Analyze multiple binaries
python3 example_runner.py
# Select option 8 (Batch Analysis)
```

---

## 🎓 Learn by Example

### Run Interactive Examples
```bash
python3 example_runner.py
```

**Available Examples:**
1. Basic Llama Binary Analysis
2. Llama Shared Library Analysis  
3. ONNX Runtime Analysis
4. Dependency Update Simulation
5. Continuous Learning (Model Persistence)
6. Custom AFL++ Configuration
7. Standalone BinDiff Analysis
8. Batch Analysis

---

## ⚙️ Configuration (Optional)

Edit `config.json` to customize:

```json
{
  "fuzzing": {
    "afl_config": {
      "timeout": 2000,        // Execution timeout (ms)
      "cores": 8,             // CPU cores for fuzzing
      "parallel_instances": 4 // Parallel fuzzers
    }
  },
  "risk_scoring": {
    "weights": {
      "structural_risk": 0.4,  // Adjust importance
      "behavioral_risk": 0.4,
      "dependency_risk": 0.2
    }
  }
}
```

---

## 🐛 Troubleshooting

### Problem: "AFL++ not found"
**Solution:**
```bash
sudo apt-get install afl++
# Or build from source: https://github.com/AFLplusplus/AFLplusplus
```

### Problem: "BinDiff not found"
**Solution:**
- Framework has fallback to radare2
- Install BinDiff: https://www.zynamics.com/bindiff.html
- Or install radare2: `sudo apt-get install radare2`

### Problem: Low memory / crashes
**Solution:**
```bash
# Reduce parallel instances in config.json
"parallel_instances": 2

# Reduce memory limit
"memory_limit": 4096
```

### Problem: Analysis taking too long
**Solution:**
```bash
# Reduce fuzzing timeout
--fuzz-timeout 900  # 15 minutes instead of 1 hour
```

---

## 📚 Next Steps

### 1. Read Full Documentation
```bash
cat README.md          # Comprehensive guide
cat ARCHITECTURE.md    # Technical deep-dive
```

### 2. Explore Advanced Features
- Continuous learning with model persistence
- Dependency update simulation
- Custom fuzzing strategies
- Batch analysis of multiple binaries

### 3. Integrate with Your Workflow
```bash
# Example CI/CD integration
./run_analysis.sh new_build.so && deploy || rollback
```

### 4. Contribute or Extend
- Add new binary formats
- Improve RL algorithms
- Enhance risk scoring
- Build web dashboard

---

## 🎯 Real-World Example

**Scenario:** You're deploying Llama.cpp v1.1 to production

```bash
# 1. Run analysis
python3 marl_vuln_forecast.py \
  --baseline production/llama-v1.0/llama-server \
  --updated staging/llama-v1.1/llama-server \
  --corpus production/models \
  --workspace ./llama_v1.1_analysis \
  --save-models

# 2. Check results
cat ./llama_v1.1_analysis/forecast_results.json

# 3. Decision tree
# - Low/Medium risk → Deploy to staging
# - High risk → Extended testing
# - Critical risk → Block deployment, investigate
```

---

## 💡 Tips for Best Results

1. **Use Representative Corpus**: Include diverse model files
2. **Give Enough Time**: Longer fuzzing = better results
3. **Learn Over Time**: Use `--save-models` and `--load-models`
4. **Start Small**: Try quick scans first, then deep analysis
5. **Monitor Resources**: Watch CPU and disk space during fuzzing

---

## 📞 Help & Support

**Documentation:**
- `README.md` - Full documentation
- `ARCHITECTURE.md` - System design
- `example_runner.py` - Interactive examples

**Get Help:**
```bash
python3 marl_vuln_forecast.py --help
```

**Report Issues:**
- Check logs: `cat vuln_forecast.log`
- Review workspace: `ls -R workspace/`

---

## ✅ Success Checklist

- [ ] Installation completed (`./install.sh`)
- [ ] Virtual environment activated
- [ ] Example analysis runs successfully
- [ ] Results JSON generated
- [ ] Understand risk categories
- [ ] Ready for production use!

---

**🎉 You're all set! Start forecasting vulnerabilities!**

**Pro Tip:** Start with Example 1 from `example_runner.py` to see the system in action.
