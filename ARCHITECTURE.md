# MARL Vulnerability Forecasting System
## Project Summary & Architecture Overview

**Author:** Pallase Kasdorf  
**Date:** February 2026  
**Research Focus:** AI Runtime Binary Security

---

## 🎯 Executive Summary

This Multi-Agent Reinforcement Learning (MARL) framework represents a novel approach to predicting security vulnerabilities in AI runtime binaries before they are exploited. By combining Google BinDiff for structural analysis, AFL++ for behavioral testing, and Q-learning agents that improve over time, the system provides actionable security forecasts for binary updates.

### Key Innovation
**Predictive vs. Reactive Security**: Traditional approaches detect vulnerabilities after crashes or exploits occur. Our framework forecasts vulnerability risk by analyzing structural and behavioral changes in updated binaries, enabling proactive security decisions.

---

## 📂 Project Structure

```
marl-vuln-forecast/
│
├── marl_vuln_forecast.py      # Main MARL orchestrator (5 agents)
├── afl_integration.py          # AFL++ fuzzing management
├── bindiff_integration.py      # Google BinDiff interface
├── example_runner.py           # 8 usage examples
│
├── config.json                 # System configuration
├── requirements.txt            # Python dependencies
├── install.sh                  # Installation script
├── README.md                   # Comprehensive documentation
├── ARCHITECTURE.md             # This file
│
├── corpus/                     # Fuzzing test cases
│   ├── llama_models/          # GGUF/GGML files
│   └── onnx_models/           # ONNX model files
│
├── test_binaries/             # Binaries under analysis
│   ├── llama/
│   └── onnx/
│
├── workspaces/                # Analysis workspaces
│   └── [per-analysis directories]
│
└── models/                    # Saved RL agent models
    ├── bindiff_agent.pkl
    ├── fuzzing_agent.pkl
    ├── dependency_agent.pkl
    └── risk_agent.pkl
```

---

## 🏗️ System Architecture

### High-Level Data Flow

```
┌──────────────┐
│   Baseline   │     ┌────────────┐
│    Binary    │────▶│            │
└──────────────┘     │  BinDiff   │     ┌──────────────┐
                     │  Analyzer  │────▶│              │
┌──────────────┐     │   Agent    │     │              │
│   Updated    │────▶│            │     │              │
│    Binary    │     └────────────┘     │              │
└──────────────┘                        │              │
                                        │              │
┌──────────────┐                        │     Risk     │
│   Fuzzing    │     ┌────────────┐     │  Evaluator   │────▶ Forecast
│   Corpus     │────▶│  Fuzzing   │────▶│    Agent     │      Output
└──────────────┘     │ Coordinator│     │              │
                     │   Agent    │     │              │
                     └────────────┘     │              │
                                        │              │
                     ┌────────────┐     │              │
                     │ Dependency │────▶│              │
                     │   Mapper   │     └──────────────┘
                     │   Agent    │
                     └────────────┘
```

### Component Details

#### 1. **BinDiff Analyzer Agent**
- **Purpose**: Structural change detection
- **Input**: Two binary versions
- **Output**: Function-level changes with similarity scores
- **RL Decision**: Analysis depth and focus areas
- **State Space**: Binary size, previous findings
- **Action Space**: full_analysis, focus_memory_functions, focus_parsing_functions, quick_scan
- **Reward**: Quality of high-risk findings

**Key Functions:**
```python
analyze_binary_diff(baseline, updated, output_dir)
  → List[StructuralChange]

_is_memory_related(function_name) → bool
_is_parsing_related(function_name) → bool
_calculate_analysis_reward(changes) → float
```

#### 2. **Fuzzing Coordinator Agent**
- **Purpose**: AFL++ campaign management
- **Input**: Binary + corpus + structural changes
- **Output**: Crash counts, coverage metrics
- **RL Decision**: Fuzzing strategy selection
- **State Space**: Binary characteristics, structural changes
- **Action Space**: aggressive_deep, coverage_focused, mutation_heavy, balanced, quick_exploration
- **Reward**: Crashes found + coverage achieved

**Key Functions:**
```python
coordinate_fuzzing(binary, corpus, structural_changes, timeout)
  → FuzzingResult

_execute_fuzzing(binary, corpus, strategy, timeout)
  → FuzzingResult
```

#### 3. **Dependency Mapper Agent**
- **Purpose**: Library dependency analysis
- **Input**: Binary paths
- **Output**: Dependency graph + risk scores
- **RL Decision**: Mapping depth and method
- **State Space**: Binary name and type
- **Action Space**: shallow_map, deep_recursive, symbol_analysis
- **Reward**: Completeness of dependency map

**Key Functions:**
```python
map_dependencies(binary_path)
  → Dict[str, List[str]]

analyze_update_propagation(old_deps, new_deps)
  → float (risk_score)
```

#### 4. **Risk Evaluator Agent**
- **Purpose**: Synthesize all findings into forecast
- **Input**: Structural + behavioral + dependency data
- **Output**: Comprehensive vulnerability forecast
- **RL Decision**: Risk weighting scheme
- **State Space**: Component risk scores
- **Action Space**: conservative, balanced, aggressive, adaptive
- **Reward**: Forecast accuracy (requires ground truth)

**Key Functions:**
```python
evaluate_risk(structural_changes, baseline_fuzzing, 
             updated_fuzzing, dependency_risk)
  → VulnerabilityForecast

_calculate_structural_risk(changes) → float
_calculate_behavioral_risk(baseline, updated) → float
_combine_scores(structural, behavioral, dependency, scheme) → float
```

---

## 🧠 Reinforcement Learning Design

### Q-Learning Implementation

Each agent maintains a Q-table: `Q(state, action) → expected_reward`

**Update Rule:**
```
Q(s,a) ← Q(s,a) + α[r + γ·max Q(s',a') - Q(s,a)]
where:
  α = learning rate (0.01)
  γ = discount factor (0.95)
  r = reward
  s' = next state
```

**Exploration Strategy:**
- Epsilon-greedy: ε = 0.1 (10% random exploration)
- Decay: ε → 0.01 over time
- Ensures balance between exploration and exploitation

**Experience Replay:**
- Buffer size: 10,000 experiences
- Enables learning from past successful strategies
- Improves sample efficiency

### State Representations

**BinDiff Agent:**
```python
state = f"size_delta_{delta//1024}k_changes_{num_changes}_mem_{num_memory}_parse_{num_parsing}"
```

**Fuzzing Agent:**
```python
state = f"changes_{num_changes}_risk_{high_risk_changes}_crashes_{crash_rate}"
```

**Risk Evaluator:**
```python
state = f"struct_{int(structural)}_behav_{int(behavioral)}_dep_{int(dependency)}"
```

### Reward Functions

**BinDiff Reward:**
```python
reward = (memory_changes * 2.0 + 
         parsing_changes * 1.5 + 
         low_similarity * 1.0) / total_changes
```

**Fuzzing Reward:**
```python
reward = unique_crashes * 10.0 + 
         coverage_percentage + 
         (execs_per_second / 1000)
```

---

## 🔍 Analysis Pipeline

### Stage-by-Stage Execution

**Stage 1: Dependency Mapping** (30 seconds)
```
Input:  Baseline binary, Updated binary
Process: ldd analysis, recursive dependency resolution
Output: Dependency graphs, propagation risk score
```

**Stage 2: Structural Analysis** (2-5 minutes)
```
Input:  Two binaries
Process: BinDiff comparison, function matching, CFG analysis
Output: List of StructuralChange objects with similarity scores
```

**Stage 3: Baseline Fuzzing** (30-60 minutes)
```
Input:  Baseline binary, corpus
Process: AFL++ fuzzing with chosen strategy
Output: FuzzingResult (crashes, coverage, stability)
```

**Stage 4: Updated Binary Fuzzing** (30-60 minutes)
```
Input:  Updated binary, corpus
Process: AFL++ fuzzing with same strategy
Output: FuzzingResult for comparison
```

**Stage 5: Risk Evaluation** (1 minute)
```
Input:  All previous stage outputs
Process: Score calculation, weighting, categorization
Output: VulnerabilityForecast with recommendations
```

### Total Analysis Time
- Quick scan: ~1-2 hours
- Standard analysis: ~2-4 hours  
- Deep analysis: ~4-8 hours

---

## 📊 Risk Scoring Methodology

### Component Scores

**1. Structural Risk (0-100)**
```python
For each changed function:
  base_score = (1.0 - similarity) * 20
  memory_bonus = 30 if memory-related
  parsing_bonus = 20 if parsing-related  
  complexity_penalty = |cfg_delta| * 2
  
  function_score = base + memory + parsing + complexity

structural_risk = avg(function_scores) * 1.5
```

**2. Behavioral Risk (0-100)**
```python
crash_increase = updated_crashes - baseline_crashes
coverage_delta = |updated_cov - baseline_cov|
stability_drop = baseline_stability - updated_stability

behavioral_risk = (crash_increase * 5.0 + 
                  coverage_delta * 0.5 + 
                  stability_drop * 2.0)
```

**3. Dependency Risk (0-100)**
```python
added_deps = new_deps - old_deps
removed_deps = old_deps - new_deps
changed_deps = deps with different versions

dependency_risk = (|added| * 1.5 + 
                   |removed| * 2.0 + 
                   |changed| * 1.0)
```

### Combined Score

**Default Weighting:**
```python
combined = (structural * 0.4 + 
           behavioral * 0.4 + 
           dependency * 0.2)
```

**Risk Categories:**
- **Low** (0-30): Minor changes, stable behavior
- **Medium** (30-60): Moderate changes, some new crashes
- **High** (60-85): Significant changes, crash increases
- **Critical** (85-100): Major changes, memory issues, many crashes

---

## 🎛️ Configuration Options

### Fuzzing Configuration
```json
{
  "timeout": 2000,          // ms per execution
  "memory_limit": 8192,     // MB
  "power_schedule": "explore",
  "use_cmplog": true,       // Compare coverage
  "use_laf": true,          // Look-ahead fuzzing
  "parallel_instances": 4
}
```

### MARL Configuration
```json
{
  "learning_rate": 0.01,
  "discount_factor": 0.95,
  "epsilon": 0.1,           // Exploration rate
  "epsilon_decay": 0.995
}
```

### Risk Scoring
```json
{
  "weights": {
    "structural_risk": 0.4,
    "behavioral_risk": 0.4,
    "dependency_risk": 0.2
  },
  "severity_multipliers": {
    "memory_function": 2.0,
    "parsing_function": 1.5
  }
}
```

---

## 🔧 Extension Points

### Adding New Agents

```python
class CustomAnalysisAgent(ReinforcementLearningAgent):
    def __init__(self):
        super().__init__(AgentRole.CUSTOM_ANALYZER)
        
    def analyze(self, data):
        state = self._create_state(data)
        action = self.choose_action(state, available_actions)
        result = self._execute_action(action, data)
        reward = self._calculate_reward(result)
        self.update_q_value(state, action, reward, next_state)
        return result
```

### Adding Binary Format Support

```python
# In afl_integration.py
def create_fuzzing_dictionary(self, binary_type: str):
    if binary_type == 'new_format':
        return {
            'magic="\\xAB\\xCD"',
            'header="NEW_FORMAT"',
            # ... format-specific tokens
        }
```

### Custom Risk Metrics

```python
# In marl_vuln_forecast.py - RiskEvaluatorAgent
def _calculate_custom_metric(self, data):
    # Your custom risk calculation
    return risk_score
```

---

## 📈 Performance Considerations

### Computational Requirements

**Minimum:**
- 8GB RAM
- 4 CPU cores
- 50GB disk space

**Recommended:**
- 16GB+ RAM
- 8+ CPU cores
- 200GB SSD

### Optimization Tips

1. **Parallel Fuzzing**: Use 1 fuzzer per CPU core
2. **Corpus Minimization**: Reduce redundant test cases
3. **Short Timeouts**: Start with quick scans (1 hour)
4. **Incremental Learning**: Load pre-trained models
5. **Distributed Analysis**: Run stages on different machines

---

## 🧪 Testing Strategy

### Unit Tests
```bash
pytest tests/test_agents.py
pytest tests/test_integration.py
```

### Integration Tests
```bash
python3 example_runner.py  # Runs all examples
```

### Validation
```bash
# Compare against known CVEs
python3 validate_forecasts.py --cve-database ./cves.json
```

---

## 🚀 Future Enhancements

### Planned Features
1. **Deep RL**: Replace Q-learning with DQN/PPO
2. **Multi-Binary Analysis**: Analyze entire dependency chains
3. **Web Dashboard**: Real-time monitoring and visualization
4. **CI/CD Integration**: Automated binary scanning in pipelines
5. **CVE Database**: Learn from historical vulnerabilities
6. **Symbolic Execution**: Combine with angr/KLEE
7. **Crash Triage**: Automatic exploit classification
8. **Distributed Fuzzing**: Cloud-based parallel fuzzing

### Research Directions
- Transfer learning across binary types
- Meta-learning for quick adaptation
- Ensemble methods with multiple analysis tools
- Explainable AI for security decisions

---

## 📚 References

### Academic Papers
1. Braz et al. (2022) - Regression vulnerabilities
2. Lin et al. (2024) - Vulnerability detection in OSS
3. Rawat et al. (2017) - VUzzer application-aware fuzzing

### Tools & Frameworks
- AFL++: https://github.com/AFLplusplus/AFLplusplus
- BinDiff: https://www.zynamics.com/bindiff.html
- Llama.cpp: https://github.com/ggerganov/llama.cpp
- ONNX Runtime: https://github.com/microsoft/onnxruntime

---

## 📞 Support & Contact

**Project Lead:** Pallase Kasdorf  
**Institution:** [Your Institution]  
**Email:** [Your Email]  
**GitHub:** [Repository URL]

**For Issues:**
- Bug reports: GitHub Issues
- Feature requests: GitHub Discussions
- Security concerns: security@[domain]

---

**Last Updated:** February 2026  
**Version:** 1.0.0  
**License:** Research & Educational Use
