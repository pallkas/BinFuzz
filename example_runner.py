#!/usr/bin/env python3
"""
Example Runner Script for MARL Vulnerability Forecasting System
Demonstrates various usage scenarios
"""

import sys
import os
import json
import logging
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from marl_vuln_forecast import MARLVulnerabilityForecaster, VulnerabilityForecast
from afl_integration import AFLPlusPlusManager, AFLConfig
from bindiff_integration import BinDiffAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vuln_forecast.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


def load_config(config_path: str = "config.json") -> dict:
    """Load configuration from JSON file"""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        logger.info(f"Configuration loaded from {config_path}")
        return config
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {config_path}")
        return {}
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in configuration file: {e}")
        return {}


def example_1_basic_analysis():
    """
    Example 1: Basic vulnerability forecast for Llama binaries
    """
    print("\n" + "="*80)
    print("EXAMPLE 1: Basic Llama Binary Analysis")
    print("="*80 + "\n")
    
    # Initialize forecaster
    forecaster = MARLVulnerabilityForecaster(workspace_dir="./example1_workspace")
    
    # Define binaries (replace with actual paths)
    baseline_binary = "./test_binaries/llama-cli-v1.0"
    updated_binary = "./test_binaries/llama-cli-v1.1"
    corpus_dir = "./test_corpus/llama_models"
    
    # Create dummy files for demonstration
    os.makedirs("./test_binaries", exist_ok=True)
    os.makedirs(corpus_dir, exist_ok=True)
    Path(baseline_binary).touch()
    Path(updated_binary).touch()
    Path(f"{corpus_dir}/test.gguf").touch()
    
    # Run forecast
    config = {
        'fuzz_timeout': 1800  # 30 minutes
    }
    
    try:
        forecast = forecaster.forecast_vulnerability(
            baseline_binary,
            updated_binary,
            corpus_dir,
            config
        )
        
        print(f"\n✓ Forecast completed!")
        print(f"  Risk Level: {forecast.risk_category.upper()}")
        print(f"  Score: {forecast.combined_risk_score:.2f}/100")
        
        # Save models for future use
        forecaster.save_models()
        
    except Exception as e:
        logger.error(f"Forecast failed: {e}")


def example_2_llama_shared_library_analysis():
    """
    Example 2: Analyze Llama shared libraries (libllama.so, libggml.so)
    """
    print("\n" + "="*80)
    print("EXAMPLE 2: Llama Shared Library Analysis")
    print("="*80 + "\n")
    
    forecaster = MARLVulnerabilityForecaster(workspace_dir="./example2_workspace")
    
    # Analyze shared libraries
    libraries = [
        ("libllama.so.0", "./test_binaries/v1.0/libllama.so.0", 
         "./test_binaries/v1.1/libllama.so.0"),
        ("libggml.so.0", "./test_binaries/v1.0/libggml.so.0", 
         "./test_binaries/v1.1/libggml.so.0"),
    ]
    
    results = {}
    
    for lib_name, baseline, updated in libraries:
        print(f"\nAnalyzing {lib_name}...")
        
        # Create dummy files
        os.makedirs(os.path.dirname(baseline), exist_ok=True)
        os.makedirs(os.path.dirname(updated), exist_ok=True)
        Path(baseline).touch()
        Path(updated).touch()
        
        try:
            forecast = forecaster.forecast_vulnerability(
                baseline,
                updated,
                "./test_corpus/llama_models",
                {'fuzz_timeout': 1200}
            )
            
            results[lib_name] = {
                'risk_category': forecast.risk_category,
                'score': forecast.combined_risk_score,
                'recommendations': forecast.recommendations
            }
            
            print(f"  ✓ {lib_name}: {forecast.risk_category.upper()} "
                  f"(Score: {forecast.combined_risk_score:.2f})")
            
        except Exception as e:
            logger.error(f"Analysis failed for {lib_name}: {e}")
    
    # Generate summary
    print("\n" + "-"*80)
    print("SUMMARY")
    print("-"*80)
    for lib_name, result in results.items():
        print(f"{lib_name:20s} | {result['risk_category']:10s} | "
              f"Score: {result['score']:6.2f}")


def example_3_onnx_runtime_analysis():
    """
    Example 3: Analyze ONNX Runtime binaries
    """
    print("\n" + "="*80)
    print("EXAMPLE 3: ONNX Runtime Analysis")
    print("="*80 + "\n")
    
    forecaster = MARLVulnerabilityForecaster(workspace_dir="./example3_workspace")
    
    baseline = "./test_binaries/onnx/v1.14/onnxruntime"
    updated = "./test_binaries/onnx/v1.15/onnxruntime"
    corpus_dir = "./test_corpus/onnx_models"
    
    # Create dummy files
    os.makedirs(os.path.dirname(baseline), exist_ok=True)
    os.makedirs(os.path.dirname(updated), exist_ok=True)
    os.makedirs(corpus_dir, exist_ok=True)
    Path(baseline).touch()
    Path(updated).touch()
    Path(f"{corpus_dir}/model.onnx").touch()
    
    # Configure ONNX-specific fuzzing
    config = {
        'fuzz_timeout': 3600,
        'use_onnx_dict': True
    }
    
    forecast = forecaster.forecast_vulnerability(
        baseline,
        updated,
        corpus_dir,
        config
    )
    
    print(f"\n✓ ONNX Runtime Forecast:")
    print(f"  Risk: {forecast.risk_category.upper()}")
    print(f"  Score: {forecast.combined_risk_score:.2f}/100")
    print(f"\n  Recommendations:")
    for i, rec in enumerate(forecast.recommendations, 1):
        print(f"    {i}. {rec}")


def example_4_dependency_simulation():
    """
    Example 4: Dependency update simulation
    Testing mixed old/new library combinations
    """
    print("\n" + "="*80)
    print("EXAMPLE 4: Dependency Update Simulation")
    print("="*80 + "\n")
    
    forecaster = MARLVulnerabilityForecaster(workspace_dir="./example4_workspace")
    
    # Test different dependency combinations
    configurations = [
        {
            'name': 'All Updated',
            'libllama': 'v1.1',
            'libggml': 'v1.1'
        },
        {
            'name': 'Mixed: Old libllama, New libggml',
            'libllama': 'v1.0',
            'libggml': 'v1.1'
        },
        {
            'name': 'Mixed: New libllama, Old libggml',
            'libllama': 'v1.1',
            'libggml': 'v1.0'
        }
    ]
    
    print("Testing dependency update scenarios...\n")
    
    for config in configurations:
        print(f"Configuration: {config['name']}")
        print(f"  libllama: {config['libllama']}")
        print(f"  libggml: {config['libggml']}")
        
        # In production, would actually swap library versions
        # For now, just demonstrate the concept
        print(f"  → Risk assessment would be performed here")
        print()


def example_5_continuous_learning():
    """
    Example 5: Continuous learning with model persistence
    Demonstrates loading pre-trained models and continuing training
    """
    print("\n" + "="*80)
    print("EXAMPLE 5: Continuous Learning")
    print("="*80 + "\n")
    
    # Initialize with model loading
    forecaster = MARLVulnerabilityForecaster(workspace_dir="./example5_workspace")
    
    # Try to load existing models
    if Path("./example5_workspace/models").exists():
        print("Loading pre-trained models...")
        forecaster.load_models()
    else:
        print("No pre-trained models found, starting fresh")
    
    # Run multiple analyses to continue learning
    test_cases = [
        ("./test_binaries/test1_old", "./test_binaries/test1_new"),
        ("./test_binaries/test2_old", "./test_binaries/test2_new"),
    ]
    
    for i, (baseline, updated) in enumerate(test_cases, 1):
        print(f"\nTraining iteration {i}...")
        
        os.makedirs(os.path.dirname(baseline), exist_ok=True)
        os.makedirs(os.path.dirname(updated), exist_ok=True)
        Path(baseline).touch()
        Path(updated).touch()
        
        try:
            forecast = forecaster.forecast_vulnerability(
                baseline,
                updated,
                "./test_corpus/llama_models",
                {'fuzz_timeout': 600}
            )
            
            print(f"  Iteration {i} complete: {forecast.risk_category}")
            
        except Exception as e:
            logger.error(f"Iteration {i} failed: {e}")
    
    # Save updated models
    print("\nSaving improved models...")
    forecaster.save_models()
    print("✓ Models saved for future use")


def example_6_custom_afl_config():
    """
    Example 6: Custom AFL++ configuration for specific scenarios
    """
    print("\n" + "="*80)
    print("EXAMPLE 6: Custom AFL++ Configuration")
    print("="*80 + "\n")
    
    # Create custom AFL++ configuration
    afl_manager = AFLPlusPlusManager()
    
    # Aggressive fuzzing for high-risk binaries
    aggressive_config = AFLConfig(
        timeout=5000,
        memory_limit=16384,
        cores=8,
        power_schedule="explore",
        use_cmplog=True,
        use_laf=True,
        use_redqueen=True
    )
    
    # Quick exploration for initial assessment
    quick_config = AFLConfig(
        timeout=1000,
        memory_limit=4096,
        cores=2,
        power_schedule="fast",
        use_cmplog=False,
        use_laf=False
    )
    
    print("Aggressive Config:")
    print(f"  Timeout: {aggressive_config.timeout}ms")
    print(f"  Memory: {aggressive_config.memory_limit}MB")
    print(f"  Schedule: {aggressive_config.power_schedule}")
    print(f"  CMPLOG: {aggressive_config.use_cmplog}")
    
    print("\nQuick Config:")
    print(f"  Timeout: {quick_config.timeout}ms")
    print(f"  Memory: {quick_config.memory_limit}MB")
    print(f"  Schedule: {quick_config.power_schedule}")


def example_7_bindiff_standalone():
    """
    Example 7: Standalone BinDiff analysis
    """
    print("\n" + "="*80)
    print("EXAMPLE 7: Standalone BinDiff Analysis")
    print("="*80 + "\n")
    
    analyzer = BinDiffAnalyzer()
    
    baseline = "./test_binaries/standalone/baseline.so"
    updated = "./test_binaries/standalone/updated.so"
    output_dir = "./bindiff_standalone"
    
    # Create dummy files
    os.makedirs(os.path.dirname(baseline), exist_ok=True)
    Path(baseline).touch()
    Path(updated).touch()
    
    print("Running BinDiff analysis...")
    
    # Create diff database
    db_path = analyzer.create_bindiff_database(baseline, updated, output_dir)
    
    # Parse results
    matches, diffs = analyzer.parse_bindiff_results(db_path)
    
    print(f"\n✓ Analysis complete:")
    print(f"  Function matches: {len(matches)}")
    print(f"  Functions with changes: {len(diffs)}")
    
    # Identify high-risk changes
    high_risk = analyzer.identify_high_risk_changes(diffs)
    print(f"  High-risk changes: {len(high_risk)}")
    
    # Generate report
    report_path = os.path.join(output_dir, "analysis_report.json")
    analyzer.generate_diff_report(matches, diffs, report_path)
    print(f"\n✓ Report saved: {report_path}")


def example_8_batch_analysis():
    """
    Example 8: Batch analysis of multiple binary pairs
    """
    print("\n" + "="*80)
    print("EXAMPLE 8: Batch Analysis")
    print("="*80 + "\n")
    
    forecaster = MARLVulnerabilityForecaster(workspace_dir="./example8_workspace")
    
    # Define multiple binary pairs to analyze
    binary_pairs = [
        {
            'name': 'llama-cli',
            'baseline': './test_binaries/batch/llama-cli-v1.0',
            'updated': './test_binaries/batch/llama-cli-v1.1',
            'corpus': './test_corpus/llama_models'
        },
        {
            'name': 'llama-server',
            'baseline': './test_binaries/batch/llama-server-v1.0',
            'updated': './test_binaries/batch/llama-server-v1.1',
            'corpus': './test_corpus/llama_models'
        },
        {
            'name': 'libllama.so',
            'baseline': './test_binaries/batch/libllama.so-v1.0',
            'updated': './test_binaries/batch/libllama.so-v1.1',
            'corpus': './test_corpus/llama_models'
        }
    ]
    
    results = []
    
    for binary_pair in binary_pairs:
        print(f"\nAnalyzing: {binary_pair['name']}")
        
        # Create dummy files
        for key in ['baseline', 'updated', 'corpus']:
            path = binary_pair[key]
            os.makedirs(os.path.dirname(path) if '/' in path else '.', exist_ok=True)
            if key != 'corpus':
                Path(path).touch()
            else:
                os.makedirs(path, exist_ok=True)
                Path(f"{path}/test.gguf").touch()
        
        try:
            forecast = forecaster.forecast_vulnerability(
                binary_pair['baseline'],
                binary_pair['updated'],
                binary_pair['corpus'],
                {'fuzz_timeout': 900}
            )
            
            results.append({
                'name': binary_pair['name'],
                'risk': forecast.risk_category,
                'score': forecast.combined_risk_score
            })
            
            print(f"  ✓ {forecast.risk_category.upper()} "
                  f"(Score: {forecast.combined_risk_score:.2f})")
            
        except Exception as e:
            logger.error(f"Failed to analyze {binary_pair['name']}: {e}")
    
    # Print batch summary
    print("\n" + "="*80)
    print("BATCH ANALYSIS SUMMARY")
    print("="*80)
    print(f"{'Binary':<20} | {'Risk Level':<10} | {'Score':<10}")
    print("-"*80)
    for result in results:
        print(f"{result['name']:<20} | {result['risk']:<10} | {result['score']:>6.2f}")


def main():
    """Main function to run examples"""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║      Multi-Agent Reinforcement Learning Vulnerability Forecasting           ║
║                    Example Usage Scenarios                                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")
    
    examples = {
        '1': ('Basic Llama Binary Analysis', example_1_basic_analysis),
        '2': ('Llama Shared Library Analysis', example_2_llama_shared_library_analysis),
        '3': ('ONNX Runtime Analysis', example_3_onnx_runtime_analysis),
        '4': ('Dependency Update Simulation', example_4_dependency_simulation),
        '5': ('Continuous Learning', example_5_continuous_learning),
        '6': ('Custom AFL++ Configuration', example_6_custom_afl_config),
        '7': ('Standalone BinDiff Analysis', example_7_bindiff_standalone),
        '8': ('Batch Analysis', example_8_batch_analysis),
    }
    
    print("Available examples:")
    for key, (name, _) in examples.items():
        print(f"  {key}. {name}")
    print("  9. Run all examples")
    print("  0. Exit")
    
    choice = input("\nSelect example to run (0-9): ").strip()
    
    if choice == '0':
        print("Exiting...")
        return
    elif choice == '9':
        print("\nRunning all examples...\n")
        for _, (name, func) in examples.items():
            try:
                func()
            except Exception as e:
                logger.error(f"Example '{name}' failed: {e}")
    elif choice in examples:
        name, func = examples[choice]
        print(f"\nRunning: {name}\n")
        try:
            func()
        except Exception as e:
            logger.error(f"Example failed: {e}")
    else:
        print("Invalid choice!")


if __name__ == "__main__":
    main()
