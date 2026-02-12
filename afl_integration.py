#!/usr/bin/env python3
"""
AFL++ Integration Module
Advanced fuzzing strategies for AI runtime binaries
"""

import os
import subprocess
import json
import time
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import shutil

logger = logging.getLogger(__name__)


@dataclass
class AFLConfig:
    """Configuration for AFL++ fuzzing campaigns"""
    timeout: int = 1000  # ms
    memory_limit: int = 8192  # MB
    cores: int = 4
    power_schedule: str = "fast"  # fast, explore, coe, lin, quad, exploit
    mutation_mode: str = "default"  # default, rare, custom
    dict_path: Optional[str] = None
    use_cmplog: bool = True
    use_laf: bool = True
    use_redqueen: bool = True


class AFLPlusPlusManager:
    """Manages AFL++ fuzzing campaigns with advanced strategies"""
    
    def __init__(self, afl_base_path: str = "/usr/bin"):
        self.afl_fuzz = os.path.join(afl_base_path, "afl-fuzz")
        self.afl_showmap = os.path.join(afl_base_path, "afl-showmap")
        self.afl_cmin = os.path.join(afl_base_path, "afl-cmin")
        self.afl_tmin = os.path.join(afl_base_path, "afl-tmin")
        
        self.verify_afl_installation()
    
    def verify_afl_installation(self):
        """Verify AFL++ is properly installed"""
        required_tools = [self.afl_fuzz, self.afl_showmap]
        for tool in required_tools:
            if not shutil.which(tool.split('/')[-1]):
                logger.warning(f"{tool} not found in PATH. Using simulated mode.")
    
    def prepare_corpus(self, corpus_dir: str, output_dir: str, 
                      binary_path: str, minimize: bool = True) -> str:
        """
        Prepare and minimize fuzzing corpus
        
        Args:
            corpus_dir: Input corpus directory
            output_dir: Output directory for minimized corpus
            binary_path: Target binary for corpus minimization
            minimize: Whether to minimize corpus
            
        Returns:
            Path to prepared corpus
        """
        logger.info(f"Preparing corpus from {corpus_dir}")
        
        os.makedirs(output_dir, exist_ok=True)
        
        if minimize and shutil.which("afl-cmin"):
            try:
                minimized_dir = os.path.join(output_dir, "minimized")
                os.makedirs(minimized_dir, exist_ok=True)
                
                cmd = [
                    self.afl_cmin,
                    "-i", corpus_dir,
                    "-o", minimized_dir,
                    "-m", "8192",
                    "--", binary_path, "@@"
                ]
                
                logger.info("Minimizing corpus...")
                subprocess.run(cmd, timeout=300, check=False)
                
                # Count files
                original_count = len(list(Path(corpus_dir).glob("*")))
                minimized_count = len(list(Path(minimized_dir).glob("*")))
                logger.info(f"Corpus minimized: {original_count} -> {minimized_count} files")
                
                return minimized_dir
            except Exception as e:
                logger.error(f"Corpus minimization failed: {e}")
                return corpus_dir
        
        return corpus_dir
    
    def create_fuzzing_dictionary(self, binary_type: str) -> str:
        """
        Create fuzzing dictionary for specific binary type
        
        Args:
            binary_type: 'llama', 'onnx', or 'generic'
            
        Returns:
            Path to dictionary file
        """
        dict_path = f"/tmp/fuzz_dict_{binary_type}.dict"
        
        dictionaries = {
            'llama': [
                # GGML/GGUF magic numbers and headers
                'ggml="GGML"',
                'gguf="GGUF"',
                'ggjt="GGJT"',
                # Common tensor types
                'f32="\\x00\\x00\\x00\\x00"',
                'f16="\\x01\\x00\\x00\\x00"',
                'q4_0="\\x02\\x00\\x00\\x00"',
                'q4_1="\\x03\\x00\\x00\\x00"',
                # Model architecture markers
                'llama="llama"',
                'attention="attention"',
                'feed_forward="feed_forward"',
            ],
            'onnx': [
                # ONNX protobuf markers
                'onnx_model="\\x08\\x03"',
                'ir_version="ir_version"',
                'opset="opset_import"',
                # Node types
                'conv="Conv"',
                'relu="Relu"',
                'matmul="MatMul"',
                'gemm="Gemm"',
                'reshape="Reshape"',
                # Data types
                'float="\\x01"',
                'uint8="\\x02"',
                'int8="\\x03"',
            ],
            'generic': [
                # Common patterns
                'elf="\\x7fELF"',
                'magic="\\xca\\xfe\\xba\\xbe"',
                'null="\\x00\\x00\\x00\\x00"',
            ]
        }
        
        dict_content = dictionaries.get(binary_type, dictionaries['generic'])
        
        with open(dict_path, 'w') as f:
            for entry in dict_content:
                f.write(entry + '\n')
        
        logger.info(f"Created fuzzing dictionary: {dict_path}")
        return dict_path
    
    def start_fuzzing_campaign(self, binary_path: str, corpus_dir: str,
                              output_dir: str, config: AFLConfig,
                              session_name: str = "main") -> subprocess.Popen:
        """
        Start AFL++ fuzzing campaign
        
        Args:
            binary_path: Path to instrumented binary
            corpus_dir: Input corpus directory
            output_dir: Output directory for fuzzing results
            config: AFL configuration
            session_name: Name for this fuzzing session
            
        Returns:
            Process handle for the fuzzing campaign
        """
        logger.info(f"Starting AFL++ campaign: {session_name}")
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Build AFL++ command
        cmd = [self.afl_fuzz]
        
        # Basic parameters
        cmd.extend(["-i", corpus_dir])
        cmd.extend(["-o", output_dir])
        cmd.extend(["-m", str(config.memory_limit)])
        cmd.extend(["-t", str(config.timeout)])
        
        # Power schedule
        if config.power_schedule != "default":
            cmd.extend(["-p", config.power_schedule])
        
        # Dictionary
        if config.dict_path and os.path.exists(config.dict_path):
            cmd.extend(["-x", config.dict_path])
        
        # Advanced features
        if config.use_cmplog:
            cmd.append("-l")
            cmd.append("2")  # CMPLOG level
        
        if config.use_laf:
            cmd.append("-L")
            cmd.append("0")  # LAF-Intel mode
        
        # Session name
        cmd.extend(["-S", session_name])
        
        # Target binary
        cmd.extend(["--", binary_path, "@@"])
        
        logger.info(f"AFL++ command: {' '.join(cmd)}")
        
        # Start fuzzing in background
        try:
            # Create log file
            log_file = os.path.join(output_dir, f"afl_{session_name}.log")
            log_handle = open(log_file, 'w')
            
            process = subprocess.Popen(
                cmd,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid  # Create new process group
            )
            
            logger.info(f"AFL++ campaign started (PID: {process.pid})")
            logger.info(f"Log file: {log_file}")
            
            return process
            
        except Exception as e:
            logger.error(f"Failed to start AFL++: {e}")
            raise
    
    def parse_fuzzing_stats(self, output_dir: str, session_name: str = "main") -> Dict:
        """
        Parse AFL++ fuzzer_stats file
        
        Args:
            output_dir: AFL++ output directory
            session_name: Fuzzing session name
            
        Returns:
            Dictionary of fuzzing statistics
        """
        stats_file = os.path.join(output_dir, session_name, "fuzzer_stats")
        
        if not os.path.exists(stats_file):
            logger.warning(f"Stats file not found: {stats_file}")
            return {}
        
        stats = {}
        try:
            with open(stats_file, 'r') as f:
                for line in f:
                    if ':' in line:
                        key, value = line.strip().split(':', 1)
                        stats[key.strip()] = value.strip()
        except Exception as e:
            logger.error(f"Error parsing stats: {e}")
        
        return stats
    
    def get_coverage_map(self, binary_path: str, input_file: str,
                        output_file: str) -> Dict:
        """
        Generate coverage map for a specific input
        
        Args:
            binary_path: Target binary
            input_file: Test input file
            output_file: Output file for coverage map
            
        Returns:
            Coverage statistics
        """
        cmd = [
            self.afl_showmap,
            "-o", output_file,
            "-m", "8192",
            "-t", "5000",
            "--", binary_path, input_file
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            # Parse coverage from output
            coverage = {}
            if os.path.exists(output_file):
                with open(output_file, 'rb') as f:
                    data = f.read()
                    coverage['edges'] = len([b for b in data if b != 0])
                    coverage['size'] = len(data)
            
            return coverage
            
        except Exception as e:
            logger.error(f"Error getting coverage map: {e}")
            return {}
    
    def compare_coverage(self, baseline_map: str, updated_map: str) -> Dict:
        """
        Compare coverage between two binaries
        
        Args:
            baseline_map: Coverage map from baseline binary
            updated_map: Coverage map from updated binary
            
        Returns:
            Coverage comparison metrics
        """
        try:
            with open(baseline_map, 'rb') as f:
                baseline_data = set(i for i, b in enumerate(f.read()) if b != 0)
            
            with open(updated_map, 'rb') as f:
                updated_data = set(i for i, b in enumerate(f.read()) if b != 0)
            
            new_edges = updated_data - baseline_data
            removed_edges = baseline_data - updated_data
            common_edges = baseline_data & updated_data
            
            comparison = {
                'baseline_edges': len(baseline_data),
                'updated_edges': len(updated_data),
                'new_edges': len(new_edges),
                'removed_edges': len(removed_edges),
                'common_edges': len(common_edges),
                'jaccard_similarity': len(common_edges) / len(baseline_data | updated_data)
                                     if baseline_data or updated_data else 0
            }
            
            return comparison
            
        except Exception as e:
            logger.error(f"Error comparing coverage: {e}")
            return {}
    
    def analyze_crashes(self, crashes_dir: str) -> List[Dict]:
        """
        Analyze crash files to identify unique crashes
        
        Args:
            crashes_dir: Directory containing crash files
            
        Returns:
            List of crash analysis results
        """
        crashes = []
        
        if not os.path.exists(crashes_dir):
            return crashes
        
        crash_files = list(Path(crashes_dir).glob("id:*"))
        
        for crash_file in crash_files:
            try:
                # Extract crash info from filename
                filename = crash_file.name
                crash_info = {
                    'file': str(crash_file),
                    'size': crash_file.stat().st_size,
                    'timestamp': crash_file.stat().st_mtime
                }
                
                # Parse signal information if available
                if 'sig:' in filename:
                    sig_part = filename.split('sig:')[1].split(',')[0]
                    crash_info['signal'] = sig_part
                
                crashes.append(crash_info)
                
            except Exception as e:
                logger.error(f"Error analyzing crash {crash_file}: {e}")
        
        logger.info(f"Analyzed {len(crashes)} crashes")
        return crashes
    
    def parallel_fuzzing(self, binary_path: str, corpus_dir: str,
                        output_dir: str, config: AFLConfig,
                        num_instances: int = 4) -> List[subprocess.Popen]:
        """
        Launch parallel fuzzing instances
        
        Args:
            binary_path: Target binary
            corpus_dir: Input corpus
            output_dir: Output directory
            config: AFL configuration
            num_instances: Number of parallel instances
            
        Returns:
            List of process handles
        """
        processes = []
        
        # First instance is the master
        master_config = config
        master_process = self.start_fuzzing_campaign(
            binary_path, corpus_dir, output_dir, master_config, "master"
        )
        processes.append(master_process)
        
        # Wait a bit for master to initialize
        time.sleep(5)
        
        # Launch secondary instances with different strategies
        strategies = ["explore", "coe", "lin", "quad"]
        
        for i in range(1, min(num_instances, len(strategies) + 1)):
            secondary_config = AFLConfig(
                timeout=config.timeout,
                memory_limit=config.memory_limit,
                power_schedule=strategies[i-1],
                use_cmplog=config.use_cmplog,
                use_laf=False  # Disable for secondary instances
            )
            
            session_name = f"secondary_{i}"
            process = self.start_fuzzing_campaign(
                binary_path, corpus_dir, output_dir, 
                secondary_config, session_name
            )
            processes.append(process)
            
            time.sleep(2)  # Stagger startup
        
        logger.info(f"Launched {len(processes)} parallel fuzzing instances")
        return processes
    
    def stop_fuzzing(self, processes: List[subprocess.Popen]):
        """Stop all fuzzing processes gracefully"""
        logger.info("Stopping fuzzing campaigns...")
        
        for process in processes:
            try:
                process.terminate()
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
            except Exception as e:
                logger.error(f"Error stopping process {process.pid}: {e}")
        
        logger.info("All fuzzing campaigns stopped")


class TargetBinaryPreparation:
    """Prepare binaries for fuzzing with various instrumentation options"""
    
    @staticmethod
    def compile_with_afl(source_dir: str, output_binary: str,
                        use_asan: bool = True, use_ubsan: bool = False) -> bool:
        """
        Compile binary with AFL++ instrumentation
        
        Args:
            source_dir: Source code directory
            output_binary: Output binary path
            use_asan: Enable AddressSanitizer
            use_ubsan: Enable UndefinedBehaviorSanitizer
            
        Returns:
            Success status
        """
        logger.info(f"Compiling with AFL++ instrumentation")
        
        env = os.environ.copy()
        
        # Set AFL++ compiler
        env['CC'] = 'afl-clang-fast'
        env['CXX'] = 'afl-clang-fast++'
        
        # Add sanitizers
        if use_asan:
            env['AFL_USE_ASAN'] = '1'
        if use_ubsan:
            env['AFL_USE_UBSAN'] = '1'
        
        # Build command (example for CMake projects)
        commands = [
            ['cmake', '-DCMAKE_BUILD_TYPE=Debug', source_dir],
            ['make', '-j4']
        ]
        
        try:
            for cmd in commands:
                subprocess.run(cmd, env=env, check=True, timeout=600)
            
            logger.info(f"Binary compiled successfully: {output_binary}")
            return True
            
        except Exception as e:
            logger.error(f"Compilation failed: {e}")
            return False
    
    @staticmethod
    def check_binary_instrumentation(binary_path: str) -> Dict:
        """
        Check what instrumentation is present in binary
        
        Args:
            binary_path: Path to binary
            
        Returns:
            Dictionary of instrumentation flags
        """
        instrumentation = {
            'afl_instrumented': False,
            'asan_enabled': False,
            'coverage_enabled': False
        }
        
        try:
            # Check with nm or objdump
            result = subprocess.run(
                ['nm', '-D', binary_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            symbols = result.stdout.lower()
            
            if '__afl' in symbols:
                instrumentation['afl_instrumented'] = True
            if 'asan' in symbols or '__sanitizer' in symbols:
                instrumentation['asan_enabled'] = True
            if '__gcov' in symbols or '__llvm_profile' in symbols:
                instrumentation['coverage_enabled'] = True
            
        except Exception as e:
            logger.error(f"Error checking instrumentation: {e}")
        
        return instrumentation


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    manager = AFLPlusPlusManager()
    
    # Example: Prepare corpus
    corpus = manager.prepare_corpus(
        "./test_corpus",
        "./prepared_corpus",
        "./target_binary",
        minimize=True
    )
    
    # Create dictionary
    dict_path = manager.create_fuzzing_dictionary("llama")
    
    # Configure fuzzing
    config = AFLConfig(
        timeout=2000,
        memory_limit=8192,
        power_schedule="explore",
        dict_path=dict_path,
        use_cmplog=True
    )
    
    print("AFL++ Manager ready for fuzzing campaigns")
