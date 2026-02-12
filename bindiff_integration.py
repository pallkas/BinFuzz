#!/usr/bin/env python3
"""
Google BinDiff Integration Module
Binary diffing and structural analysis for vulnerability forecasting
"""

import os
import subprocess
import json
import logging
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from collections import defaultdict
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class FunctionMatch:
    """Represents a function match between two binaries"""
    baseline_address: int
    updated_address: int
    baseline_name: str
    updated_name: str
    similarity: float
    confidence: str  # manual, automatic
    algorithm: str  # matching algorithm used
    baseline_basic_blocks: int
    updated_basic_blocks: int
    baseline_edges: int
    updated_edges: int
    baseline_instructions: int
    updated_instructions: int


@dataclass
class FunctionDiff:
    """Detailed differences for a matched function"""
    function_match: FunctionMatch
    changed_basic_blocks: int
    added_basic_blocks: int
    removed_basic_blocks: int
    changed_edges: int
    cfg_complexity_delta: int
    instruction_changes: List[str]
    critical_changes: List[str]  # Memory ops, parsing, etc.


class BinDiffAnalyzer:
    """Interface to Google BinDiff for binary comparison"""
    
    def __init__(self, bindiff_path: str = "/opt/bindiff/bin/bindiff"):
        self.bindiff_path = bindiff_path
        self.ida_path = "/opt/ida/idat64"  # IDA Pro for disassembly
        self.verify_installation()
        
    def verify_installation(self):
        """Check if BinDiff and IDA are available"""
        if not os.path.exists(self.bindiff_path):
            logger.warning(f"BinDiff not found at {self.bindiff_path}")
            logger.warning("Falling back to alternative binary analysis methods")
        
        if not os.path.exists(self.ida_path):
            logger.warning(f"IDA Pro not found at {self.ida_path}")
            logger.warning("Will use Ghidra or radare2 as fallback")
    
    def create_bindiff_database(self, binary1: str, binary2: str, 
                               output_dir: str) -> str:
        """
        Create BinDiff database comparing two binaries
        
        Args:
            binary1: Path to first binary (baseline)
            binary2: Path to second binary (updated)
            output_dir: Output directory for results
            
        Returns:
            Path to BinDiff database file
        """
        logger.info(f"Creating BinDiff database")
        logger.info(f"  Baseline: {binary1}")
        logger.info(f"  Updated:  {binary2}")
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Step 1: Export IDBs (IDA databases)
        idb1 = self._export_idb(binary1, output_dir)
        idb2 = self._export_idb(binary2, output_dir)
        
        # Step 2: Export BinExport files
        binexport1 = self._export_binexport(idb1, output_dir)
        binexport2 = self._export_binexport(idb2, output_dir)
        
        # Step 3: Run BinDiff comparison
        bindiff_db = os.path.join(output_dir, "diff_results.BinDiff")
        
        cmd = [
            self.bindiff_path,
            "--primary", binexport1,
            "--secondary", binexport2,
            "--output_dir", output_dir
        ]
        
        try:
            if os.path.exists(self.bindiff_path):
                result = subprocess.run(cmd, capture_output=True, text=True, 
                                       timeout=600, check=False)
                logger.info(f"BinDiff completed")
                
                if result.returncode != 0:
                    logger.error(f"BinDiff error: {result.stderr}")
            else:
                # Fallback: Use radare2 or custom analysis
                logger.info("Using fallback binary analysis")
                bindiff_db = self._fallback_binary_diff(binary1, binary2, output_dir)
            
            return bindiff_db
            
        except Exception as e:
            logger.error(f"Error running BinDiff: {e}")
            return self._fallback_binary_diff(binary1, binary2, output_dir)
    
    def _export_idb(self, binary: str, output_dir: str) -> str:
        """Export IDA database for binary"""
        idb_path = os.path.join(output_dir, 
                               os.path.basename(binary) + ".i64")
        
        if os.path.exists(self.ida_path):
            cmd = [
                self.ida_path,
                "-A",  # Autonomous mode
                "-B",  # Batch mode
                f"-o{idb_path}",
                binary
            ]
            
            try:
                subprocess.run(cmd, timeout=300, check=False)
                logger.info(f"IDB exported: {idb_path}")
            except Exception as e:
                logger.error(f"IDB export failed: {e}")
        else:
            logger.warning("IDA not available, using alternative")
            # Create placeholder
            Path(idb_path).touch()
        
        return idb_path
    
    def _export_binexport(self, idb_path: str, output_dir: str) -> str:
        """Export BinExport file from IDB"""
        binexport_path = idb_path.replace(".i64", ".BinExport")
        
        # BinExport plugin should be installed in IDA
        # This is typically done via IDA's plugin system
        logger.info(f"BinExport file: {binexport_path}")
        
        # Placeholder - in production this would be created by IDA plugin
        Path(binexport_path).touch()
        
        return binexport_path
    
    def _fallback_binary_diff(self, binary1: str, binary2: str, 
                             output_dir: str) -> str:
        """Fallback binary diffing using radare2 or objdump"""
        logger.info("Using radare2 for binary analysis")
        
        diff_db = os.path.join(output_dir, "fallback_diff.json")
        
        # Use radare2 for analysis
        analysis1 = self._analyze_with_radare2(binary1)
        analysis2 = self._analyze_with_radare2(binary2)
        
        # Simple diff
        diff_results = {
            'binary1': binary1,
            'binary2': binary2,
            'functions1': analysis1.get('functions', []),
            'functions2': analysis2.get('functions', []),
            'method': 'radare2_fallback'
        }
        
        with open(diff_db, 'w') as f:
            json.dump(diff_results, f, indent=2)
        
        return diff_db
    
    def _analyze_with_radare2(self, binary: str) -> Dict:
        """Analyze binary with radare2"""
        try:
            # Check if radare2 is available
            if not shutil.which('r2'):
                logger.warning("radare2 not found")
                return {}
            
            cmd = ['r2', '-q', '-A', '-c', 'aflj', binary]
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                   timeout=60)
            
            functions = json.loads(result.stdout) if result.stdout else []
            return {'functions': functions}
            
        except Exception as e:
            logger.error(f"radare2 analysis failed: {e}")
            return {}
    
    def parse_bindiff_results(self, bindiff_db: str) -> Tuple[List[FunctionMatch], 
                                                              List[FunctionDiff]]:
        """
        Parse BinDiff database and extract matching and diff information
        
        Args:
            bindiff_db: Path to BinDiff database
            
        Returns:
            Tuple of (function_matches, function_diffs)
        """
        logger.info(f"Parsing BinDiff results from {bindiff_db}")
        
        matches = []
        diffs = []
        
        # BinDiff uses SQLite database
        if bindiff_db.endswith('.BinDiff'):
            matches, diffs = self._parse_bindiff_sqlite(bindiff_db)
        elif bindiff_db.endswith('.json'):
            matches, diffs = self._parse_fallback_json(bindiff_db)
        
        logger.info(f"Parsed {len(matches)} function matches")
        logger.info(f"Identified {len(diffs)} functions with changes")
        
        return matches, diffs
    
    def _parse_bindiff_sqlite(self, db_path: str) -> Tuple[List[FunctionMatch], 
                                                           List[FunctionDiff]]:
        """Parse BinDiff SQLite database"""
        matches = []
        diffs = []
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Query function matches
            query = """
                SELECT 
                    address1, address2, name1, name2, 
                    similarity, confidence, algorithm,
                    basicblocks1, basicblocks2,
                    edges1, edges2,
                    instructions1, instructions2
                FROM function
                WHERE address1 IS NOT NULL AND address2 IS NOT NULL
            """
            
            cursor.execute(query)
            
            for row in cursor.fetchall():
                match = FunctionMatch(
                    baseline_address=row[0],
                    updated_address=row[1],
                    baseline_name=row[2] or f"sub_{row[0]:x}",
                    updated_name=row[3] or f"sub_{row[1]:x}",
                    similarity=row[4] if row[4] else 0.0,
                    confidence=row[5] or "automatic",
                    algorithm=row[6] or "unknown",
                    baseline_basic_blocks=row[7] or 0,
                    updated_basic_blocks=row[8] or 0,
                    baseline_edges=row[9] or 0,
                    updated_edges=row[10] or 0,
                    baseline_instructions=row[11] or 0,
                    updated_instructions=row[12] or 0
                )
                matches.append(match)
                
                # Create diff for changed functions
                if match.similarity < 1.0:
                    diff = self._create_function_diff(match, cursor)
                    diffs.append(diff)
            
            conn.close()
            
        except Exception as e:
            logger.error(f"Error parsing BinDiff database: {e}")
        
        return matches, diffs
    
    def _parse_fallback_json(self, json_path: str) -> Tuple[List[FunctionMatch], 
                                                            List[FunctionDiff]]:
        """Parse fallback JSON diff results"""
        matches = []
        diffs = []
        
        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
            
            funcs1 = {f.get('name'): f for f in data.get('functions1', [])}
            funcs2 = {f.get('name'): f for f in data.get('functions2', [])}
            
            # Simple name-based matching
            for name in set(funcs1.keys()) & set(funcs2.keys()):
                f1 = funcs1[name]
                f2 = funcs2[name]
                
                # Calculate simple similarity
                similarity = 1.0 if f1.get('size') == f2.get('size') else 0.8
                
                match = FunctionMatch(
                    baseline_address=f1.get('offset', 0),
                    updated_address=f2.get('offset', 0),
                    baseline_name=name,
                    updated_name=name,
                    similarity=similarity,
                    confidence="automatic",
                    algorithm="name_match",
                    baseline_basic_blocks=f1.get('nbbs', 0),
                    updated_basic_blocks=f2.get('nbbs', 0),
                    baseline_edges=f1.get('edges', 0),
                    updated_edges=f2.get('edges', 0),
                    baseline_instructions=f1.get('ninstr', 0),
                    updated_instructions=f2.get('ninstr', 0)
                )
                matches.append(match)
            
        except Exception as e:
            logger.error(f"Error parsing fallback JSON: {e}")
        
        return matches, diffs
    
    def _create_function_diff(self, match: FunctionMatch, 
                             cursor: sqlite3.Cursor) -> FunctionDiff:
        """Create detailed diff for a function match"""
        
        bb_delta = match.updated_basic_blocks - match.baseline_basic_blocks
        edge_delta = match.updated_edges - match.baseline_edges
        
        # Complexity can be approximated by edges/blocks ratio
        baseline_complexity = (match.baseline_edges / max(match.baseline_basic_blocks, 1))
        updated_complexity = (match.updated_edges / max(match.updated_basic_blocks, 1))
        complexity_delta = int((updated_complexity - baseline_complexity) * 10)
        
        diff = FunctionDiff(
            function_match=match,
            changed_basic_blocks=abs(bb_delta),
            added_basic_blocks=max(0, bb_delta),
            removed_basic_blocks=max(0, -bb_delta),
            changed_edges=abs(edge_delta),
            cfg_complexity_delta=complexity_delta,
            instruction_changes=[],
            critical_changes=[]
        )
        
        # Analyze critical changes
        diff.critical_changes = self._identify_critical_changes(match)
        
        return diff
    
    def _identify_critical_changes(self, match: FunctionMatch) -> List[str]:
        """Identify critical changes in a function"""
        critical = []
        
        name_lower = match.baseline_name.lower()
        
        # Memory-related functions
        memory_keywords = ['alloc', 'free', 'malloc', 'realloc', 'memcpy', 
                          'memset', 'strcpy', 'buffer']
        if any(kw in name_lower for kw in memory_keywords):
            critical.append(f"MEMORY: Modified memory-handling function")
        
        # Parsing functions
        parsing_keywords = ['parse', 'deserialize', 'read', 'load', 'decode']
        if any(kw in name_lower for kw in parsing_keywords):
            critical.append(f"PARSING: Modified parsing function")
        
        # Size changes
        size_change = match.updated_instructions - match.baseline_instructions
        if abs(size_change) > 50:
            critical.append(f"SIZE: Significant instruction count change ({size_change:+d})")
        
        # Complexity changes
        if match.updated_basic_blocks > match.baseline_basic_blocks * 1.5:
            critical.append(f"COMPLEXITY: Significant increase in basic blocks")
        
        return critical
    
    def identify_high_risk_changes(self, diffs: List[FunctionDiff],
                                   similarity_threshold: float = 0.8) -> List[FunctionDiff]:
        """
        Filter high-risk function changes
        
        Args:
            diffs: List of all function diffs
            similarity_threshold: Functions below this similarity are high-risk
            
        Returns:
            List of high-risk diffs
        """
        high_risk = []
        
        for diff in diffs:
            match = diff.function_match
            
            # Criteria for high risk
            is_high_risk = (
                match.similarity < similarity_threshold or
                len(diff.critical_changes) > 0 or
                abs(diff.cfg_complexity_delta) > 5 or
                diff.added_basic_blocks > 10
            )
            
            if is_high_risk:
                high_risk.append(diff)
        
        logger.info(f"Identified {len(high_risk)} high-risk function changes")
        return high_risk
    
    def generate_diff_report(self, matches: List[FunctionMatch],
                            diffs: List[FunctionDiff],
                            output_file: str):
        """
        Generate comprehensive diff report
        
        Args:
            matches: List of function matches
            diffs: List of function diffs
            output_file: Output file path for report
        """
        logger.info(f"Generating diff report: {output_file}")
        
        report = {
            'summary': {
                'total_matches': len(matches),
                'total_diffs': len(diffs),
                'perfect_matches': sum(1 for m in matches if m.similarity >= 1.0),
                'modified_functions': sum(1 for m in matches if m.similarity < 1.0),
                'average_similarity': sum(m.similarity for m in matches) / len(matches)
                                     if matches else 0
            },
            'high_risk_functions': [],
            'statistics': {
                'total_baseline_functions': len(matches),
                'total_updated_functions': len(matches),
                'similarity_distribution': self._calculate_similarity_distribution(matches)
            },
            'detailed_changes': []
        }
        
        # Add high-risk functions
        high_risk = self.identify_high_risk_changes(diffs)
        for diff in high_risk:
            report['high_risk_functions'].append({
                'name': diff.function_match.baseline_name,
                'similarity': diff.function_match.similarity,
                'critical_changes': diff.critical_changes,
                'complexity_delta': diff.cfg_complexity_delta
            })
        
        # Add detailed changes
        for diff in diffs[:50]:  # Top 50 changes
            report['detailed_changes'].append({
                'function': diff.function_match.baseline_name,
                'similarity': diff.function_match.similarity,
                'bb_added': diff.added_basic_blocks,
                'bb_removed': diff.removed_basic_blocks,
                'edge_changes': diff.changed_edges,
                'critical': diff.critical_changes
            })
        
        # Write report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report generated: {output_file}")
    
    def _calculate_similarity_distribution(self, matches: List[FunctionMatch]) -> Dict:
        """Calculate distribution of similarity scores"""
        bins = {
            '0.0-0.2': 0,
            '0.2-0.4': 0,
            '0.4-0.6': 0,
            '0.6-0.8': 0,
            '0.8-1.0': 0,
            '1.0': 0
        }
        
        for match in matches:
            sim = match.similarity
            if sim == 1.0:
                bins['1.0'] += 1
            elif sim >= 0.8:
                bins['0.8-1.0'] += 1
            elif sim >= 0.6:
                bins['0.6-0.8'] += 1
            elif sim >= 0.4:
                bins['0.4-0.6'] += 1
            elif sim >= 0.2:
                bins['0.2-0.4'] += 1
            else:
                bins['0.0-0.2'] += 1
        
        return bins


import shutil

if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    analyzer = BinDiffAnalyzer()
    
    # Create diff database
    db_path = analyzer.create_bindiff_database(
        "/path/to/baseline/libllama.so",
        "/path/to/updated/libllama.so",
        "./bindiff_output"
    )
    
    # Parse results
    matches, diffs = analyzer.parse_bindiff_results(db_path)
    
    # Generate report
    analyzer.generate_diff_report(
        matches, diffs,
        "./bindiff_output/diff_report.json"
    )
    
    print(f"Analysis complete: {len(matches)} matches, {len(diffs)} diffs")
