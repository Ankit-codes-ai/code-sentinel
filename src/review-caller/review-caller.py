import os
import json
import logging
import hashlib
import time
import re
from pathlib import Path
import ast
import subprocess
import shutil
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import google.generativeai as genai
from langgraph.graph import StateGraph, END
from datetime import datetime, timezone
import threading
import queue


def safe_json_loads(raw_text: str) -> Optional[Any]:
    """Attempt to parse JSON, fixing minor issues like trailing commas.

    Returns the parsed object or None if parsing fails."""
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        cleaned = re.sub(r",\s*([}\]])", r"\1", raw_text)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            return None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')
if not GEMINI_API_KEY:
    print("ERROR: No Gemini API key provided. Set the GEMINI_API_KEY environment variable.")
    import sys
    sys.exit(1)
else:
    genai.configure(api_key=GEMINI_API_KEY)

class ReviewSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class IssueType(Enum):
    SECURITY = "security"
    PERFORMANCE = "performance"
    MAINTAINABILITY = "maintainability"
    BUG = "bug"
    CODE_SMELL = "code_smell"
    DEPENDENCY = "dependency"
    ARCHITECTURE = "architecture"
    DOCUMENTATION = "documentation"

@dataclass
class ReviewIssue:
    """Represents a code review issue"""
    id: str
    type: IssueType
    severity: ReviewSeverity
    title: str
    description: str
    file_path: str
    line_number: Optional[int]
    recommendation: str
    code_snippet: Optional[str] = None
    fix_suggestion: Optional[str] = None
    dependencies: List[str] = None
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []
        if not self.id:
            self.id = hashlib.md5(f"{self.file_path}_{self.title}".encode()).hexdigest()[:8]

@dataclass
class RefactoringRecommendation:
    """Represents a refactoring recommendation"""
    id: str
    target_files: List[str]
    description: str
    rationale: str
    estimated_effort: str
    priority: ReviewSeverity
    semantic_grouping: List[str]
    
    def __post_init__(self):
        if not self.id:
            content = "_".join(self.target_files) + self.description
            self.id = hashlib.md5(content.encode()).hexdigest()[:8]

@dataclass
class SecurityFinding:
    """Represents a security vulnerability finding"""
    id: str
    vulnerability_type: str
    severity: ReviewSeverity
    cwe_id: Optional[str]
    description: str
    affected_files: List[str]
    attack_vector: str
    mitigation: str
    cvss_score: Optional[float] = None
    
    def __post_init__(self):
        if not self.id:
            content = f"{self.vulnerability_type}_{self.description}"
            self.id = hashlib.md5(content.encode()).hexdigest()[:8]

@dataclass
class DependencyAnalysis:
    """Represents dependency analysis results"""
    external_dependencies: List[str]
    internal_dependencies: Dict[str, List[str]]
    circular_dependencies: List[List[str]]
    unused_dependencies: List[str]
    outdated_dependencies: List[Dict[str, Any]]
    vulnerability_scan: List[SecurityFinding]

@dataclass
class ReviewReport:
    """Comprehensive review report"""
    project_name: str
    timestamp: str
    summary: str
    issues: List[ReviewIssue]
    refactoring_recommendations: List[RefactoringRecommendation]
    security_findings: List[SecurityFinding]
    dependency_analysis: DependencyAnalysis
    control_flow_analysis: Dict[str, Any]
    metrics: Dict[str, Any]
    total_files_reviewed: int
    total_lines_of_code: int
    
class SemanticRefactoringAgent:
    """Agent for semantic refactoring analysis"""
    
    def __init__(self):
        self.model = genai.GenerativeModel('gemini-2.5-flash')
        self.max_retries = 100
    
    def analyze_subtrees(self, subtrees: List[Dict], hash_map: Dict) -> List[RefactoringRecommendation]:
        """Analyze subtrees for refactoring opportunities"""
        logger.info("Starting semantic refactoring analysis")
        
        recommendations = []
        
        similar_groups = self._find_similar_subtrees(subtrees, hash_map)
        
        for group in similar_groups:
            recommendation = self._analyze_group_for_refactoring(group, hash_map)
            if recommendation:
                recommendations.append(recommendation)
        
        for subtree_data in subtrees:
            individual_recs = self._analyze_individual_subtree(subtree_data, hash_map)
            recommendations.extend(individual_recs)
        
        logger.info(f"Generated {len(recommendations)} refactoring recommendations")
        return recommendations
    
    def _find_similar_subtrees(self, subtrees: List[Dict], hash_map: Dict) -> List[List[Dict]]:
        """Find semantically similar subtrees that could be merged"""
        subtree_summaries = []
        for subtree_data in subtrees:
            subtree_id = subtree_data.get('id')
            if subtree_id in hash_map:
                summary_data = {
                    'id': subtree_id,
                    'summary': hash_map[subtree_id]['semantic_summary'],
                    'files': hash_map[subtree_id]['file_paths'],
                    'dependencies': hash_map[subtree_id]['dependencies'],
                    'metadata': hash_map[subtree_id]['metadata']
                }
                subtree_summaries.append(summary_data)
        
        if len(subtree_summaries) < 2:
            return []
        
        prompt = f"""
        Analyze the following subtrees and identify groups that could be semantically merged or refactored together.
        Look for:
        - Similar functionality patterns
        - Duplicate or near-duplicate code structures
        - Related business logic that's scattered
        - Tightly coupled components that should be grouped
        
        Subtrees to analyze:
        {json.dumps(subtree_summaries, indent=2)}
        
        Return ONLY a valid JSON array where each element is a list of subtree IDs that should be grouped together.
        Only include groups with 2 or more subtrees. Example: [["id1", "id2"], ["id3", "id4", "id5"]]
        """
        
        for attempt in range(self.max_retries):
            try:
                response = self.model.generate_content(prompt)
                cleaned_response = self._clean_json_response(response.text)
                groups_data = safe_json_loads(cleaned_response)
                if groups_data is None:
                    logger.warning(
                        "Malformed JSON from Gemini in similar subtree grouping. Raw response truncated: %s",
                        cleaned_response[:250],
                    )
                    continue
                
                id_to_subtree = {s['id']: s for s in subtree_summaries}
                result_groups = []
                
                for group_ids in groups_data:
                    group_subtrees = []
                    for subtree_id in group_ids:
                        if subtree_id in id_to_subtree:
                            group_subtrees.append(id_to_subtree[subtree_id])
                    if len(group_subtrees) >= 2:
                        result_groups.append(group_subtrees)
                
                return result_groups
                
            except KeyboardInterrupt:
                raise
            except Exception as e:
                if self._is_rate_limit_error(e):
                    self._handle_rate_limit(attempt)
                    continue
                else:
                    logger.warning(f"Error finding similar subtrees: {e}")
                    return []
        
        logger.warning("Max retries exhausted for finding similar subtrees")
        return []
    
    def _analyze_group_for_refactoring(self, group: List[Dict], hash_map: Dict) -> Optional[RefactoringRecommendation]:
        """Analyze a group of similar subtrees for refactoring opportunities"""
        if len(group) < 2:
            return None
        
        group_info = {
            'subtrees': group,
            'total_files': sum(len(s['files']) for s in group),
            'combined_summary': ' | '.join(s['summary'] for s in group)
        }
        
        prompt = f"""
        Analyze this group of semantically related subtrees for refactoring opportunities:
        
        {json.dumps(group_info, indent=2)}
        
        Provide a refactoring recommendation in the following JSON format:
        {{
            "should_refactor": true/false,
            "description": "Clear description of what should be refactored",
            "rationale": "Why this refactoring would improve the codebase",
            "estimated_effort": "small/medium/large",
            "priority": "critical/high/medium/low",
            "semantic_grouping": ["list of related concepts/patterns found"]
        }}
        
        Only recommend refactoring if there's clear benefit. Consider:
        - Code duplication elimination
        - Improved maintainability
        - Better separation of concerns
        - Enhanced testability
        """
        
        for attempt in range(self.max_retries):
            try:
                response = self.model.generate_content(prompt)
                cleaned_response = self._clean_json_response(response.text)
                analysis = safe_json_loads(cleaned_response)
                if analysis is None:
                    logger.warning(
                        "Malformed JSON from Gemini in group refactoring analysis. Raw response truncated: %s",
                        cleaned_response[:250],
                    )
                    continue
                
                if analysis.get('should_refactor', False):
                    all_files = []
                    for subtree in group:
                        all_files.extend(subtree['files'])
                    
                    return RefactoringRecommendation(
                        id="",
                        target_files=all_files,
                        description=analysis['description'],
                        rationale=analysis['rationale'],
                        estimated_effort=analysis['estimated_effort'],
                        priority=ReviewSeverity(analysis['priority'].lower()),
                        semantic_grouping=analysis['semantic_grouping']
                    )
                
                return None
                
            except KeyboardInterrupt:
                raise
            except Exception as e:
                if self._is_rate_limit_error(e):
                    self._handle_rate_limit(attempt)
                    continue
                else:
                    logger.warning(f"Error analyzing group for refactoring: {e}")
                    return None
        
        return None
    
    def _analyze_individual_subtree(self, subtree_data: Dict, hash_map: Dict) -> List[RefactoringRecommendation]:
        """Analyze individual subtree for internal refactoring opportunities"""
        subtree_id = subtree_data.get('id')
        if subtree_id not in hash_map:
            return []
        
        subtree_info = hash_map[subtree_id]
        
        if subtree_info['metadata'].get('file_count', 0) < 2:
            return []
        
        prompt = f"""
        Analyze this subtree for internal refactoring opportunities:
        
        Summary: {subtree_info['semantic_summary']}
        Files: {subtree_info['file_paths']}
        Dependencies: {subtree_info['dependencies']}
        Metadata: {subtree_info['metadata']}
        
        Look for internal refactoring opportunities such as:
        - Large files that should be split
        - Functions/classes that violate single responsibility
        - Complex dependency chains within the subtree
        - Opportunities for better abstraction
        
        Return a JSON array of refactoring recommendations. Each recommendation should have:
        {{
            "description": "What should be refactored",
            "rationale": "Why this would improve the code",
            "estimated_effort": "small/medium/large",
            "priority": "critical/high/medium/low",
            "semantic_grouping": ["related concepts"]
        }}
        
        Return empty array [] if no significant refactoring opportunities exist.
        """
        
        for attempt in range(self.max_retries):
            try:
                response = self.model.generate_content(prompt)
                cleaned_response = self._clean_json_response(response.text)
                recommendations_data = safe_json_loads(cleaned_response)
                if recommendations_data is None:
                    logger.warning(
                        "Malformed JSON from Gemini in individual subtree refactoring analysis. Raw response truncated: %s",
                        cleaned_response[:250],
                    )
                    continue
                
                recommendations = []
                for rec_data in recommendations_data:
                    recommendation = RefactoringRecommendation(
                        id="",
                        target_files=subtree_info['file_paths'],
                        description=rec_data['description'],
                        rationale=rec_data['rationale'],
                        estimated_effort=rec_data['estimated_effort'],
                        priority=ReviewSeverity(rec_data['priority'].lower()),
                        semantic_grouping=rec_data['semantic_grouping']
                    )
                    recommendations.append(recommendation)
                
                return recommendations
                
            except KeyboardInterrupt:
                raise
            except Exception as e:
                if self._is_rate_limit_error(e):
                    self._handle_rate_limit(attempt)
                    continue
                else:
                    logger.warning(f"Error analyzing individual subtree: {e}")
                    return []
        
        return []
    
    def _clean_json_response(self, text: str) -> str:
        """Clean Gemini response to extract valid JSON (copied from other agents)"""
        text = text.strip()
        if text.startswith('```json'):
            text = text[7:]
        if text.startswith('```'):
            text = text[3:]
        if text.endswith('```'):
            text = text[:-3]
        text = text.strip()
        start_chars = ['{', '[']
        end_chars = ['}', ']']
        start_idx = -1
        for char in start_chars:
            idx = text.find(char)
            if idx != -1 and (start_idx == -1 or idx < start_idx):
                start_idx = idx
        if start_idx == -1:
            return text
        start_char = text[start_idx]
        end_char = '}' if start_char == '{' else ']'
        end_idx = text.rfind(end_char)
        if end_idx != -1 and end_idx > start_idx:
            text = text[start_idx:end_idx + 1]
        return text
    
    def _is_rate_limit_error(self, error) -> bool:
        """Check if error is a rate limit error (copied from other agents)"""
        error_str = str(error).lower()
        return '429' in error_str or 'quota' in error_str or 'rate limit' in error_str
    
    def _handle_rate_limit(self, attempt: int):
        """Handle rate limit with exponential backoff (copied from other agents)"""
        wait_time = min(60, 2 ** (attempt % 6))
        logger.warning(f"Rate limit hit, waiting {wait_time} seconds (attempt {attempt + 1})")
        time.sleep(wait_time)

class ControlFlowSecurityAgent:
    """Agent for control flow and security analysis"""
    
    def __init__(self):
        self.model = genai.GenerativeModel('gemini-2.5-flash')
        self.max_retries = 100
    
    def analyze_control_flow_and_security(self, subtrees: List[Dict], hash_map: Dict) -> Tuple[Dict[str, Any], List[SecurityFinding], List[ReviewIssue]]:
        """Analyze control flow and security aspects"""
        logger.info("Starting control flow and security analysis")
        api_key_findings = scan_for_api_keys(subtrees, hash_map)
        control_flow_analysis = self._analyze_control_flow(subtrees, hash_map)
        security_findings = self._analyze_security(subtrees, hash_map, api_key_findings)
        control_flow_issues = self._identify_control_flow_issues(control_flow_analysis)
        logger.info(f"Found {len(security_findings)} security findings and {len(control_flow_issues)} control flow issues")
        return control_flow_analysis, security_findings, control_flow_issues
    
    def _analyze_control_flow(self, subtrees: List[Dict], hash_map: Dict) -> Dict[str, Any]:
        """Analyze control flow patterns across subtrees"""
        subtree_summaries = []
        for subtree_data in subtrees:
            subtree_id = subtree_data.get('id')
            if subtree_id in hash_map:
                subtree_info = hash_map[subtree_id]
                summary = {
                    'id': subtree_id,
                    'summary': subtree_info['semantic_summary'],
                    'files': subtree_info['file_paths'],
                    'dependencies': subtree_info['dependencies']
                }
                subtree_summaries.append(summary)
        
        prompt = f"""
        Analyze the control flow relationships between these code subtrees:
        
        {json.dumps(subtree_summaries, indent=2)}
        
        Provide analysis in this JSON format:
        {{
            "entry_points": ["list of main entry point files/functions"],
            "data_flow_patterns": ["description of how data flows through the system"],
            "control_dependencies": {{"subtree_id": ["dependent_subtree_ids"]}},
            "potential_bottlenecks": ["areas that might cause performance issues"],
            "error_handling_patterns": ["how errors are handled across the system"],
            "complexity_hotspots": ["areas with high cyclomatic/cognitive complexity"]
        }}
        """
        
        for attempt in range(self.max_retries):
            try:
                response = self.model.generate_content(prompt)
                cleaned_response = self._clean_json_response(response.text)
                analysis = safe_json_loads(cleaned_response)
                if analysis is None:
                    logger.warning(
                        "Malformed JSON from Gemini in control-flow analysis. Raw response truncated: %s",
                        cleaned_response[:250],
                    )
                    continue

                default_structure = {
                    "entry_points": [],
                    "data_flow_patterns": [],
                    "control_dependencies": {},
                    "potential_bottlenecks": [],
                    "error_handling_patterns": [],
                    "complexity_hotspots": []
                }
                for key, default_val in default_structure.items():
                    analysis.setdefault(key, default_val)

                return analysis

            except KeyboardInterrupt:
                raise
            except Exception as e:
                if self._is_rate_limit_error(e):
                    self._handle_rate_limit(attempt)
                    continue
                else:
                    logger.warning(f"Error analyzing control flow (attempt {attempt + 1}): {e}")
                    continue

        logger.warning("Control-flow analysis failed after max retries – using fallback heuristics")
        return self._fallback_control_flow_analysis(subtrees, hash_map)

    def _fallback_control_flow_analysis(self, subtrees: List[Dict], hash_map: Dict) -> Dict[str, Any]:
        """Generate a best-effort control-flow analysis without the LLM.

        This heuristic approach ensures the report always contains at least
        minimal information, preventing empty UI sections when the model
        response is malformed or unavailable.
        """
        import os
        entry_points: List[str] = []
        potential_bottlenecks: List[str] = []

        for subtree in subtrees:
            sid = subtree.get("id")
            info = hash_map.get(sid, {})
            for fp in info.get("file_paths", []):
                bn = os.path.basename(fp).lower()
                if bn == "main.py" or bn.endswith("_main.py"):
                    entry_points.append(fp)

            if info:
                lines = info.get("metadata", {}).get("total_lines", 0)
                if lines and lines > 800:
                    potential_bottlenecks.append(
                        f"Subtree {sid} contains large file(s) totalling {lines} lines which may impact readability and performance."
                    )

        entry_points = list(dict.fromkeys(entry_points))

        return {
            "entry_points": entry_points,
            "data_flow_patterns": [],
            "control_dependencies": {},
            "potential_bottlenecks": potential_bottlenecks,
            "error_handling_patterns": [],
            "complexity_hotspots": []
        }
    
    def _analyze_security(self, subtrees: List[Dict], hash_map: Dict, api_key_findings=None) -> List[SecurityFinding]:
        """Analyze for security vulnerabilities"""
        if api_key_findings is None:
            api_key_findings = []
        security_findings = []
        
        for subtree_data in subtrees:
            subtree_id = subtree_data.get('id')
            if subtree_id not in hash_map:
                continue
            
            subtree_info = hash_map[subtree_id]
            findings = self._analyze_subtree_security(subtree_info, api_key_findings)
            security_findings.extend(findings)
        
        return security_findings
    
    def _analyze_subtree_security(self, subtree_info: Dict, api_key_findings=None) -> List[SecurityFinding]:
        """Analyze individual subtree for security issues"""
        if api_key_findings is None:
            api_key_findings = []
        relevant_keys = [f for f in api_key_findings if f['file'] in subtree_info['file_paths']]
        api_key_context = "\n".join([
            f"API key found in {f['file']} at line {f['line']}: {f['value']}" for f in relevant_keys
        ])
        prompt = f"""
        Perform a security analysis on this code subtree:
        
        Summary: {subtree_info['semantic_summary']}
        Files: {subtree_info['file_paths']}
        Dependencies: {subtree_info['dependencies']}
        {('The following hard-coded API keys/secrets were found in this subtree:\n' + api_key_context) if api_key_context else ''}
        Look for common security vulnerabilities such as:
        - Input validation issues
        - SQL injection possibilities
        - Cross-site scripting (XSS)
        - Authentication/authorization flaws
        - Insecure data storage
        - Cryptographic issues
        - Dependency vulnerabilities
        - Information disclosure
        - Unsafe file operations
        - Command injection
        IMPORTANT: Only report actual, observed vulnerabilities or insecure code patterns found in the provided code. Do NOT report theoretical threats, generic risks, or issues that are not directly evidenced in the code. Do not speculate or make up issues.
        When writing the mitigation, use clear plain text. For numbered or bulleted lists, ensure each item starts on a new line. Do not use markdown formatting (such as ** for bold or * for bullets); use plain text only. Example:
        1. Do this first.
        2. Do this second.
        Return a JSON array of security findings. Each finding should have:
        {{
            "vulnerability_type": "specific type of vulnerability",
            "severity": "critical/high/medium/low",
            "cwe_id": "CWE identifier if applicable",
            "description": "detailed description of the vulnerability",
            "attack_vector": "how this could be exploited",
            "mitigation": "how to fix this vulnerability (plain text, no markdown)",
            "cvss_score": numerical_score_if_applicable
        }}
        
        Return empty array [] if no security issues are found.
        """
        
        for attempt in range(self.max_retries):
            try:
                response = self.model.generate_content(prompt)
                cleaned_response = self._clean_json_response(response.text)
                findings_data = safe_json_loads(cleaned_response)
                if findings_data is None:
                    logger.warning(
                        "Malformed JSON from Gemini in security analysis. Raw response truncated: %s",
                        cleaned_response[:250],
                    )
                    continue
                findings = []
                for finding_data in findings_data:
                    finding = SecurityFinding(
                        id="",
                        vulnerability_type=finding_data['vulnerability_type'],
                        severity=ReviewSeverity(finding_data['severity'].lower()),
                        cwe_id=finding_data.get('cwe_id'),
                        description=finding_data['description'],
                        affected_files=subtree_info['file_paths'],
                        attack_vector=finding_data['attack_vector'],
                        mitigation=finding_data['mitigation'],
                        cvss_score=finding_data.get('cvss_score')
                    )
                    findings.append(finding)
                return findings
            except KeyboardInterrupt:
                raise
            except Exception as e:
                if self._is_rate_limit_error(e):
                    self._handle_rate_limit(attempt)
                    continue
                else:
                    logger.warning(f"Error analyzing subtree security: {e}")
                    return []
        return []
    
    def _identify_control_flow_issues(self, control_flow_analysis: Dict) -> List[ReviewIssue]:
        """Identify issues based on control flow analysis"""
        issues = []
        
        for hotspot in control_flow_analysis.get('complexity_hotspots', []):
            if not self._is_severe_complexity(hotspot):
                continue
            issue = ReviewIssue(
                id="",
                type=IssueType.MAINTAINABILITY,
                severity=ReviewSeverity.HIGH,
                title="High Complexity Detected",
                description=f"Complexity hotspot identified: {hotspot}",
                file_path="multiple",
                line_number=None,
                recommendation="Consider refactoring to reduce complexity and improve maintainability"
            )
            issues.append(issue)
        
        for bottleneck in control_flow_analysis.get('potential_bottlenecks', []):
            if not self._is_severe_bottleneck(bottleneck):
                continue
            issue = ReviewIssue(
                id="",
                type=IssueType.PERFORMANCE,
                severity=ReviewSeverity.HIGH,
                title="Potential Performance Bottleneck",
                description=f"Performance bottleneck identified: {bottleneck}",
                file_path="multiple",
                line_number=None,
                recommendation="Review and optimize this area for better performance"
            )
            issues.append(issue)
        
        return issues

    def _is_severe_bottleneck(self, text: str) -> bool:
        """Heuristic filter to decide whether a reported bottleneck is severe enough
        to warrant surfacing. Returns True only when the description suggests an
        egregious slowdown rather than a minor performance risk."""

        lower = text.lower()

        severe_keywords = [
            'o(n^2', 'o(n²', 'o(n^3', 'o(n³', 'quadratic', 'cubic',
            'n+1', 'n+1 query', 'significant slowdown', 'slow database',
            'blocking i/o', 'thread contention', 'deadlock', 'high latency',
            'memory leak', 'out-of-memory'
        ]

        if any(k in lower for k in severe_keywords):
            return True

        import re as _re
        match = _re.search(r'(\d[\d,]*)\s+lines', lower)
        if match:
            try:
                lines = int(match.group(1).replace(',', ''))
                if lines > 2000:
                    return True
            except ValueError:
                pass

        return False

    def _is_severe_complexity(self, text: str) -> bool:
        """Heuristic to decide if a complexity hotspot is truly severe.

        Looks for very high reported cyclomatic/cognitive complexity numbers or
        specific phrases indicating extreme nesting/size. Returns True only
        when the hotspot clearly violates maintainability best-practices."""

        lower = text.lower()

        severe_terms = [
            'cyclomatic complexity', 'cognitive complexity', 'nested',
            'deeply nested', 'high complexity', 'extremely complex',
            'very high complexity'
        ]

        if any(term in lower for term in severe_terms):
            import re as _re
            match = _re.search(r'(cyclomatic|cognitive) complexity[^\d]*(\d+)', lower)
            if match:
                try:
                    val = int(match.group(2))
                    if val >= 20:
                        return True
                except ValueError:
                    pass
            match_depth = _re.search(r'nested[^\d]*(\d+)', lower)
            if match_depth:
                try:
                    depth = int(match_depth.group(1))
                    if depth >= 5:
                        return True
                except ValueError:
                    pass

        import re as _re
        match_lines = _re.search(r'(\d[\d,]*)\s+lines', lower)
        if match_lines:
            try:
                lines = int(match_lines.group(1).replace(',', ''))
                if lines > 2000:
                    return True
            except ValueError:
                pass

        return False
    
    def _clean_json_response(self, text: str) -> str:
        """Clean Gemini response to extract valid JSON (copied from other agents)"""
        text = text.strip()
        if text.startswith('```json'):
            text = text[7:]
        if text.startswith('```'):
            text = text[3:]
        if text.endswith('```'):
            text = text[:-3]
        text = text.strip()
        start_chars = ['{', '[']
        end_chars = ['}', ']']
        start_idx = -1
        for char in start_chars:
            idx = text.find(char)
            if idx != -1 and (start_idx == -1 or idx < start_idx):
                start_idx = idx
        if start_idx == -1:
            return text
        start_char = text[start_idx]
        end_char = '}' if start_char == '{' else ']'
        end_idx = text.rfind(end_char)
        if end_idx != -1 and end_idx > start_idx:
            text = text[start_idx:end_idx + 1]
        return text
    
    def _is_rate_limit_error(self, error) -> bool:
        """Check if error is a rate limit error (copied from other agents)"""
        error_str = str(error).lower()
        return '429' in error_str or 'quota' in error_str or 'rate limit' in error_str
    
    def _handle_rate_limit(self, attempt: int):
        """Handle rate limit with exponential backoff (copied from other agents)"""
        wait_time = min(60, 2 ** (attempt % 6))
        logger.warning(f"Rate limit hit, waiting {wait_time} seconds (attempt {attempt + 1})")
        time.sleep(wait_time)

class DependencyAnalysisAgent:
    """Agent for dependency analysis"""
    
    def __init__(self):
        self.model = genai.GenerativeModel('gemini-2.5-flash')
        self.max_retries = 100
    
    def analyze_dependencies(self, subtrees: List[Dict], hash_map: Dict) -> DependencyAnalysis:
        """Perform comprehensive dependency analysis"""
        logger.info("Starting dependency analysis")
        
        all_external_deps = set()
        internal_deps = {}
        
        for subtree_data in subtrees:
            subtree_id = subtree_data.get('id')
            if subtree_id in hash_map:
                subtree_info = hash_map[subtree_id]
                deps = subtree_info.get('dependencies', [])
                
                external_deps, internal_subtree_deps = self._categorize_dependencies(deps, subtree_info['file_paths'])
                all_external_deps.update(external_deps)
                internal_deps[subtree_id] = internal_subtree_deps
        
        circular_deps = self._find_circular_dependencies(internal_deps)
        
        unused_deps = self._find_unused_dependencies(list(all_external_deps), subtrees, hash_map)
        outdated_deps = self._find_outdated_dependencies(list(all_external_deps))
        vulnerability_scan = self._scan_dependency_vulnerabilities(list(all_external_deps))
        
        return DependencyAnalysis(
            external_dependencies=list(all_external_deps),
            internal_dependencies=internal_deps,
            circular_dependencies=circular_deps,
            unused_dependencies=unused_deps,
            outdated_dependencies=outdated_deps,
            vulnerability_scan=vulnerability_scan
        )
    
    def _categorize_dependencies(self, deps: List[str], file_paths: List[str]) -> Tuple[List[str], List[str]]:
        """Categorize dependencies as external or internal"""
        external_deps = []
        internal_deps = []
        
        file_dirs = set()
        for file_path in file_paths:
            file_dirs.add(str(Path(file_path).parent))
        
        for dep in deps:
            if self._looks_like_external_dependency(dep, file_dirs):
                external_deps.append(dep)
            else:
                internal_deps.append(dep)
        
        return external_deps, internal_deps
    
    def _looks_like_external_dependency(self, dep: str, file_dirs: set) -> bool:
        """Determine if a dependency is external"""
        external_indicators = [
            '.',
            not any(dir_part in dep for dir_part in file_dirs),
            dep in ['os', 'sys', 'json', 'time', 'logging', 'pathlib', 'typing', 'dataclasses', 'enum']
        ]
        
        return any(external_indicators)
    
    def _find_circular_dependencies(self, internal_deps: Dict[str, List[str]]) -> List[List[str]]:
        """Find circular dependency chains"""
        def dfs(node, path, visited, cycles):
            if node in path:
                cycle_start = path.index(node)
                cycle = path[cycle_start:] + [node]
                cycles.append(cycle)
                return
            
            if node in visited:
                return
            
            visited.add(node)
            path.append(node)
            
            for neighbor in internal_deps.get(node, []):
                if neighbor in internal_deps:
                    dfs(neighbor, path, visited, cycles)
            
            path.pop()
        
        cycles = []
        visited = set()
        
        for node in internal_deps:
            if node not in visited:
                dfs(node, [], visited, cycles)
        
        return cycles
    
    def _find_unused_dependencies(self, external_deps: List[str], subtrees: List[Dict], hash_map: Dict) -> List[str]:
        """Find potentially unused external dependencies"""
        if not external_deps:
            return []
        
        used_deps = set()
        for subtree_data in subtrees:
            subtree_id = subtree_data.get('id')
            if subtree_id in hash_map:
                subtree_info = hash_map[subtree_id]
                used_deps.update(subtree_info.get('dependencies', []))
        
        potentially_unused = []
        for dep in external_deps:
            if dep not in used_deps:
                potentially_unused.append(dep)
        
        return potentially_unused
    
    def _find_outdated_dependencies(self, external_deps: List[str]) -> List[Dict[str, Any]]:
        """Analyze external dependencies for outdated versions"""
        if not external_deps:
            return []
        
        prompt = f"""
        Analyze these external dependencies for potential version issues:
        
        Dependencies: {external_deps}
        
        For each dependency, check if it's a well-known package that might have:
        - Outdated versions
        - Known security issues
        - Better alternatives
        - Deprecated status
        
        Return a JSON array of outdated/problematic dependencies:
        [
            {{
                "name": "dependency_name",
                "issue": "outdated/deprecated/security",
                "current_concern": "description of the issue",
                "recommendation": "what to do about it"
            }}
        ]
        
        Return empty array [] if no issues are identified.
        """
        
        for attempt in range(self.max_retries):
            try:
                response = self.model.generate_content(prompt)
                cleaned_response = self._clean_json_response(response.text)
                data = safe_json_loads(cleaned_response)
                if data is not None:
                    return data
                logger.warning(
                    "Malformed JSON from Gemini in outdated dependencies. Raw response truncated: %s",
                    cleaned_response[:250],
                )
                continue
            except KeyboardInterrupt:
                raise
            except Exception as e:
                if self._is_rate_limit_error(e):
                    self._handle_rate_limit(attempt)
                    continue
                else:
                    logger.warning(f"Error finding outdated dependencies: {e}")
                    return []
        return []
    
    def _scan_dependency_vulnerabilities(self, external_deps: List[str]) -> List[SecurityFinding]:
        """Scan dependencies for known vulnerabilities"""
        if not external_deps:
            return []
        
        prompt = f"""
        Analyze these external dependencies for known security vulnerabilities:
        Dependencies: {external_deps}
        For each dependency, check for:
        - Known CVEs or vulnerabilities
        - Security advisories
        - Common risks (e.g., outdated, unmaintained, risky usage)
        Return a JSON array of findings:
        [
            {{
                "vulnerability_type": "type of vulnerability",
                "severity": "critical/high/medium/low",
                "cwe_id": "CWE identifier if applicable",
                "description": "description of the vulnerability",
                "attack_vector": "how it could be exploited",
                "mitigation": "how to fix",
                "cvss_score": numerical_score_if_applicable
            }}
        ]
        Return empty array [] if no issues are found.
        """
        for attempt in range(self.max_retries):
            try:
                response = self.model.generate_content(prompt)
                cleaned_response = self._clean_json_response(response.text)
                findings_data = safe_json_loads(cleaned_response)
                if findings_data is None:
                    logger.warning(
                        "Malformed JSON from Gemini in dependency vulnerabilities. Raw response truncated: %s",
                        cleaned_response[:250],
                    )
                    continue
                findings = []
                for finding_data in findings_data:
                    finding = SecurityFinding(
                        id="",
                        vulnerability_type=finding_data['vulnerability_type'],
                        severity=ReviewSeverity(finding_data['severity'].lower()),
                        cwe_id=finding_data.get('cwe_id'),
                        description=finding_data['description'],
                        affected_files=[],
                        attack_vector=finding_data['attack_vector'],
                        mitigation=finding_data['mitigation'],
                        cvss_score=finding_data.get('cvss_score')
                    )
                    findings.append(finding)
                return findings
            except KeyboardInterrupt:
                raise
            except Exception as e:
                if self._is_rate_limit_error(e):
                    self._handle_rate_limit(attempt)
                    continue
                else:
                    logger.warning(f"Error scanning dependency vulnerabilities: {e}")
                    return []
        return []
    
    def _clean_json_response(self, text: str) -> str:
        """Clean Gemini response to extract valid JSON"""
        text = text.strip()
        if text.startswith('```json'):
            text = text[7:]
        if text.startswith('```'):
            text = text[3:]
        if text.endswith('```'):
            text = text[:-3]
        text = text.strip()
        start_chars = ['{', '[']
        end_chars = ['}', ']']
        start_idx = -1
        for char in start_chars:
            idx = text.find(char)
            if idx != -1 and (start_idx == -1 or idx < start_idx):
                start_idx = idx
        if start_idx == -1:
            return text
        start_char = text[start_idx]
        end_char = '}' if start_char == '{' else ']'
        end_idx = text.rfind(end_char)
        if end_idx != -1 and end_idx > start_idx:
            text = text[start_idx:end_idx + 1]
        return text
    
    def _is_rate_limit_error(self, error) -> bool:
        """Check if error is a rate limit error"""
        error_str = str(error).lower()
        return '429' in error_str or 'quota' in error_str or 'rate limit' in error_str
    
    def _handle_rate_limit(self, attempt: int):
        """Handle rate limit with exponential backoff"""
        wait_time = min(60, 2 ** (attempt % 6))
        logger.warning(f"Rate limit hit, waiting {wait_time} seconds (attempt {attempt + 1})")
        time.sleep(wait_time)

class StaticAnalysisAgent:
    """Executes offline static-analysis tools (Bandit, Radon, pip-audit) whenever
    they are available on the host system. Falls back gracefully when tools are
    missing, and converts their findings into ReviewIssue / SecurityFinding
    objects so they appear in the unified report.

    IMPORTANT: The agent never fails the entire review; all subprocess errors
    are caught and logged so the pipeline remains robust.
    """

    def __init__(self, project_root: str):
        self.project_root = project_root

    def run(self) -> Tuple[List[ReviewIssue], List[SecurityFinding]]:
        issues: List[ReviewIssue] = []
        findings: List[SecurityFinding] = []

        bandit_findings = self._run_bandit()
        findings.extend(bandit_findings)

        radon_issues = self._run_radon_cc()
        issues.extend(radon_issues)

        pipaudit_findings = self._run_pip_audit()
        findings.extend(pipaudit_findings)

        return issues, findings

    def _run_bandit(self) -> List[SecurityFinding]:
        """Run Bandit security linter if available and parse JSON output."""
        if shutil.which("bandit") is None:
            logger.info("Bandit not found on PATH – skipping Bandit analysis")
            return []

        cmd = [
            "bandit",
            "-r",
            self.project_root,
            "-f",
            "json",
            "--quiet",
        ]

        try:
            completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if completed.returncode not in (0, 1):
                logger.warning("Bandit exited with code %s: %s", completed.returncode, completed.stderr.strip())
                return []

            output = completed.stdout.strip()
            if not output:
                return []

            data = safe_json_loads(output)
            if data is None:
                logger.warning("Bandit produced non-JSON output; skipping parse")
                return []

            results = data.get("results", [])
            findings: List[SecurityFinding] = []
            for res in results:
                severity = res.get("issue_severity", "LOW").lower()
                try:
                    sev_enum = ReviewSeverity(severity)
                except ValueError:
                    sev_enum = ReviewSeverity.INFO

                finding = SecurityFinding(
                    id="",
                    vulnerability_type=res.get("test_name", "bandit_issue"),
                    severity=sev_enum,
                    cwe_id=res.get("test_id"),
                    description=res.get("issue_text", ""),
                    affected_files=[res.get("filename", "")],
                    attack_vector="Static code analysis – see Bandit rule",
                    mitigation=(
                        "Address the vulnerability reported by Bandit. Refer to Bandit documentation for "
                        f"test ID {res.get('test_id')} and apply recommended fixes."
                    ),
                    cvss_score=None,
                )
                findings.append(finding)

            return findings
        except Exception as e:
            logger.exception("Failed to run Bandit: %s", e)
            return []

    def _run_radon_cc(self) -> List[ReviewIssue]:
        """Run Radon cyclomatic complexity analysis and flag high-complexity blocks."""
        if shutil.which("radon") is None:
            logger.info("Radon not found on PATH – skipping complexity analysis")
            return []

        cmd = ["radon", "cc", "-j", self.project_root]

        try:
            completed = subprocess.run(cmd, capture_output=True, text=True, check=True)
            output = completed.stdout.strip()
            data = safe_json_loads(output)
            if data is None:
                logger.warning("Radon produced non-JSON output; skipping parse")
                return []

            issues: List[ReviewIssue] = []
            RANK_THRESHOLD = set(["D", "E", "F"])
            for file_path, blocks in data.items():
                for block in blocks:
                    rank = block.get("rank")
                    complexity = block.get("complexity", 0)
                    lineno = block.get("lineno", None)
                    if rank in RANK_THRESHOLD or complexity >= 15:
                        issues.append(
                            ReviewIssue(
                                id="",
                                type=IssueType.MAINTAINABILITY,
                                severity=ReviewSeverity.HIGH if rank in ("E", "F") or complexity >= 20 else ReviewSeverity.MEDIUM,
                                title="High cyclomatic complexity",
                                description=(
                                    f"Block '{block.get('name')}' in {file_path} has complexity {complexity} (rank {rank})."
                                ),
                                file_path=file_path,
                                line_number=lineno,
                                recommendation="Refactor this function to reduce complexity and improve readability.",
                            )
                        )

            return issues
        except subprocess.CalledProcessError as e:
            logger.warning("Radon failed: %s", e)
            return []
        except Exception as e:
            logger.exception("Error parsing Radon output: %s", e)
            return []

    def _run_pip_audit(self) -> List[SecurityFinding]:
        """Run pip-audit to detect vulnerable dependencies if installed."""
        if shutil.which("pip-audit") is None:
            logger.info("pip-audit not found on PATH – skipping dependency vulnerability scan")
            return []

        req_file = os.path.join(self.project_root, "requirements.txt")
        if os.path.isfile(req_file):
            cmd = ["pip-audit", "-r", req_file, "-f", "json"]
            logger.info("Running pip-audit against %s", req_file)
        else:
            cmd = ["pip-audit", "-f", "json"]
            logger.info("Running pip-audit against current environment (requirements.txt not found)")
        try:
            completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if completed.returncode not in (0, 1):
                logger.warning("pip-audit exited with code %s", completed.returncode)
                return []

            output = completed.stdout.strip()
            if not output:
                return []

            data = safe_json_loads(output)
            if data is None:
                logger.warning("pip-audit returned non-JSON; skipping parse")
                return []

            findings: List[SecurityFinding] = []
            seen = set()
            for vuln in data:
                pkg = vuln.get("name")
                version = vuln.get("version")
                id_list = vuln.get("vulns", [])
                for entry in id_list:
                    vuln_id = entry.get("id")
                    key = (pkg, vuln_id)
                    if key in seen:
                        continue
                    seen.add(key)

                    severity_enum = ReviewSeverity.CRITICAL
                    if "severity" in entry:
                        sev = str(entry["severity"]).lower()
                        if sev in ReviewSeverity.__members__.values():
                            try:
                                severity_enum = ReviewSeverity(sev)
                            except ValueError:
                                pass

                    finding = SecurityFinding(
                        id="",
                        vulnerability_type=f"Dependency vulnerability: {pkg}",
                        severity=severity_enum,
                        cwe_id=vuln_id,
                        description=f"{pkg} {version} is affected: {entry.get('description', '')}",
                        affected_files=[],
                        attack_vector="Supply chain / vulnerable dependency",
                        mitigation=entry.get("fix", "Upgrade to a secure version"),
                        cvss_score=entry.get("cvss", {}).get("score") if isinstance(entry.get("cvss"), dict) else None,
                    )
                    findings.append(finding)
            return findings
        except Exception as e:
            logger.exception("Failed to run pip-audit: %s", e)
            return []

def scan_for_api_keys(subtrees, hash_map):
    """
    Scan all files in the codebase for hard-coded API keys/secrets.
    Returns a list of dicts: {file, line, key_type, value}
    """
    import re
    api_key_patterns = [
        r'(?i)(api[_-]?key|secret|token|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9\-_=]{16,})["\']',
        r'AIza[0-9A-Za-z\-_]{35}',
        r'sk_live_[0-9a-zA-Z]{24,}',
        r'ghp_[0-9A-Za-z]{36,}',
        r'(?i)aws(.{0,20})?(access|secret)?(.{0,20})?key(.{0,20})?(["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{20,40}["\']?)',
    ]
    findings = []
    for subtree in subtrees:
        for file_path in hash_map.get(subtree.get('id'), {}).get('file_paths', []):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for i, line in enumerate(f, 1):
                        for pat in api_key_patterns:
                            for match in re.finditer(pat, line):
                                findings.append({
                                    'file': file_path,
                                    'line': i,
                                    'key_type': match.group(1) if match.groups() else 'API_KEY',
                                    'value': match.group(0)
                                })
            except Exception:
                continue
    return findings

def detect_infinite_recursion(subtrees, hash_map):
    """Detect functions that call themselves without an obvious termination condition.

    This is a heuristic, best-effort static analysis intended to surface the
    most egregious cases of infinite recursion (e.g. a function whose body is
    primarily a direct call to itself).

    The algorithm parses each Python file into an AST and looks for functions
    that:
    1. Contain at least one direct self-call (e.g. `def foo(): foo()`), AND
    2. Have no control-flow constructs that could guard the recursion such as
       `if`, `while`, `for`, `try`, OR any explicit `return` *prior* to the
       self-call.

    The heuristic intentionally errs on the side of *not* flagging borderline
    cases to avoid false positives; it is therefore suitable as an additional
    safeguard on top of the LLM analysis, not a complete replacement.
    """

    issues = []

    def function_has_unconditional_self_call(func_node: ast.FunctionDef) -> Optional[int]:
        """Return the 1-based line number of the first unconditional self-call or
        None if no such pattern is found."""

        def is_guard(node: ast.stmt) -> bool:
            return isinstance(node, (ast.If, ast.For, ast.While, ast.Try, ast.With))

        for stmt in func_node.body:
            if is_guard(stmt):
                return None

            if isinstance(stmt, ast.Return):
                return None

            call_node = None
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call_node = stmt.value
            elif isinstance(stmt, ast.Call):
                call_node = stmt

            if call_node is None:
                return None

            callee_name = None
            if isinstance(call_node.func, ast.Name):
                callee_name = call_node.func.id
            elif isinstance(call_node.func, ast.Attribute) and isinstance(call_node.func.value, ast.Name):
                callee_name = call_node.func.attr

            if callee_name == func_node.name:
                return call_node.lineno

            return None

        return None

    for subtree in subtrees:
        for file_path in hash_map.get(subtree.get("id"), {}).get("file_paths", []):
            if not file_path.endswith(".py"):
                continue
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    source = f.read()
                tree = ast.parse(source, filename=file_path)

                for node in tree.body:
                    if isinstance(node, ast.FunctionDef):
                        line = function_has_unconditional_self_call(node)
                        if line is not None:
                            issues.append(
                                ReviewIssue(
                                    id="",
                                    type=IssueType.BUG,
                                    severity=ReviewSeverity.CRITICAL,
                                    title="Possible infinite recursion detected",
                                    description=(
                                        f"Function '{node.name}' appears to call itself without a termination "
                                        "condition, which will lead to a RuntimeError (maximum recursion depth "
                                        "exceeded)."
                                    ),
                                    file_path=file_path,
                                    line_number=line,
                                    recommendation=(
                                        "Add a proper base case or termination condition before the recursive "
                                        "call, or refactor the logic to an iterative approach if appropriate."
                                    ),
                                    code_snippet=None,
                                )
                            )
            except (SyntaxError, UnicodeDecodeError, FileNotFoundError):
                continue

    return issues

def main(subtrees_path: str, hash_map_path: str, output_path: str):
    with open(subtrees_path, 'r', encoding='utf-8') as f:
        subtrees = json.load(f)
    with open(hash_map_path, 'r', encoding='utf-8') as f:
        hash_map = json.load(f)

    refactoring_agent = SemanticRefactoringAgent()
    control_flow_agent = ControlFlowSecurityAgent()
    dependency_agent = DependencyAnalysisAgent()

    refactoring_recs = refactoring_agent.analyze_subtrees(subtrees, hash_map)
    control_flow_analysis, security_findings, control_flow_issues = control_flow_agent.analyze_control_flow_and_security(subtrees, hash_map)
    dependency_analysis = dependency_agent.analyze_dependencies(subtrees, hash_map)

    static_agent = StaticAnalysisAgent(project_root=os.path.dirname(base_dir))
    static_issues, static_security_findings = static_agent.run()

    recursion_issues = detect_infinite_recursion(subtrees, hash_map)

    all_issues = control_flow_issues + recursion_issues + static_issues
    security_findings.extend(static_security_findings)

    total_files = sum(len(st.get('file_paths', [])) for st in hash_map.values())
    total_lines = sum(st.get('metadata', {}).get('total_lines', 0) for st in hash_map.values())

    report = ReviewReport(
        project_name="Project Review",
        timestamp=datetime.now(timezone.utc).isoformat(),
        summary="Automated code review report.",
        issues=all_issues,
        refactoring_recommendations=refactoring_recs,
        security_findings=security_findings,
        dependency_analysis=dependency_analysis,
        control_flow_analysis=control_flow_analysis,
        metrics={},
        total_files_reviewed=total_files,
        total_lines_of_code=total_lines
    )

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(asdict(report), f, indent=2, default=str)
    logger.info(f"Review report written to {output_path}")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    subtrees_path = os.path.join(base_dir, "code-packager", "output", "subtrees.json")
    hash_map_path = os.path.join(base_dir, "code-packager", "output", "hash_map.json")
    output_path = os.path.join(base_dir, "review-caller", "review_report.json")
    main(subtrees_path, hash_map_path, output_path)