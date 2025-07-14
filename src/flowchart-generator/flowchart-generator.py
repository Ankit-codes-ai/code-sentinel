import os
import json
import re
import time
import google.generativeai as genai
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).parent
SUBTREES_PATH = SCRIPT_DIR / '../code-packager/output/subtrees.json'
HASH_MAP_PATH = SCRIPT_DIR / '../code-packager/output/hash_map.json'
OUTPUT_MERMAID_PATH = SCRIPT_DIR / 'project_flowchart.mmd'

def _load_json(path: Path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

class FileLevelFlowchartGenerator:
    """Generate a file-level Mermaid flow-chart based on code-packager outputs."""

    MODEL_NAME = 'gemini-2.5-flash'

    def __init__(self,
                 subtrees_path: Path = SUBTREES_PATH,
                 hash_map_path: Path = HASH_MAP_PATH,
                 output_path: Path = OUTPUT_MERMAID_PATH):
        self.subtrees_path = Path(subtrees_path)
        self.hash_map_path = Path(hash_map_path)
        self.output_path = Path(output_path)

        self.subtrees: List[Dict[str, Any]] = []
        self.hash_map: Dict[str, Any] = {}

        self._initialize_gemini()

    def _initialize_gemini(self):
        api_key = os.environ.get('GEMINI_API_KEY', '')
        if not api_key:
            raise ValueError("GEMINI_API_KEY not found in environment variables")
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(self.MODEL_NAME)
        logger.info("Gemini API initialised for FileLevelFlowchartGenerator")

    def generate_complete_flowchart(self) -> Optional[str]:
        try:
            self._load_data()
            files_meta = self._analyse_project_files()
            if not files_meta:
                logger.error("No files found after analysis. Aborting flowchart generation.")
                return None

            mermaid_code = self._generate_mermaid_code(files_meta)
            if not mermaid_code:
                logger.error("Failed to obtain Mermaid code from Gemini")
                return None

            saved_path = self._validate_and_save_mermaid(mermaid_code)
            if saved_path:
                logger.info(f"File-level flowchart saved to {saved_path}")
            return saved_path
        except Exception as e:
            logger.error(f"Unexpected error during flowchart generation: {e}")
            return None

    def _load_data(self):
        logger.info("Loading packager outputs …")
        if not self.subtrees_path.exists() or not self.hash_map_path.exists():
            raise FileNotFoundError("Required code-packager output files not found.")
        self.subtrees = _load_json(self.subtrees_path)
        self.hash_map = _load_json(self.hash_map_path)

    def _analyse_project_files(self) -> List[Dict[str, Any]]:
        logger.info("Analysing project files …")
        files_meta = []
        for subtree_idx, subtree in enumerate(self.subtrees):
            for node in subtree.get('nodes', []):
                file_name = node.get('name', f'file_{subtree_idx}')
                code = node.get('cleaned_content') or node.get('raw_content', '')
                if not code.strip():
                    continue
                files_meta.append(self._extract_file_info(code, file_name))
        logger.info(f"Collected metadata for {len(files_meta)} files")
        return files_meta

    @staticmethod
    def _extract_file_info(code: str, file_name: str) -> Dict[str, Any]:
        """Extract high-level info (imports, major funcs, classes, entry points)."""
        info = {
            'name': file_name,
            'major_functions': [],
            'classes': [],
            'imports': [],
            'entry_points': []
        }
        for line in code.split('\n'):
            line = line.strip()
            if line.startswith(('import ', 'from ')):
                parts = line.split()
                if 'import' in parts:
                    idx = parts.index('import')
                    if idx + 1 < len(parts):
                        mod = parts[idx + 1].split('.')[0]
                        info['imports'].append(mod)
            if line.startswith('def ') and not line.startswith('def _'):
                m = re.match(r'def\s+(\w+)\s*\(', line)
                if m:
                    info['major_functions'].append(m.group(1))
            if line.startswith('class '):
                m = re.match(r'class\s+(\w+)', line)
                if m:
                    info['classes'].append(m.group(1))
            if line.startswith('if __name__ == "__main__"') or 'def main' in line or 'async def main' in line:
                info['entry_points'].append('main')
        return info

    def _build_prompt(self, files_meta: List[Dict[str, Any]]) -> str:
        summaries = []
        for meta in files_meta:
            summary = f"- {meta['name']}"
            comps = []
            if meta['classes']:
                comps.append(f"Classes: {', '.join(meta['classes'][:3])}")
            if meta['major_functions']:
                comps.append(f"Functions: {', '.join(meta['major_functions'][:4])}")
            if meta['entry_points']:
                comps.append("Entry Point: Yes")
            if comps:
                summary += f" ({'; '.join(comps)})"
            if meta['imports']:
                key_imps = [imp for imp in meta['imports'] if not imp.startswith('_')][:3]
                if key_imps:
                    summary += f" | Imports: {', '.join(key_imps)}"
            summaries.append(summary)

        prompt = f"""
Create a file-level Mermaid flowchart showing the project structure and file relationships.

Project files:
{chr(10).join(summaries)}

Create a flowchart that shows:
1. Files as main nodes
2. Data flow between files
3. Entry points and main execution flow
4. Key dependencies between files

CRITICAL SYNTAX RULES - FOLLOW EXACTLY:
- Use ONLY: NodeA --> NodeB (for connections)
- Use ONLY: NodeA --> Decision{{Question?}} (for decisions)  
- NEVER use colons after arrows
- NEVER use brackets after arrows
- NEVER use comments with %% anywhere
- NEVER add explanatory text after connections
- Use only alphanumeric characters and underscores in node names
- Replace dots with underscores (file.py becomes file_py)
- One connection per line
- Focus on FILE-LEVEL flow, not detailed code implementation
- Do NOT include subgraph syntax
- Do NOT include any headers or declarations
- Start output directly with connections only

Example valid format:
main_py --> setup_py
setup_py --> config_py
config_py --> database_py

IMPORTANT: Output ONLY the connection lines. No comments, no explanations, no additional text.
"""
        return prompt

    def _generate_mermaid_code(self, files_meta: List[Dict[str, Any]], max_retries: int = 5, base_delay: int = 30) -> Optional[str]:
        prompt = self._build_prompt(files_meta)
        for attempt in range(max_retries):
            try:
                response = self.model.generate_content(prompt)
                if hasattr(response, 'text') and response.text.strip():
                    return response.text.strip()
                logger.warning("Empty response from Gemini, retrying…")
            except Exception as e:
                msg = str(e)
                if ('429' in msg) or ('quota' in msg.lower()):
                    delay = base_delay * (2 ** attempt)
                    logger.warning(f"Rate limit hit, sleeping {delay}s (attempt {attempt+1}/{max_retries})")
                    time.sleep(delay)
                    continue
                logger.error(f"Gemini error: {e}")
                break
        return None

    @staticmethod
    def _clean_mermaid(raw: str) -> str:
        """Remove markdown fences and any Mermaid header lines that Gemini may emit."""
        skip_prefixes = (
            '```', '```mermaid',
            'flowchart', 'graph', 'classdiagram', 'sequencediagram', 'statediagram'
        )
        cleaned: List[str] = []
        for ln in raw.splitlines():
            ln_stripped = ln.strip()
            if not ln_stripped:
                continue
            lower = ln_stripped.lower()
            if any(lower.startswith(pref) for pref in skip_prefixes):
                continue
            cleaned.append(ln_stripped)
        return '\n'.join(cleaned)

    @staticmethod
    def _fix_common_syntax(line: str) -> str:
        """Sanitise a single connection line and return a valid Mermaid edge or empty string."""
        line = re.sub(r'%%.*', '', line).strip()

        if not line or '-->' not in line:
            return ''
        line = re.sub(r'(\w+)-->\[([^]]+)]', r'\1-->\2', line)
        line = re.sub(r'-->[^\s{}]+:\s*(\w+)', r'-->\1', line)
        line = line.replace('.py', '_py').replace('.', '_')
        line = re.sub(r'\s*-->\s*', ' --> ', line)
        parts = [p.strip() for p in line.split('-->')]
        if len(parts) != 2:
            return ''
        left = re.sub(r'[^a-zA-Z0-9_{}()]', '', parts[0])
        right = re.sub(r'[^a-zA-Z0-9_{}()]', '', parts[1])
        if not left or not right:
            return ''
        return f"{left} --> {right}"

    def _validate_and_save_mermaid(self, raw_code: str) -> str:
        """Validate and save the Mermaid code with proper syntax."""
        cleaned = self._clean_mermaid(raw_code)
        fixed_lines = []
        
        for line in cleaned.split('\n'):
            line = line.strip()
            if not line:
                continue
            if line.lower().startswith('subgraph') or line.lower().startswith('end'):
                continue
                
            fixed_line = self._fix_common_syntax(line)
            if fixed_line and '-->' in fixed_line:
                fixed_lines.append(fixed_line)
        def build_header():
            return ['flowchart TD', '    %% File-Level Project Structure', '']

        MAX_CHARS = 48000
        chunks: List[List[str]] = []
        current_chunk = build_header()
        current_len = sum(len(l) + 1 for l in current_chunk)

        for line in fixed_lines:
            if not line.strip():
                continue
            line_entry = '    ' + line
            if current_len + len(line_entry) + 1 > MAX_CHARS:
                chunks.append(current_chunk.copy())
                current_chunk = build_header() + [line_entry]
                current_len = sum(len(l) + 1 for l in current_chunk)
            else:
                current_chunk.append(line_entry)
                current_len += len(line_entry) + 1
        chunks.append(current_chunk)
        written_paths: List[str] = []
        for idx, lines_block in enumerate(chunks, 1):
            content = '\n'.join(lines_block)
            out_path = self.output_path if idx == 1 else self.output_path.with_stem(f"{self.output_path.stem}_part{idx}")
            out_path.write_text(content, encoding='utf-8')
            written_paths.append(str(out_path))

        logger.info(f"Mermaid files written: {', '.join(written_paths)}")
        final_content = '\n'.join(chunks[0])
        edge_count = sum(1 for ln in fixed_lines if '-->' in ln)
        buffer = max(int(edge_count * 0.2), 50)
        max_edges_value = edge_count + buffer

        config_path = self.output_path.parent / 'mermaid_config.json'
        try:
            config_path.write_text(json.dumps({"maxEdges": max_edges_value}), encoding='utf-8')
            logger.info(f"Mermaid config written with maxEdges={max_edges_value} → {config_path}")
        except Exception as cfg_err:
            logger.warning(f"Failed to write Mermaid config: {cfg_err}")

        return str(self.output_path)

def main():
    try:
        generator = FileLevelFlowchartGenerator()
        result_path = generator.generate_complete_flowchart()
        if result_path:
            print(f"SUCCESS: File-level flowchart generated: {result_path}")
        else:
            print("FAILED: Failed to generate file-level flowchart.")
    except Exception as e:
        logger.error(f"Error in flowchart generator: {e}")
        print("❌ Flowchart generation failed. See logs for details.")

if __name__ == "__main__":
    main()
